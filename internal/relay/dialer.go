package relay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ErrPrivateTarget 表示目标解析到了内网/本机地址而设备组不允许。
var ErrPrivateTarget = errors.New("目标为内网或本机地址,已被策略拒绝")

// Dialer 负责连接转发目标:带 DNS 缓存、内网地址拦截、TCP keepalive。
type Dialer struct {
	AllowPrivate bool
	Timeout      time.Duration
	nd           net.Dialer
}

// NewDialer 创建拨号器。
func NewDialer(allowPrivate bool) *Dialer {
	d := &Dialer{AllowPrivate: allowPrivate, Timeout: 5 * time.Second}
	d.nd = net.Dialer{Timeout: d.Timeout, KeepAlive: 30 * time.Second, ControlContext: d.control}
	return d
}

type listenerKey struct {
	network string
	addr    netip.AddrPort
}

var localListeners sync.Map

// Register only sockets that successfully bound; the returned function belongs to that listener.
func RegisterListener(network string, addr net.Addr) func() {
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		panic(err)
	}
	key := listenerKey{network, ap}
	localListeners.Store(key, true)
	return func() { localListeners.Delete(key) }
}
func targetsListener(network string, ap netip.AddrPort) bool {
	network = strings.TrimRight(network, "46")
	for _, wild := range []netip.Addr{ap.Addr(), netip.IPv4Unspecified(), netip.IPv6Unspecified()} {
		if _, ok := localListeners.Load(listenerKey{network, netip.AddrPortFrom(wild, ap.Port())}); !ok {
			continue
		}
		if !wild.IsUnspecified() || ap.Addr().IsLoopback() || ap.Addr().IsUnspecified() {
			return true
		}
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return true
		}
		for _, a := range addrs {
			ip, _, _ := net.ParseCIDR(a.String())
			if addr, ok := netip.AddrFromSlice(ip); ok && addr.Unmap() == ap.Addr().Unmap() {
				return true
			}
		}
	}
	return false
}

// netip.IsGlobalUnicast includes several IANA special-purpose address blocks.
var specialNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

// Globally reachable IANA assignments within the special-purpose blocks above.
var publicAssignments = []netip.Prefix{
	netip.MustParsePrefix("192.0.0.9/32"), netip.MustParsePrefix("192.0.0.10/32"),
	netip.MustParsePrefix("2001:1::1/128"), netip.MustParsePrefix("2001:1::2/128"), netip.MustParsePrefix("2001:1::3/128"),
	netip.MustParsePrefix("2001:3::/32"), netip.MustParsePrefix("2001:4:112::/48"),
	netip.MustParsePrefix("2001:20::/28"), netip.MustParsePrefix("2001:30::/28"),
}

var globalIPv6 = netip.MustParsePrefix("2000::/3")

func RestrictedAddr(a netip.Addr) bool {
	if a.Zone() != "" {
		return true
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return true
	}
	// Excludes NAT64, discard-only and other non-public IPv6 address space.
	if a.Is6() && !globalIPv6.Contains(a) {
		return true
	}
	for _, p := range specialNetworks {
		if p.Contains(a) {
			return !slices.ContainsFunc(publicAssignments, func(allowed netip.Prefix) bool { return allowed.Contains(a) })
		}
	}
	return false
}

// control 在 connect 之前检查实际要连接的 IP(已完成 DNS 解析),防止用户把规则指向节点内网。
type excludedTargetsKey struct{}
type excludedTargets struct {
	listenPort int
	advertised []netip.AddrPort
}

func WithExcludedTargets(ctx context.Context, listenPort int, targets []netip.AddrPort) context.Context {
	if listenPort == 0 && len(targets) == 0 {
		return ctx
	}
	return context.WithValue(ctx, excludedTargetsKey{}, excludedTargets{listenPort: listenPort, advertised: targets})
}

func (d *Dialer) control(ctx context.Context, network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return ErrPrivateTarget
	}
	blocked, _ := ctx.Value(excludedTargetsKey{}).(excludedTargets)
	if slices.Contains(blocked.advertised, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())) || (blocked.listenPort == int(ap.Port()) && targetsListener(network, ap)) {
		return errors.New("目标指向本机转发监听端口")
	}
	if !d.AllowPrivate && RestrictedAddr(ap.Addr()) {
		return ErrPrivateTarget
	}
	return nil
}

type dnsEntry struct {
	addrs []netip.Addr
	exp   time.Time
}

var dnsCache sync.Map // host -> *dnsEntry

const (
	dnsTTL   = 60 * time.Second
	dnsStale = 10 * time.Minute // 解析失败时允许继续使用过期结果的时长
)

// Resolve 解析主机名(带缓存)。IP 字面量直接返回。
func Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	now := time.Now()
	var old *dnsEntry
	if v, ok := dnsCache.Load(host); ok {
		old = v.(*dnsEntry)
		if now.Before(old.exp) {
			return old.addrs, nil
		}
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		if old != nil && now.Before(old.exp.Add(dnsStale)) {
			return old.addrs, nil
		}
		if err == nil {
			err = errors.New("域名无解析结果: " + host)
		}
		return nil, err
	}
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	dnsCache.Store(host, &dnsEntry{addrs: addrs, exp: now.Add(dnsTTL)})
	return addrs, nil
}

// DialTCP 连接 host:port。域名解析出多个地址时最多尝试前两个。
func (d *Dialer) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	addrs, err := Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error
	for i, a := range addrs {
		if i >= 2 {
			break
		}
		c, err := d.nd.DialContext(ctx, "tcp", net.JoinHostPort(a.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
		if errors.Is(err, ErrPrivateTarget) || ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

// DialUDP 创建一个已 connect 到 addr 的 UDP 套接字。
func (d *Dialer) DialUDP(ctx context.Context, addr string) (*net.UDPConn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	addrs, err := Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	c, err := d.nd.DialContext(ctx, "udp", net.JoinHostPort(addrs[0].String(), port))
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), nil
}

// DialBalanced 按均衡器给出的顺序连接目标,失败自动换下一个(最多 3 个)。
// 成功时后端的 Active 计数已加一,调用方在连接结束后需要减回去。
func DialBalanced(ctx context.Context, d *Dialer, bal *Balancer, hash uint64) (net.Conn, *Backend, error) {
	var last error = errors.New("没有可用的转发目标")
	for i, be := range bal.Candidates(hash) {
		if i >= 3 || ctx.Err() != nil {
			break
		}
		c, err := d.DialTCP(ctx, be.Addr)
		if errors.Is(err, ErrPrivateTarget) {
			return nil, nil, err
		}
		bal.Report(be, err == nil)
		if err == nil {
			be.Active.Add(1)
			return c, be, nil
		}
		last = err
	}
	return nil, nil, last
}

// HashAddr 计算来源 IP 的哈希(ip_hash 策略使用)。
func HashAddr(a netip.Addr) uint64 {
	b := a.As16()
	h := uint64(14695981039346656037)
	for _, x := range b {
		h ^= uint64(x)
		h *= 1099511628211
	}
	return h
}
