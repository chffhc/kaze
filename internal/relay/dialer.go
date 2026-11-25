package relay

import (
	"context"
	"errors"
	"net"
	"net/netip"
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
	d.nd = net.Dialer{Timeout: d.Timeout, KeepAlive: 30 * time.Second, Control: d.control}
	return d
}

func isPrivate(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	// 100.64.0.0/10 运营商级 NAT
	if a.Is4() {
		b := a.As4()
		if b[0] == 100 && b[1]&0xc0 == 64 {
			return true
		}
	}
	return false
}

// control 在 connect 之前检查实际要连接的 IP(已完成 DNS 解析),防止用户把规则指向节点内网。
func (d *Dialer) control(network, address string, _ syscall.RawConn) error {
	if d.AllowPrivate {
		return nil
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil
	}
	if isPrivate(ap.Addr()) {
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
