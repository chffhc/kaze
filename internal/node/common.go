package node

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"kaze/internal/proto"
	"kaze/internal/relay"
	"kaze/internal/tunnel"
)

const (
	connectTimeout      = 10 * time.Second
	tlsHandshakeTimeout = 10 * time.Second
)

// tunnelSet 维护一组到出口组的隧道客户端,并让它们收敛到面板下发的配置。
// 入口(到首跳出口)和链式出口的中间跳(到下一跳)都用它。
type tunnelSet struct {
	tag     string
	mu      sync.Mutex
	entries map[int64]*tunnelEntry
	cur     atomic.Pointer[map[int64]*tunnel.Client]
}

type tunnelEntry struct {
	spec proto.TunnelSpec
	opts tunnel.ClientOpts // Now 字段不参与比较
	cli  *tunnel.Client
}

func newTunnelSet(tag string) *tunnelSet {
	ts := &tunnelSet{tag: tag, entries: make(map[int64]*tunnelEntry)}
	empty := map[int64]*tunnel.Client{}
	ts.cur.Store(&empty)
	return ts
}

// usesReverse 报告这条隧道(或它的故障转移组)是否依赖本节点的反向隧道监听。
func usesReverse(s *proto.TunnelSpec) bool {
	return s.Reverse || (s.Fallback != nil && s.Fallback.Reverse)
}

// apply 收敛到 specs:配置没变的客户端原样保留(连接不受影响),变了的退役后重建,多余的退役。
func (ts *tunnelSet) apply(specs map[int64]*proto.TunnelSpec, o tunnel.ClientOpts) map[int64]bool {
	changed := make(map[int64]bool)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for gid, spec := range specs {
		if spec == nil {
			continue
		}
		if old := ts.entries[gid]; old != nil {
			if reflect.DeepEqual(old.spec, *spec) && old.opts.MaxFail == o.MaxFail && old.opts.FailTimeout == o.FailTimeout &&
				(!usesReverse(spec) || old.opts.Reverse == o.Reverse) {
				continue
			}
			old.cli.Close()
			changed[gid] = true
			delete(ts.entries, gid)
		}
		cli, err := tunnel.NewClient(spec, o)
		if err != nil {
			log.Printf("[%s] 出口组 #%d 隧道配置无效: %v", ts.tag, gid, err)
			continue
		}
		ts.entries[gid] = &tunnelEntry{spec: *spec, opts: o, cli: cli}
		changed[gid] = true
	}
	for gid, old := range ts.entries {
		if specs[gid] == nil {
			old.cli.Close()
			changed[gid] = true
			delete(ts.entries, gid)
		}
	}
	m := make(map[int64]*tunnel.Client, len(ts.entries))
	for gid, e := range ts.entries {
		m[gid] = e.cli
	}
	ts.cur.Store(&m)
	return changed
}

func (ts *tunnelSet) get(gid int64) *tunnel.Client { return (*ts.cur.Load())[gid] }

func (ts *tunnelSet) closeAll() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for gid, e := range ts.entries {
		e.cli.Close()
		delete(ts.entries, gid)
	}
	empty := map[int64]*tunnel.Client{}
	ts.cur.Store(&empty)
}

func addrPortOf(a net.Addr) netip.AddrPort {
	if t, ok := a.(*net.TCPAddr); ok {
		ap := t.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}

// targetOpts 描述如何连接转发目标。
type targetOpts struct {
	proxyProtocol int              // 0 关闭 / 1 / 2
	src           netip.AddrPort   // 客户端真实地址(PROXY 头里的源)
	dst           netip.AddrPort   // PROXY 头里的目的地址;无效时用到目标连接的本地地址
	origin        *proto.OriginTLS // 非 nil 时与目标之间再做一层 TLS
	alpn          string           // 回源 TLS 时声明的应用层协议(与客户端协商出的保持一致)
}

// connectTarget 连接转发目标:按均衡策略选择并在失败时换下一个;可选发送 PROXY 头、做回源 TLS。
// 成功时目标的 Active 计数已加一,调用方在连接结束后减回去。
// 返回的 prefix 是需要先写给目标的数据(PROXY 头);回源 TLS 时它已经在握手之前发出。
func connectTarget(ctx context.Context, d *relay.Dialer, bal *relay.Balancer, hash uint64, o targetOpts) (conn net.Conn, be *relay.Backend, prefix []byte, err error) {
	raw, be, err := relay.DialBalanced(ctx, d, bal, hash)
	if err != nil {
		return nil, nil, nil, err
	}
	if o.proxyProtocol > 0 {
		dst := o.dst
		if !dst.IsValid() {
			dst = addrPortOf(raw.LocalAddr())
		}
		prefix = relay.ProxyHeader(o.proxyProtocol, o.src, dst)
	}
	if o.origin == nil {
		return raw, be, prefix, nil
	}
	fail := func(err error) (net.Conn, *relay.Backend, []byte, error) {
		raw.Close()
		be.Active.Add(-1)
		// 握手失败计入目标的故障次数;但声明了客户端协商出的 ALPN 时,失败可能只是该客户端的协议目标不支持
		if o.alpn == "" {
			bal.Report(be, false)
		}
		return nil, nil, nil, err
	}
	// PROXY 头属于传输层,必须在 TLS 握手之前以明文发出(与 nginx 的 "listen ... ssl proxy_protocol" 一致)
	if len(prefix) > 0 {
		raw.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err := raw.Write(prefix)
		raw.SetWriteDeadline(time.Time{})
		if err != nil {
			return fail(err)
		}
		prefix = nil
	}
	name := o.origin.SNI
	if name == "" {
		name, _, _ = net.SplitHostPort(be.Addr) // IP 字面量不会作为 SNI 发出,但开启校验时会用它核对证书
	}
	cfg := &tls.Config{ServerName: name, InsecureSkipVerify: !o.origin.Verify, MinVersion: tls.VersionTLS12}
	if o.alpn != "" {
		cfg.NextProtos = []string{o.alpn}
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return fail(fmt.Errorf("回源 TLS 握手失败: %w", err))
	}
	return tc, be, nil, nil
}

// tcping 并发测量到各地址的 TCP 建连耗时。
func tcping(from, toPrefix string, addrs []string, d *relay.Dialer) []proto.DiagHop {
	hops := make([]proto.DiagHop, len(addrs))
	var wg sync.WaitGroup
	for i, addr := range addrs {
		wg.Add(1)
		go func(i int, addr string) {
			defer wg.Done()
			h := proto.DiagHop{From: from, To: toPrefix + addr}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			if host, _, err := net.SplitHostPort(addr); err == nil {
				relay.Resolve(ctx, host) // 预解析,不把 DNS 耗时算进建连时间
			}
			t0 := time.Now()
			c, err := d.DialTCP(ctx, addr)
			if err != nil {
				h.Error = err.Error()
			} else {
				h.Ms = float64(time.Since(t0).Microseconds()) / 1000
				c.Close()
			}
			hops[i] = h
		}(i, addr)
	}
	wg.Wait()
	return hops
}

// tunnelHops 测量本节点到某个出口组的连通性:正向隧道测到各出口节点的建连耗时,
// 反向隧道报告已接入的连接数与往返时延。
func tunnelHops(from string, cli *tunnel.Client) []proto.DiagHop {
	if cli == nil {
		return []proto.DiagHop{{From: from, To: "下一跳出口组", Error: "出口组不可用(隧道配置未下发或无效)"}}
	}
	name := fmt.Sprintf("出口组 #%d", cli.Spec.GroupID)
	if rev, n, rtt, err := cli.ReverseStatus(); rev {
		h := proto.DiagHop{From: from, To: fmt.Sprintf("%s(反向隧道,%d 条连接)", name, n), Ms: float64(rtt.Microseconds()) / 1000}
		if err != nil {
			h.Error = err.Error()
		}
		return []proto.DiagHop{h}
	}
	if len(cli.Endpoints()) == 0 {
		return []proto.DiagHop{{From: from, To: name, Error: "出口组没有可连接的节点"}}
	}
	return tcping(from, "出口 ", cli.Endpoints(), relay.NewDialer(true))
}
