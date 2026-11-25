package node

import (
	"context"
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

// outbound 管理出口节点:一个隧道服务端(TCP 类传输层)+ 同端口的原生 UDP 通道,
// 收到的每条流按规则号找到目标并转发。
type outbound struct {
	a *Agent

	mu    sync.Mutex
	srv   *tunnel.Server
	udp   *relay.UDPRelay
	ident string // 监听参数指纹,变化时重启服务端
	port  int

	rules  atomic.Pointer[map[int64]*outRule]
	dialer atomic.Pointer[relay.Dialer]
	sink   atomic.Int64 // 出口不单独计费,流量由入口上报
}

type outRule struct {
	spec proto.OutRule
	bal  *relay.Balancer
	live *ruleConns
}

func newOutbound(a *Agent) *outbound {
	o := &outbound{a: a}
	o.dialer.Store(relay.NewDialer(false))
	empty := map[int64]*outRule{}
	o.rules.Store(&empty)
	return o
}

func (o *outbound) apply(cfg *proto.OutboundConfig) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	// 规则表:内容没变的规则沿用原对象,保留均衡器里的健康状态。
	old := *o.rules.Load()
	next := make(map[int64]*outRule, len(cfg.Rules))
	for _, r := range cfg.Rules {
		if prev := old[r.ID]; prev != nil && reflect.DeepEqual(prev.spec, r) {
			next[r.ID] = prev
			continue
		}
		// Existing sessions keep their original targets on edits. Only a
		// removal ends this ID's lifetime (including sessions predating edits).
		var live *ruleConns
		if prev := old[r.ID]; prev != nil {
			live = prev.live
		} else {
			live = newRuleConns()
		}
		next[r.ID] = &outRule{spec: r, live: live, bal: relay.NewBalancer(r.Targets, r.LB, cfg.MaxFail,
			time.Duration(cfg.FailTimeout)*time.Second)}
	}
	o.rules.Store(&next)
	for id, prev := range old {
		if next[id] == nil {
			prev.live.stop()
		}
	}
	if d := o.dialer.Load(); d.AllowPrivate != cfg.AllowPrivate {
		o.dialer.Store(relay.NewDialer(cfg.AllowPrivate))
	}

	// 监听端口优先级:命令行 > 面板设备组配置 > 上次使用的端口 > 随机
	want := o.a.opt.TunnelPort
	if want == 0 {
		want = cfg.ListenPort
	}
	// 指纹里记录的是"要求的端口"(0 = 自动),自动选出的端口不参与比较,避免无谓重启。
	ident := fmt.Sprintf("%d|%s|%s|%s|%s", want, cfg.Transport, cfg.Key, cfg.Path, cfg.CertPEM)
	if o.srv != nil && ident == o.ident {
		return nil
	}
	port := want
	if port == 0 {
		port = o.a.state.TunnelPort
	}
	o.closeLocked()

	keys, err := tunnel.DeriveKeys(cfg.Key)
	if err != nil {
		return err
	}
	sc := tunnel.ServerConfig{Bind: o.a.opt.Bind, Port: port, Transport: cfg.Transport, Keys: keys, Path: cfg.Path, Now: o.a.now}
	if cfg.Transport == tunnel.TransportTLS || cfg.Transport == tunnel.TransportWSS {
		cert, err := tunnel.ParseCert(cfg.CertPEM, cfg.KeyPEM)
		if err != nil {
			return fmt.Errorf("出口证书无效: %w", err)
		}
		sc.Cert = &cert
	}
	srv, err := tunnel.NewServer(sc, o.handle)
	if err != nil && want == 0 && port != 0 {
		sc.Port = 0 // 上次自动选的端口已被占用:重新随机
		srv, err = tunnel.NewServer(sc, o.handle)
	}
	if err != nil {
		return err
	}
	o.srv, o.ident, o.port = srv, ident, srv.Port()

	// 原生 UDP 通道与隧道共用同一个端口号
	ua := &net.UDPAddr{IP: net.ParseIP(o.a.opt.Bind), Port: o.port}
	if uc, err := net.ListenUDP("udp", ua); err != nil {
		log.Printf("[出口] 原生 UDP 通道监听失败(UDP 仅能走 udp_over_tcp): %v", err)
	} else {
		uc.SetReadBuffer(4 << 20)
		uc.SetWriteBuffer(4 << 20)
		ciph := tunnel.NewUDPCipher(keys, false)
		o.udp = &relay.UDPRelay{
			Conn: uc,
			Decode: func(pkt []byte) ([]byte, uint32, bool) {
				id, pt, ok := ciph.Open(pkt)
				return pt, id, ok
			},
			Encode: func(dst, payload []byte) []byte { return ciph.Seal(dst, 0, payload) },
			Open:   o.openUDP,
		}
		go o.udp.Serve()
	}
	if o.a.state.TunnelPort != o.port {
		o.a.state.TunnelPort = o.port
		o.a.saveState()
	}
	log.Printf("[出口] 隧道已监听 :%d (%s)", o.port, cfg.Transport)
	return nil
}

func (o *outbound) closeLocked() {
	if o.srv != nil {
		o.srv.Close()
		o.srv = nil
	}
	if o.udp != nil {
		o.udp.Close()
		o.udp = nil
	}
	o.port = 0
}

func (o *outbound) stopAll() {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, rule := range *o.rules.Swap(&map[int64]*outRule{}) {
		rule.live.stop()
	}
	o.closeLocked()
}

func (o *outbound) listenPort() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.port
}

// handle 处理一条来自入口的隧道流。
func (o *outbound) handle(conn net.Conn, h tunnel.StreamHeader) {
	rule := (*o.rules.Load())[int64(h.RuleID)]
	if rule == nil {
		relay.Abort(conn)
		return
	}
	if !rule.live.track(conn) {
		return
	}
	defer rule.live.forget(conn)
	ctx, cancel := context.WithTimeout(rule.live.ctx, connectTimeout)
	defer cancel()
	d := o.dialer.Load()
	hash := relay.HashAddr(h.Src.Addr())
	switch h.Cmd {
	case tunnel.CmdTCP:
		target, be, err := relay.DialBalanced(ctx, d, rule.bal, hash)
		if err != nil {
			relay.Abort(conn)
			return
		}
		cancel()
		defer be.Active.Add(-1)
		if !rule.live.track(target) {
			return
		}
		defer rule.live.forget(target)
		var prefix []byte
		if rule.spec.ProxyProtocol > 0 {
			prefix = relay.ProxyHeader(rule.spec.ProxyProtocol, h.Src, addrPortOf(target.LocalAddr()))
		}
		relay.Pipe(conn, target, &relay.PipeOpts{Up: &o.sink, Down: &o.sink, Prefix: prefix})

	case tunnel.CmdUDP:
		cands := rule.bal.Candidates(hash)
		if len(cands) == 0 {
			relay.Abort(conn)
			return
		}
		uc, err := d.DialUDP(ctx, cands[0].Addr)
		if err != nil {
			relay.Abort(conn)
			return
		}
		cancel()
		if !rule.live.track(uc) {
			return
		}
		defer rule.live.forget(uc)
		relay.ServeUDPStream(conn, uc, 0)
	}
}

// openUDP 为原生 UDP 通道上的新会话连接目标。
func (o *outbound) openUDP(client netip.AddrPort, ruleID uint32) (relay.Upstream, error) {
	rule := (*o.rules.Load())[int64(ruleID)]
	if rule == nil {
		return nil, fmt.Errorf("规则 #%d 不存在", ruleID)
	}
	cands := rule.bal.Candidates(relay.HashAddr(client.Addr()))
	if len(cands) == 0 {
		return nil, fmt.Errorf("没有转发目标")
	}
	ctx, cancel := context.WithTimeout(rule.live.ctx, connectTimeout)
	defer cancel()
	uc, err := o.dialer.Load().DialUDP(ctx, cands[0].Addr)
	if err != nil {
		return nil, err
	}
	if !rule.live.track(uc) {
		return nil, net.ErrClosed
	}
	return &outUDP{UDPConnUpstream: relay.UDPConnUpstream{UDPConn: uc}, live: rule.live}, nil
}

type outUDP struct {
	relay.UDPConnUpstream
	live *ruleConns
}

func (u *outUDP) Close() error {
	defer u.live.forget(u.UDPConn)
	return u.UDPConn.Close()
}

// diag 测量本节点到规则各目标的 TCP 建连耗时。
func (o *outbound) diag(ruleID int64) []proto.DiagHop {
	from := "出口 " + o.a.hostname
	rule := (*o.rules.Load())[ruleID]
	if rule == nil {
		return []proto.DiagHop{{From: from, To: "-", Error: "规则未同步到该节点"}}
	}
	return tcping(from, "目标 ", rule.spec.Targets, o.dialer.Load())
}
