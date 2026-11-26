package node

import (
	"context"
	"errors"
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

// outbound 管理出口节点:
//   - 一个隧道服务端(TCP 类传输层)加同端口的原生 UDP 通道,接受入口或上一跳的连接;
//   - 反向隧道:主动拨入开启了反向监听的入口节点,在这些连接上接受同样的流;
//   - 收到的每条流按规则号查表:最后一跳连接转发目标,链式出口的中间跳转给下一个出口组。
type outbound struct {
	a *Agent

	mu    sync.Mutex
	srv   *tunnel.Server
	udp   *relay.UDPRelay
	ident string // 监听参数指纹,变化时重启服务端
	port  int
	revs  map[string]*revEntry // 入口节点的反向端口地址 -> 拨号器

	tunnels *tunnelSet // 链式出口:到下一跳的隧道,键由面板分配
	rules   atomic.Pointer[map[int64]*outRule]
	dialer  atomic.Pointer[relay.Dialer]
	sink    atomic.Int64 // 出口不单独计费,流量由入口上报
}

type outRule struct {
	spec proto.OutRule
	bal  *relay.Balancer // 仅最后一跳
}

type revEntry struct {
	spec    proto.ReverseSpec
	key     string
	groupID int64
	d       *tunnel.ReverseDialer
}

func newOutbound(a *Agent) *outbound {
	o := &outbound{a: a, revs: make(map[string]*revEntry), tunnels: newTunnelSet("出口")}
	o.dialer.Store(relay.NewDialer(false))
	empty := map[int64]*outRule{}
	o.rules.Store(&empty)
	return o
}

func (o *outbound) apply(cfg *proto.OutboundConfig, groupID int64) error {
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
		or := &outRule{spec: r}
		if r.Next == 0 {
			or.bal = relay.NewBalancer(r.Targets, r.LB, cfg.MaxFail, time.Duration(cfg.FailTimeout)*time.Second)
		}
		next[r.ID] = or
	}
	o.rules.Store(&next)
	if d := o.dialer.Load(); d.AllowPrivate != cfg.AllowPrivate {
		o.dialer.Store(relay.NewDialer(cfg.AllowPrivate))
	}
	o.tunnels.apply(cfg.Tunnels, tunnel.ClientOpts{
		MaxFail: cfg.MaxFail, FailTimeout: time.Duration(cfg.FailTimeout) * time.Second, Now: o.a.now,
	})

	keys, err := tunnel.DeriveKeys(cfg.Key)
	if err != nil {
		o.closeReverseLocked()
		return err
	}
	o.applyReverseLocked(cfg, groupID, keys)

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
	o.closeServerLocked()

	sc := tunnel.ServerConfig{Bind: o.a.opt.Bind, Port: port, Transport: cfg.Transport, Keys: keys, Path: cfg.Path, Now: o.a.now}
	if tunnel.TransportUsesTLS(cfg.Transport) {
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

// applyReverseLocked 让反向拨号器收敛到配置:参数没变的保持连接,其余重建。
func (o *outbound) applyReverseLocked(cfg *proto.OutboundConfig, groupID int64, keys *tunnel.Keys) {
	want := make(map[string]proto.ReverseSpec, len(cfg.Reverse))
	for _, rs := range cfg.Reverse {
		want[rs.Endpoint] = rs
	}
	for ep, e := range o.revs {
		if w, ok := want[ep]; !ok || w != e.spec || e.key != cfg.Key || e.groupID != groupID {
			e.d.Close()
			delete(o.revs, ep)
			if !ok {
				log.Printf("[出口] 已停止向入口 %s 的反向隧道", ep)
			}
		}
	}
	for ep, w := range want {
		if o.revs[ep] != nil {
			continue
		}
		d, err := tunnel.NewReverseDialer(w, groupID, keys, o.a.now, o.handle)
		if err != nil {
			log.Printf("[出口] 到入口 %s 的反向隧道配置无效: %v", ep, err)
			continue
		}
		o.revs[ep] = &revEntry{spec: w, key: cfg.Key, groupID: groupID, d: d}
		log.Printf("[出口] 开始向入口 %s 建立反向隧道", ep)
	}
}

func (o *outbound) closeReverseLocked() {
	for ep, e := range o.revs {
		e.d.Close()
		delete(o.revs, ep)
	}
}

func (o *outbound) closeServerLocked() {
	if o.srv != nil {
		o.srv.Close()
		o.srv = nil
	}
	if o.udp != nil {
		o.udp.Close()
		o.udp = nil
	}
	o.port, o.ident = 0, ""
}

func (o *outbound) stopAll() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closeServerLocked()
	o.closeReverseLocked()
	o.tunnels.closeAll()
	empty := map[int64]*outRule{}
	o.rules.Store(&empty)
}

func (o *outbound) listenPort() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.port
}

// handle 处理一条来自入口或上一跳的隧道流(正向与反向隧道共用)。
func (o *outbound) handle(conn net.Conn, h tunnel.StreamHeader) {
	rule := (*o.rules.Load())[int64(h.RuleID)]
	if rule == nil {
		relay.Abort(conn)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()

	// 链式出口的中间跳:原样把流头转给下一跳。UDP 流的封装格式各跳相同,同样按字节转发即可。
	if rule.spec.Next != 0 {
		cli := o.tunnels.get(rule.spec.Next)
		if cli == nil {
			relay.Abort(conn)
			return
		}
		next, done, err := cli.Open(ctx, h)
		if err != nil {
			relay.Abort(conn)
			return
		}
		cancel()
		relay.Pipe(conn, next, &relay.PipeOpts{Up: &o.sink, Down: &o.sink})
		done()
		return
	}

	d := o.dialer.Load()
	hash := relay.HashAddr(h.Src.Addr())
	switch h.Cmd {
	case tunnel.CmdTCP:
		target, be, prefix, err := connectTarget(ctx, d, rule.bal, hash, targetOpts{
			proxyProtocol: rule.spec.ProxyProtocol, src: h.Src, origin: rule.spec.OriginTLS, alpn: h.ALPN,
		})
		if err != nil {
			relay.Abort(conn)
			return
		}
		cancel()
		relay.Pipe(conn, target, &relay.PipeOpts{Up: &o.sink, Down: &o.sink, Prefix: prefix})
		be.Active.Add(-1)
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
		relay.ServeUDPStream(conn, uc, 0)
	}
}

// openUDP 为原生 UDP 通道上的新会话建立上游。
func (o *outbound) openUDP(client netip.AddrPort, ruleID uint32) (relay.Upstream, error) {
	rule := (*o.rules.Load())[int64(ruleID)]
	if rule == nil {
		return nil, fmt.Errorf("规则 #%d 不存在", ruleID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	if rule.spec.Next != 0 { // 链式出口:后续各跳一律走隧道流
		cli := o.tunnels.get(rule.spec.Next)
		if cli == nil {
			return nil, errors.New("下一跳不可用")
		}
		return cli.OpenUDP(ctx, ruleID, client, true)
	}
	cands := rule.bal.Candidates(relay.HashAddr(client.Addr()))
	if len(cands) == 0 {
		return nil, errors.New("没有转发目标")
	}
	uc, err := o.dialer.Load().DialUDP(ctx, cands[0].Addr)
	if err != nil {
		return nil, err
	}
	return relay.UDPConnUpstream{UDPConn: uc}, nil
}

// reverseStatus 汇总反向隧道的连接情况:需要拨入的入口节点数,以及其中已连上的个数。
func (o *outbound) reverseStatus() (total, up int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, e := range o.revs {
		total++
		if e.d.Connected() > 0 {
			up++
		}
	}
	return
}

// diag 测量本节点到规则下一跳(转发目标,或链式出口的下一个出口组)的连通性。
func (o *outbound) diag(ruleID int64) []proto.DiagHop {
	from := "出口 " + o.a.hostname
	rule := (*o.rules.Load())[ruleID]
	if rule == nil {
		return []proto.DiagHop{{From: from, To: "-", Error: "规则未同步到该节点"}}
	}
	if rule.spec.Next != 0 {
		return tunnelHops(from, o.tunnels.get(rule.spec.Next))
	}
	return tcping(from, "目标 ", rule.spec.Targets, o.dialer.Load())
}
