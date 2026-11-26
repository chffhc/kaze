package node

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"kaze/internal/proto"
	"kaze/internal/relay"
	"kaze/internal/tunnel"
)

// inbound 管理入口节点上的全部转发规则。
type inbound struct {
	a *Agent

	mu     sync.Mutex
	rules  map[int64]*ruleRunner
	users  map[int64]*userEntry
	errs   map[int64]string
	orphan map[int64][2]int64 // 已停止规则尚未上报的流量
	last   *proto.InboundConfig
	rev    *tunnel.ReverseListener // 反向隧道监听(启动参数指定了 -rev-port 且面板下发了证书时才有)
	revErr string

	tunnels        *tunnelSet
	policy         atomic.Pointer[relay.SniffPolicy]
	dialer         atomic.Pointer[relay.Dialer]
	sni            atomic.Pointer[sniTable] // TLS 母规则的端口 -> SNI -> 子规则
	rejectEmptySNI atomic.Bool
}

type userEntry struct {
	spec proto.UserLimit
	lim  *relay.Limits
}

// sniTable 是 SNI 分流表。每次应用配置后整体重建,握手时无锁读取。
type sniTable map[int]map[string]*sniTarget

// sniTarget 是一次 TLS 入站握手的归属:哪条规则处理、用哪份服务端配置(证书与 ALPN)。
type sniTarget struct {
	r   *ruleRunner
	cfg *tls.Config
}

func newInbound(a *Agent) *inbound {
	in := &inbound{
		a:       a,
		rules:   make(map[int64]*ruleRunner),
		users:   make(map[int64]*userEntry),
		errs:    make(map[int64]string),
		orphan:  make(map[int64][2]int64),
		tunnels: newTunnelSet("入口"),
	}
	in.dialer.Store(relay.NewDialer(false))
	in.sni.Store(&sniTable{})
	return in
}

// apply 把运行状态收敛到新配置:未变化的规则不受影响,变化的规则重启,消失的规则停止。
func (in *inbound) apply(cfg *proto.InboundConfig) {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.last = cfg

	// 1. 反向隧道监听,以及到各出口组的隧道客户端
	in.applyReverseLocked(cfg.Reverse)
	in.tunnels.apply(cfg.Tunnels, tunnel.ClientOpts{
		MaxFail: cfg.MaxFail, FailTimeout: time.Duration(cfg.FailTimeout) * time.Second, Now: in.a.now, Reverse: in.rev,
	})

	// 2. 用户级限制(限制不变则沿用同一个对象,规则无需重启)
	for uid, ul := range cfg.Users {
		if old := in.users[uid]; old == nil || old.spec != ul {
			in.users[uid] = &userEntry{spec: ul, lim: relay.NewLimits(ul.SpeedLimit, ul.ConnLimit, ul.IPLimit)}
		}
	}
	for uid := range in.users {
		if _, ok := cfg.Users[uid]; !ok {
			delete(in.users, uid)
		}
	}

	// 3. 全局策略
	in.policy.Store(relay.NewSniffPolicy(cfg.BlockedProtocols, cfg.BlockedHosts, cfg.AllowedHosts))
	in.rejectEmptySNI.Store(cfg.TLSRejectEmptySNI)
	if d := in.dialer.Load(); d.AllowPrivate != cfg.AllowPrivate {
		in.dialer.Store(relay.NewDialer(cfg.AllowPrivate))
	}

	// 4. 规则
	want := make(map[int64]*proto.Rule, len(cfg.Rules))
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if r.TLS != nil {
			r.Proto = "tcp" // TLS 入站只有 TCP
		} else if cfg.DisableUDP {
			if r.Proto == "udp" {
				continue
			}
			r.Proto = "tcp"
		}
		want[r.ID] = r
	}
	for id, run := range in.rules {
		w := want[id]
		var ul *relay.Limits
		if w != nil {
			if ue := in.users[w.UserID]; ue != nil {
				ul = ue.lim
			}
		}
		if w == nil || !reflect.DeepEqual(run.spec, *w) || run.ulim != ul {
			in.stopLocked(id, run)
		}
	}
	for id := range in.errs {
		if _, ok := want[id]; !ok {
			delete(in.errs, id)
		}
	}
	for id, w := range want {
		if in.rules[id] != nil {
			continue
		}
		var ul *relay.Limits
		if ue := in.users[w.UserID]; ue != nil {
			ul = ue.lim
		}
		run, err := in.startRule(*w, ul, cfg)
		if err != nil {
			in.errs[id] = err.Error()
			log.Printf("[入口] 规则 #%d (端口 %d) 启动失败: %v", id, w.ListenPort, err)
			continue
		}
		delete(in.errs, id)
		in.rules[id] = run
	}

	// 5. SNI 分流表
	in.rebuildSNILocked()
}

// applyReverseLocked 按配置开启、更新或关闭反向隧道监听。
func (in *inbound) applyReverseLocked(rc *proto.ReverseListen) {
	port := in.a.opt.RevPort
	if rc == nil || port == 0 {
		if in.rev != nil {
			in.rev.Close()
			in.rev = nil
			log.Printf("[入口] 反向隧道监听已关闭")
		}
		in.revErr = ""
		return
	}
	cert, err := tunnel.ParseCert(rc.CertPEM, rc.KeyPEM)
	if err != nil {
		in.revErr = "反向隧道证书无效: " + err.Error()
		log.Printf("[入口] %s", in.revErr)
		return
	}
	if in.rev == nil {
		ln, err := tunnel.NewReverseListener(in.a.opt.Bind, port, in.a.now)
		if err != nil {
			in.revErr = fmt.Sprintf("反向隧道端口 %d 监听失败: %v", port, err)
			log.Printf("[入口] %s", in.revErr)
			return
		}
		in.rev = ln
		log.Printf("[入口] 反向隧道已监听 :%d", ln.Port())
	}
	groups := make(map[int64]*tunnel.Keys, len(rc.Groups))
	for gid, key := range rc.Groups {
		if k, err := tunnel.DeriveKeys(key); err == nil {
			groups[gid] = k
		}
	}
	in.rev.Update(&cert, groups)
	in.revErr = ""
}

// rebuildSNILocked 重建"母规则端口 -> SNI -> 子规则"的分流表。
func (in *inbound) rebuildSNILocked() {
	parents := map[int]*ruleRunner{}
	var children []*ruleRunner
	for _, run := range in.rules {
		switch run.tlsMode() {
		case proto.TLSModeParent:
			parents[run.spec.ListenPort] = run
		case proto.TLSModeChild:
			children = append(children, run)
		}
	}
	// 同一个 SNI 被多条子规则声明时(面板会阻止),规则号小的生效
	sort.Slice(children, func(i, j int) bool { return children[i].spec.ID < children[j].spec.ID })
	tbl := sniTable{}
	for _, ch := range children {
		p := parents[ch.spec.ListenPort]
		if p == nil {
			continue // 母规则不存在或未启动:子规则暂时无法接入
		}
		// 证书的选择顺序:子规则自带的 > 母规则配置的 > 为子规则自动生成的自签名证书
		cert := ch.cert
		if !ch.ownCert && p.ownCert {
			cert = p.cert
		}
		t := &sniTarget{r: ch, cfg: serverTLSConfig(cert, ch.spec.TLS.ALPN)}
		m := tbl[ch.spec.ListenPort]
		if m == nil {
			m = map[string]*sniTarget{}
			tbl[ch.spec.ListenPort] = m
		}
		for _, name := range ch.spec.TLS.SNI {
			if name = strings.ToLower(name); m[name] == nil {
				m[name] = t
			}
		}
	}
	in.sni.Store(&tbl)
}

func (in *inbound) stopLocked(id int64, run *ruleRunner) {
	run.stop()
	o := in.orphan[id]
	o[0] += run.up.Swap(0)
	o[1] += run.down.Swap(0)
	if o[0] != 0 || o[1] != 0 {
		in.orphan[id] = o
	}
	delete(in.rules, id)
}

// retryFailed 重新尝试启动失败的规则(例如端口被占用后又释放),以及没能监听成功的反向隧道端口。
func (in *inbound) retryFailed() bool {
	in.mu.Lock()
	n, cfg := len(in.errs), in.last
	if in.revErr != "" {
		n++
	}
	in.mu.Unlock()
	if n == 0 || cfg == nil {
		return false
	}
	in.apply(cfg)
	return true
}

// collect 取走自上次以来的流量增量。
func (in *inbound) collect() []proto.Traffic {
	in.mu.Lock()
	defer in.mu.Unlock()
	var out []proto.Traffic
	for id, run := range in.rules {
		up, down := run.up.Swap(0), run.down.Swap(0)
		if o, ok := in.orphan[id]; ok {
			up, down = up+o[0], down+o[1]
			delete(in.orphan, id)
		}
		if up != 0 || down != 0 {
			out = append(out, proto.Traffic{RuleID: id, Up: up, Down: down})
		}
	}
	for id, o := range in.orphan {
		out = append(out, proto.Traffic{RuleID: id, Up: o[0], Down: o[1]})
		delete(in.orphan, id)
	}
	return out
}

// ruleErrors 返回启动失败的规则;键 0 是节点级的错误(反向隧道监听失败)。
func (in *inbound) ruleErrors() map[int64]string {
	in.mu.Lock()
	defer in.mu.Unlock()
	out := make(map[int64]string, len(in.errs)+1)
	for k, v := range in.errs {
		out[k] = v
	}
	if in.revErr != "" {
		out[0] = in.revErr
	}
	return out
}

// reverseStatus 返回允许拨入的出口组数,以及其中已有连接的组数。
func (in *inbound) reverseStatus() (total, up int) {
	in.mu.Lock()
	ln := in.rev
	in.mu.Unlock()
	if ln == nil {
		return 0, 0
	}
	return ln.Stats()
}

func (in *inbound) stopAll() {
	in.mu.Lock()
	defer in.mu.Unlock()
	for id, run := range in.rules {
		in.stopLocked(id, run)
	}
	in.sni.Store(&sniTable{})
	in.tunnels.closeAll()
	if in.rev != nil {
		in.rev.Close()
		in.rev = nil
	}
	in.revErr = ""
}

// diag 测量本节点到规则下一跳(出口节点或目标)的连通性。
func (in *inbound) diag(ruleID int64) []proto.DiagHop {
	in.mu.Lock()
	run := in.rules[ruleID]
	errMsg := in.errs[ruleID]
	in.mu.Unlock()
	from := "入口 " + in.a.hostname
	if run == nil {
		if errMsg == "" {
			errMsg = "规则未同步到该节点"
		}
		return []proto.DiagHop{{From: from, To: "-", Error: errMsg}}
	}
	switch {
	case run.tlsMode() == proto.TLSModeParent:
		return []proto.DiagHop{{From: from, To: fmt.Sprintf("TLS 端口 %d(母规则只负责监听与分流)", run.spec.ListenPort)}}
	case run.spec.OutGroup == 0:
		return tcping(from, "目标 ", run.spec.Targets, in.dialer.Load())
	}
	return tunnelHops(from, in.tunnels.get(run.spec.OutGroup))
}

// ---- 单条规则 ----

type ruleRunner struct {
	in   *inbound
	spec proto.Rule
	ulim *relay.Limits // 用户级
	rlim *relay.Limits // 规则级
	bal  *relay.Balancer

	up, down atomic.Int64

	// TLS 入站
	cert    *tls.Certificate // 规则配置的证书,或启动时自动生成的自签名证书
	ownCert bool             // 证书来自规则配置
	self    *sniTarget       // 独占端口时:握手归属就是自己
	outer   *tls.Config      // 监听端口上的握手入口,按 SNI 选出真正的服务端配置

	tcpLn  net.Listener
	udp    *relay.UDPRelay
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed atomic.Bool
}

func (r *ruleRunner) tlsMode() string {
	if r.spec.TLS == nil {
		return ""
	}
	return r.spec.TLS.Mode
}

func bucketUp(l *relay.Limits) *relay.Bucket {
	if l == nil {
		return nil
	}
	return l.Up
}

func bucketDown(l *relay.Limits) *relay.Bucket {
	if l == nil {
		return nil
	}
	return l.Down
}

func serverTLSConfig(cert *tls.Certificate, alpn []string) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12, NextProtos: alpn}
}

// loadTLS 准备规则的 TLS 入站证书:优先用规则配置的,否则生成一张自签名证书(客户端需要关闭证书校验)。
func (r *ruleRunner) loadTLS() error {
	t := r.spec.TLS
	if t.CertPEM != "" || t.KeyPEM != "" {
		cert, err := tunnel.ParseCert(t.CertPEM, t.KeyPEM)
		if err != nil {
			return fmt.Errorf("TLS 入站证书无效: %w", err)
		}
		r.cert, r.ownCert = &cert, true
		return nil
	}
	names := t.SNI
	if len(names) == 0 {
		names = []string{"localhost"}
	}
	cp, kp, _, err := tunnel.GenerateCert(names...)
	if err != nil {
		return err
	}
	cert, err := tunnel.ParseCert(cp, kp)
	if err != nil {
		return err
	}
	r.cert = &cert
	return nil
}

func (in *inbound) startRule(spec proto.Rule, ulim *relay.Limits, cfg *proto.InboundConfig) (*ruleRunner, error) {
	r := &ruleRunner{
		in: in, spec: spec, ulim: ulim,
		rlim:  relay.NewLimits(spec.SpeedLimit, spec.ConnLimit, spec.IPLimit),
		conns: make(map[net.Conn]struct{}),
	}
	mode := r.tlsMode()
	switch mode {
	case "", proto.TLSModeAlone, proto.TLSModeParent, proto.TLSModeChild:
	default:
		return nil, fmt.Errorf("未知的 TLS 入站模式: %s", mode)
	}
	if mode != "" {
		if err := r.loadTLS(); err != nil {
			return nil, err
		}
	}
	if mode != proto.TLSModeParent && spec.OutGroup == 0 {
		if len(spec.Targets) == 0 {
			return nil, errors.New("没有转发目标")
		}
		r.bal = relay.NewBalancer(spec.Targets, spec.LB, cfg.MaxFail, time.Duration(cfg.FailTimeout)*time.Second)
	}
	if mode == proto.TLSModeChild {
		if len(spec.TLS.SNI) == 0 {
			return nil, errors.New("子规则没有配置 SNI")
		}
		return r, nil // 子规则不监听端口:连接由同端口的母规则握手后交过来
	}
	if mode != "" {
		r.self = &sniTarget{r: r, cfg: serverTLSConfig(r.cert, spec.TLS.ALPN)}
		r.outer = &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				t, err := r.route(strings.ToLower(chi.ServerName))
				if err != nil {
					return nil, err
				}
				return t.cfg, nil
			},
		}
	}

	addr := net.JoinHostPort(in.a.opt.Bind, fmt.Sprint(spec.ListenPort))
	if strings.Contains(spec.Proto, "tcp") {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		r.tcpLn = ln
	}
	if strings.Contains(spec.Proto, "udp") {
		ua, err := net.ResolveUDPAddr("udp", addr)
		var uc *net.UDPConn
		if err == nil {
			uc, err = net.ListenUDP("udp", ua)
		}
		if err != nil {
			if r.tcpLn != nil {
				r.tcpLn.Close()
			}
			return nil, err
		}
		uc.SetReadBuffer(4 << 20)
		uc.SetWriteBuffer(4 << 20)
		r.udp = &relay.UDPRelay{
			Conn: uc, Up: &r.up, Down: &r.down,
			UpLimits:   [2]*relay.Bucket{bucketUp(r.rlim), bucketUp(r.ulim)},
			DownLimits: [2]*relay.Bucket{bucketDown(r.rlim), bucketDown(r.ulim)},
			Open:       r.openUDP,
		}
		go r.udp.Serve()
	}
	if r.tcpLn != nil {
		go r.serveTCP()
	}
	return r, nil
}

func (r *ruleRunner) stop() {
	if r.closed.Swap(true) {
		return
	}
	if r.tcpLn != nil {
		r.tcpLn.Close()
	}
	if r.udp != nil {
		r.udp.Close()
	}
	r.mu.Lock()
	for c := range r.conns {
		c.Close()
	}
	r.mu.Unlock()
}

// track 登记一条属于本规则的连接;规则停止时会把它们全部关闭。
func (r *ruleRunner) track(c net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed.Load() {
		return false
	}
	r.conns[c] = struct{}{}
	return true
}

func (r *ruleRunner) untrack(c net.Conn) {
	r.mu.Lock()
	delete(r.conns, c)
	r.mu.Unlock()
}

func (r *ruleRunner) serveTCP() {
	for {
		c, err := r.tcpLn.Accept()
		if err != nil {
			if r.closed.Load() {
				return
			}
			time.Sleep(20 * time.Millisecond) // 文件描述符耗尽等瞬时错误
			continue
		}
		if r.outer != nil {
			go r.handleTLS(c)
		} else {
			go r.serve(c, addrPortOf(c.RemoteAddr()), true, "")
		}
	}
}

var (
	errSNIEmpty   = errors.New("TLS 入站: 客户端没有发送 SNI")
	errSNIDenied  = errors.New("TLS 入站: SNI 不在允许范围内")
	errSNIUnknown = errors.New("TLS 入站: 没有规则匹配这个 SNI")
	errTLSBlocked = errors.New("TLS 入站: 入口组屏蔽了 TLS 协议")
)

// route 决定一次 TLS 入站握手由哪条规则处理。握手过程中和握手完成后各调用一次。
func (r *ruleRunner) route(sni string) (*sniTarget, error) {
	in := r.in
	if sni == "" && in.rejectEmptySNI.Load() {
		return nil, errSNIEmpty
	}
	// 入口组的协议屏蔽与域名黑白名单同样约束 TLS 入站
	if pol := in.policy.Load(); pol != nil {
		if pol.BlockTLS {
			return nil, errTLSBlocked
		}
		if !pol.HostAllowed(sni) {
			return nil, errSNIDenied
		}
	}
	if r.tlsMode() == proto.TLSModeParent {
		if t := (*in.sni.Load())[r.spec.ListenPort][sni]; t != nil {
			return t, nil
		}
		return nil, errSNIUnknown
	}
	if names := r.spec.TLS.SNI; len(names) > 0 && !slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, sni) }) {
		return nil, errSNIDenied
	}
	return r.self, nil
}

// handleTLS 在监听端口上终结 TLS,然后把内层的明文连接交给握手归属的规则。
func (r *ruleRunner) handleTLS(c net.Conn) {
	src := addrPortOf(c.RemoteAddr())
	if !r.track(c) { // 握手期间的连接记在监听它的规则名下
		c.Close()
		return
	}
	tc := tls.Server(c, r.outer)
	ctx, cancel := context.WithTimeout(context.Background(), tlsHandshakeTimeout)
	err := tc.HandshakeContext(ctx)
	cancel()
	r.untrack(c)
	if err != nil {
		c.Close()
		return
	}
	cs := tc.ConnectionState()
	t, err := r.route(strings.ToLower(cs.ServerName))
	// 规则要求了 ALPN 时,没有声明 ALPN 的客户端也不接受(声明了但没有交集的在握手阶段就失败了)
	if err != nil || (len(t.r.spec.TLS.ALPN) > 0 && cs.NegotiatedProtocol == "") {
		tc.Close()
		return
	}
	t.r.serve(tc, src, false, cs.NegotiatedProtocol)
}

// serve 转发一条客户端连接。c 是原始 TCP 连接,或入口终结 TLS 之后的明文连接。
// sniff 表示需要按入口组的入站策略检查首包;alpn 是 TLS 入站时协商出的应用层协议。
func (r *ruleRunner) serve(c net.Conn, src netip.AddrPort, sniff bool, alpn string) {
	if !relay.AcquireAll(src.Addr(), r.rlim, r.ulim) {
		c.Close()
		return
	}
	defer relay.ReleaseAll(src.Addr(), r.rlim, r.ulim)
	if !r.track(c) {
		c.Close()
		return
	}
	defer r.untrack(c)

	var prefix []byte
	if sniff {
		if pol := r.in.policy.Load(); pol != nil {
			var ok bool
			if prefix, ok = pol.Check(c); !ok {
				c.Close()
				return
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	var target net.Conn
	var done func()
	var err error
	if r.spec.OutGroup == 0 {
		var be *relay.Backend
		var pp []byte
		target, be, pp, err = connectTarget(ctx, r.in.dialer.Load(), r.bal, relay.HashAddr(src.Addr()), targetOpts{
			proxyProtocol: r.spec.ProxyProtocol, src: src, dst: addrPortOf(c.LocalAddr()),
			origin: r.spec.OriginTLS, alpn: alpn,
		})
		if err == nil {
			done = func() { be.Active.Add(-1) }
			prefix = append(pp, prefix...)
		}
	} else if cli := r.in.tunnels.get(r.spec.OutGroup); cli != nil {
		h := tunnel.StreamHeader{Cmd: tunnel.CmdTCP, RuleID: uint32(r.spec.ID), Src: src}
		if r.spec.OriginTLS != nil {
			// 只有最后一跳要做回源 TLS 时才需要 ALPN。其余情况保持 1.0 的流头格式,还没升级的出口也能照常处理。
			h.ALPN = alpn
		}
		target, done, err = cli.Open(ctx, h)
	} else {
		err = errors.New("出口组不可用")
	}
	cancel()
	if err != nil {
		c.Close()
		return
	}
	relay.Pipe(c, target, &relay.PipeOpts{
		Up: &r.up, Down: &r.down,
		UpLimits:   [2]*relay.Bucket{bucketUp(r.rlim), bucketUp(r.ulim)},
		DownLimits: [2]*relay.Bucket{bucketDown(r.rlim), bucketDown(r.ulim)},
		Prefix:     prefix,
	})
	done()
}

func (r *ruleRunner) openUDP(client netip.AddrPort, _ uint32) (relay.Upstream, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	if r.spec.OutGroup == 0 {
		cands := r.bal.Candidates(relay.HashAddr(client.Addr()))
		uc, err := r.in.dialer.Load().DialUDP(ctx, cands[0].Addr)
		if err != nil {
			return nil, err
		}
		return relay.UDPConnUpstream{UDPConn: uc}, nil
	}
	cli := r.in.tunnels.get(r.spec.OutGroup)
	if cli == nil {
		return nil, errors.New("出口组不可用")
	}
	return cli.OpenUDP(ctx, uint32(r.spec.ID), client, r.spec.UDPStream)
}
