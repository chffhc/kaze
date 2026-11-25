package node

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"kaze/internal/proto"
	"kaze/internal/relay"
	"kaze/internal/tunnel"
)

const connectTimeout = 10 * time.Second

// inbound 管理入口节点上的全部转发规则。
type inbound struct {
	a *Agent

	mu      sync.Mutex
	rules   map[int64]*ruleRunner
	users   map[int64]*userEntry
	tunnels map[int64]*tunnelEntry
	errs    map[int64]string
	orphan  map[int64][2]int64 // 已停止规则尚未上报的流量
	last    *proto.InboundConfig

	policy atomic.Pointer[relay.SniffPolicy]
	dialer atomic.Pointer[relay.Dialer]
	tunMap atomic.Pointer[map[int64]*tunnel.Client]
}

type userEntry struct {
	spec proto.UserLimit
	lim  *relay.Limits
}

type tunnelEntry struct {
	spec proto.TunnelSpec
	cli  *tunnel.Client
}

func newInbound(a *Agent) *inbound {
	in := &inbound{
		a:       a,
		rules:   make(map[int64]*ruleRunner),
		users:   make(map[int64]*userEntry),
		tunnels: make(map[int64]*tunnelEntry),
		errs:    make(map[int64]string),
		orphan:  make(map[int64][2]int64),
	}
	in.dialer.Store(relay.NewDialer(false))
	empty := map[int64]*tunnel.Client{}
	in.tunMap.Store(&empty)
	return in
}

// apply 把运行状态收敛到新配置:未变化的规则不受影响,变化的规则重启,消失的规则停止。
func (in *inbound) apply(cfg *proto.InboundConfig) {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.applyLocked(cfg)
}

func (in *inbound) applyLocked(cfg *proto.InboundConfig) {
	in.last = cfg

	// 1. 隧道客户端
	for gid, spec := range cfg.Tunnels {
		if old := in.tunnels[gid]; old != nil {
			if reflect.DeepEqual(old.spec, *spec) {
				continue
			}
			old.cli.Retire()
			delete(in.tunnels, gid)
		}
		cli, err := tunnel.NewClient(spec, tunnel.ClientOpts{
			MaxFail: cfg.MaxFail, FailTimeout: time.Duration(cfg.FailTimeout) * time.Second, Now: in.a.now,
		})
		if err != nil {
			log.Printf("[入口] 出口组 #%d 隧道配置无效: %v", gid, err)
			continue
		}
		in.tunnels[gid] = &tunnelEntry{spec: *spec, cli: cli}
	}
	for gid, old := range in.tunnels {
		if _, ok := cfg.Tunnels[gid]; !ok {
			old.cli.Retire()
			delete(in.tunnels, gid)
		}
	}
	tm := make(map[int64]*tunnel.Client, len(in.tunnels))
	for gid, e := range in.tunnels {
		tm[gid] = e.cli
	}
	in.tunMap.Store(&tm)

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
	if d := in.dialer.Load(); d.AllowPrivate != cfg.AllowPrivate {
		in.dialer.Store(relay.NewDialer(cfg.AllowPrivate))
	}

	// 4. 规则
	want := make(map[int64]*proto.Rule, len(cfg.Rules))
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if cfg.DisableUDP {
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

// retryFailed 重新尝试启动失败的规则(例如端口被占用后又释放)。
func (in *inbound) retryFailed() bool {
	in.mu.Lock()
	defer in.mu.Unlock()
	if len(in.errs) == 0 || in.last == nil {
		return false
	}
	in.applyLocked(in.last)
	return true
}

// collect 取走自上次以来的流量增量。
func (in *inbound) collect() []proto.Traffic {
	var out []proto.Traffic
	in.collectIf(func(v proto.Traffic) bool { out = append(out, v); return true })
	return out
}

// Subtract only accepted snapshots. Concurrent per-packet increments remain live.
func (in *inbound) collectIf(take func(proto.Traffic) bool) {
	in.mu.Lock()
	defer in.mu.Unlock()
	for id, o := range in.orphan {
		if o == [2]int64{} || take(proto.Traffic{RuleID: id, Up: o[0], Down: o[1]}) {
			delete(in.orphan, id)
		}
	}
	for id, run := range in.rules {
		up, down := run.up.Load(), run.down.Load()
		if (up != 0 || down != 0) && take(proto.Traffic{RuleID: id, Up: up, Down: down}) {
			run.up.Add(-up)
			run.down.Add(-down)
		}
	}
}

func (in *inbound) ruleErrors() map[int64]string {
	in.mu.Lock()
	defer in.mu.Unlock()
	out := make(map[int64]string, len(in.errs))
	for k, v := range in.errs {
		out[k] = v
	}
	return out
}

func (in *inbound) tunnel(gid int64) *tunnel.Client { return (*in.tunMap.Load())[gid] }

func (in *inbound) stopAll() {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.last = nil
	clear(in.errs)
	for id, run := range in.rules {
		in.stopLocked(id, run)
	}
	for gid, e := range in.tunnels {
		e.cli.Close()
		delete(in.tunnels, gid)
	}
}

// diag 测量本节点到规则下一跳(出口节点或目标)的 TCP 建连耗时。
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
	if run.spec.OutGroup == 0 {
		return tcping(from, "目标 ", run.spec.Targets, in.dialer.Load())
	}
	cli := in.tunnel(run.spec.OutGroup)
	if cli == nil {
		return []proto.DiagHop{{From: from, To: "-", Error: "出口组不可用"}}
	}
	return tcping(from, "出口 ", cli.Endpoints(), relay.NewDialer(true))
}

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

// ---- 单条规则 ----

type ruleRunner struct {
	in   *inbound
	spec proto.Rule
	ulim *relay.Limits // 用户级
	rlim *relay.Limits // 规则级
	bal  *relay.Balancer

	up, down atomic.Int64

	tcpLn net.Listener
	udp   *relay.UDPRelay
	live  *ruleConns
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

func (in *inbound) startRule(spec proto.Rule, ulim *relay.Limits, cfg *proto.InboundConfig) (*ruleRunner, error) {
	r := &ruleRunner{
		in: in, spec: spec, ulim: ulim,
		rlim: relay.NewLimits(spec.SpeedLimit, spec.ConnLimit, spec.IPLimit),
	}
	if spec.OutGroup == 0 {
		if len(spec.Targets) == 0 {
			return nil, fmt.Errorf("没有转发目标")
		}
		r.bal = relay.NewBalancer(spec.Targets, spec.LB, cfg.MaxFail, time.Duration(cfg.FailTimeout)*time.Second)
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
	}
	r.live = newRuleConns()
	if r.udp != nil {
		go r.udp.Serve()
	}
	if r.tcpLn != nil {
		go r.serveTCP()
	}
	return r, nil
}

func (r *ruleRunner) stop() {
	r.live.stop()
	if r.tcpLn != nil {
		r.tcpLn.Close()
	}
	if r.udp != nil {
		r.udp.Close()
	}
}

func (r *ruleRunner) serveTCP() {
	for {
		c, err := r.tcpLn.Accept()
		if err != nil {
			if r.live.ctx.Err() != nil {
				return
			}
			time.Sleep(20 * time.Millisecond) // 文件描述符耗尽等瞬时错误
			continue
		}
		go r.handle(c)
	}
}

func addrPortOf(a net.Addr) netip.AddrPort {
	if t, ok := a.(*net.TCPAddr); ok {
		ap := t.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}

func (r *ruleRunner) handle(c net.Conn) {
	src := addrPortOf(c.RemoteAddr())
	if !relay.AcquireAll(src.Addr(), r.rlim, r.ulim) {
		c.Close()
		return
	}
	defer relay.ReleaseAll(src.Addr(), r.rlim, r.ulim)

	if !r.live.track(c) {
		return
	}
	defer r.live.forget(c)

	var prefix []byte
	if pol := r.in.policy.Load(); pol != nil {
		var ok bool
		if prefix, ok = pol.Check(c); !ok {
			c.Close()
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.live.ctx, connectTimeout)
	var target net.Conn
	var done func()
	var err error
	if r.spec.OutGroup == 0 {
		var be *relay.Backend
		target, be, err = relay.DialBalanced(ctx, r.in.dialer.Load(), r.bal, relay.HashAddr(src.Addr()))
		if err == nil {
			done = func() { be.Active.Add(-1) }
			if r.spec.ProxyProtocol > 0 {
				pp := relay.ProxyHeader(r.spec.ProxyProtocol, src, addrPortOf(c.LocalAddr()))
				prefix = append(pp, prefix...)
			}
		}
	} else if cli := r.in.tunnel(r.spec.OutGroup); cli != nil {
		target, done, err = cli.Open(ctx, tunnel.StreamHeader{Cmd: tunnel.CmdTCP, RuleID: uint32(r.spec.ID), Src: src})
	} else {
		err = fmt.Errorf("出口组不可用")
	}
	cancel()
	if err != nil {
		c.Close()
		return
	}
	defer done()
	if !r.live.track(target) {
		return
	}
	defer r.live.forget(target)
	relay.Pipe(c, target, &relay.PipeOpts{
		Up: &r.up, Down: &r.down,
		UpLimits:   [2]*relay.Bucket{bucketUp(r.rlim), bucketUp(r.ulim)},
		DownLimits: [2]*relay.Bucket{bucketDown(r.rlim), bucketDown(r.ulim)},
		Prefix:     prefix,
	})
}

func (r *ruleRunner) openUDP(client netip.AddrPort, _ uint32) (relay.Upstream, error) {
	ctx, cancel := context.WithTimeout(r.live.ctx, connectTimeout)
	defer cancel()
	if r.spec.OutGroup == 0 {
		cands := r.bal.Candidates(relay.HashAddr(client.Addr()))
		uc, err := r.in.dialer.Load().DialUDP(ctx, cands[0].Addr)
		if err != nil {
			return nil, err
		}
		return relay.UDPConnUpstream{UDPConn: uc}, nil
	}
	cli := r.in.tunnel(r.spec.OutGroup)
	if cli == nil {
		return nil, fmt.Errorf("出口组不可用")
	}
	return cli.OpenUDP(ctx, uint32(r.spec.ID), client)
}
