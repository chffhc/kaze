package panel

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"kaze/internal/proto"
	"kaze/internal/tunnel"
)

const (
	reportInterval  = 10              // 节点流量上报间隔(秒)
	nodeRetention   = 24 * 3600       // 离线出口节点继续保留在入口连接列表里的时长(秒)
	nodeOfflineSecs = 20              // 探针判定离线的时间(秒)
	resyncInterval  = 5 * time.Minute // 周期性全量同步(兼做时钟校准)
)

// Hub 维护所有节点的控制连接:下发配置、接收流量与探针、转发诊断请求。
type Hub struct {
	s *Server

	mu    sync.RWMutex
	conns map[string]*nodeConn // key = "组ID/节点UID"

	dirtyMu  sync.Mutex
	dirty    map[int64]bool
	dirtyAll bool
	kick     chan struct{}

	version atomic.Int64
	seqMu   sync.Mutex
	lastSeq map[string]int64

	diagMu   sync.Mutex
	diagWait map[string]chan proto.DiagResult
}

type nodeConn struct {
	key     string
	groupID int64
	role    string
	nodeID  int64
	hello   proto.Hello
	ip      string
	ws      *websocket.Conn
	send    chan []byte
	since   int64

	mu         sync.Mutex
	metrics    *proto.Metrics
	metricsAt  int64
	ruleErrors map[int64]string // 节点上报的:规则启动失败的原因
	skipped    map[int64]string // 面板判定的:因节点端版本过旧而没有下发的规则
	cfgHash    [32]byte
	closed     bool
}

func newHub(s *Server) *Hub {
	return &Hub{
		s: s, conns: make(map[string]*nodeConn), dirty: make(map[int64]bool),
		kick: make(chan struct{}, 1), lastSeq: make(map[string]int64),
		diagWait: make(map[string]chan proto.DiagResult),
	}
}

// Dirty 标记设备组的配置需要重新下发(不传参数 = 全部)。
func (h *Hub) Dirty(groups ...int64) {
	h.dirtyMu.Lock()
	if len(groups) == 0 {
		h.dirtyAll = true
	}
	for _, g := range groups {
		h.dirty[g] = true
	}
	h.dirtyMu.Unlock()
	select {
	case h.kick <- struct{}{}:
	default:
	}
}

func (h *Hub) run(ctx context.Context) {
	resync := time.NewTicker(resyncInterval)
	defer resync.Stop()
	for {
		select {
		case <-ctx.Done():
			h.mu.Lock()
			for _, c := range h.conns {
				c.ws.Close()
			}
			h.mu.Unlock()
			return
		case <-resync.C:
			h.flush(true, nil, true)
		case <-h.kick:
			time.Sleep(200 * time.Millisecond) // 合并短时间内的多次变更
			h.dirtyMu.Lock()
			all, set := h.dirtyAll, h.dirty
			h.dirtyAll, h.dirty = false, make(map[int64]bool)
			h.dirtyMu.Unlock()
			h.flush(all, set, false)
		}
	}
}

// flush 为受影响的设备组重新生成配置;内容没有变化的节点不会收到推送。
func (h *Hub) flush(all bool, set map[int64]bool, force bool) {
	h.mu.RLock()
	targets := make([]*nodeConn, 0, len(h.conns))
	for _, c := range h.conns {
		if all || set[c.groupID] {
			targets = append(targets, c)
		}
	}
	h.mu.RUnlock()
	cache := map[int64]*proto.NodeConfig{}
	for _, c := range targets {
		cfg, ok := cache[c.groupID]
		if !ok {
			var err error
			if cfg, err = h.buildConfig(c.groupID); err != nil {
				log.Printf("[hub] 生成设备组 #%d 配置失败: %v", c.groupID, err)
			}
			cache[c.groupID] = cfg
		}
		if cfg != nil {
			h.pushConfig(c, cfg, force)
		}
	}
}

func (h *Hub) pushConfig(c *nodeConn, cfg *proto.NodeConfig, force bool) {
	out := *cfg
	// 出口:命令行指定的端口优先
	if out.Outbound != nil && c.hello.TunnelPort > 0 {
		ob := *out.Outbound
		ob.ListenPort = c.hello.TunnelPort
		out.Outbound = &ob
	}
	// 入口:没有以 -rev-port 启动的机器接不了反向连接,对它一律按正向隧道下发
	if out.Inbound != nil && c.hello.RevPort == 0 {
		out.Inbound = withoutReverse(out.Inbound)
	}
	// 1.1 之前的节点端不认识新增的字段,会把这些规则当成普通规则来跑(例如把 TLS 入站规则变成明文转发)。
	// 这类规则不下发给它们,并在规则状态里说明原因。
	var skipped map[int64]string
	if !versionAtLeast(c.hello.Version, "1.1.0") {
		out.Inbound, out.Outbound, skipped = forLegacyNode(out.Inbound, out.Outbound, c.hello.Version)
	}
	body, _ := json.Marshal(struct {
		I *proto.InboundConfig
		O *proto.OutboundConfig
	}{out.Inbound, out.Outbound})
	sum := sha256.Sum256(body)
	c.mu.Lock()
	same := sum == c.cfgHash
	c.cfgHash = sum
	c.skipped = skipped
	c.mu.Unlock()
	if same && !force {
		return
	}
	out.Version = h.version.Add(1)
	out.Now = time.Now().UnixMilli()
	c.trySend(proto.Pack(proto.TConfig, &out))
}

// versionAtLeast 比较 "主.次.修订" 形式的版本号;v 无法解析时视为更旧。
func versionAtLeast(v, min string) bool {
	parse := func(s string) (out [3]int, ok bool) {
		n, _ := fmt.Sscanf(s, "%d.%d.%d", &out[0], &out[1], &out[2])
		return out, n >= 2
	}
	a, ok := parse(v)
	b, _ := parse(min)
	if !ok {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return true
}

// forLegacyNode 为 1.0.x 的节点端裁剪配置(返回副本,不修改原配置),并给出被去掉的规则及原因。
func forLegacyNode(in *proto.InboundConfig, out *proto.OutboundConfig, ver string) (*proto.InboundConfig, *proto.OutboundConfig, map[int64]string) {
	skipped := map[int64]string{}
	why := func(feature string) string {
		return fmt.Sprintf("节点端版本 %s 不支持%s,请把这台机器升级到 %s", ver, feature, proto.Version)
	}
	if in != nil {
		cp := *in
		cp.Rules = make([]proto.Rule, 0, len(in.Rules))
		cp.Tunnels = make(map[int64]*proto.TunnelSpec, len(in.Tunnels))
		for k, ts := range in.Tunnels {
			if ts.Transport != tunnel.TransportHTTP {
				cp.Tunnels[k] = ts
			}
		}
		for _, r := range in.Rules {
			switch {
			case r.TLS != nil:
				skipped[r.ID] = why(" TLS 入站")
			case r.OutGroup != 0 && in.Tunnels[r.OutGroup] != nil && in.Tunnels[r.OutGroup].Transport == tunnel.TransportHTTP:
				skipped[r.ID] = why(" HTTP 伪装传输层")
			default:
				cp.Rules = append(cp.Rules, r)
			}
		}
		cp.Reverse, cp.TLSRejectEmptySNI = nil, false
		in = &cp
	}
	if out != nil {
		cp := *out
		cp.Rules = make([]proto.OutRule, 0, len(out.Rules))
		for _, r := range out.Rules {
			switch {
			case r.Next != 0:
				skipped[r.ID] = why("链式出口")
			case r.OriginTLS != nil:
				skipped[r.ID] = why("回源 TLS")
			default:
				cp.Rules = append(cp.Rules, r)
			}
		}
		cp.Tunnels, cp.Reverse = nil, nil
		out = &cp
	}
	if len(skipped) == 0 {
		skipped = nil
	}
	return in, out, skipped
}

// withoutReverse 返回去掉反向隧道设置的入口配置副本(不修改原配置,它被同组的其它节点共用)。
func withoutReverse(in *proto.InboundConfig) *proto.InboundConfig {
	uses := in.Reverse != nil
	for _, ts := range in.Tunnels {
		if ts.Reverse || (ts.Fallback != nil && ts.Fallback.Reverse) {
			uses = true
		}
	}
	if !uses {
		return in
	}
	cp := *in
	cp.Reverse = nil
	cp.Tunnels = make(map[int64]*proto.TunnelSpec, len(in.Tunnels))
	for k, ts := range in.Tunnels {
		if !ts.Reverse && (ts.Fallback == nil || !ts.Fallback.Reverse) {
			cp.Tunnels[k] = ts // 与反向隧道无关:不必复制
			continue
		}
		t := *ts
		t.Reverse = false
		if t.Fallback != nil && t.Fallback.Reverse {
			fb := *t.Fallback
			fb.Reverse = false
			t.Fallback = &fb
		}
		cp.Tunnels[k] = &t
	}
	return &cp
}

func (c *nodeConn) trySend(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	select {
	case c.send <- b:
	default:
		// 发送队列堵塞说明连接已不健康,断开让节点重连后重新同步
		c.closed = true
		c.ws.Close()
	}
}

// ---- 配置生成 ----

func mbps(v int) int64 { return int64(v) * 125000 }

// endpoints 返回入口连接出口组 g 时使用的地址列表。
func (h *Hub) endpoints(g *Group) []string {
	cfg := &g.Config
	if cfg.CDN {
		if cfg.ConnectHost == "" {
			return nil
		}
		port := cfg.ConnectPort
		if port == 0 {
			port = 80
			if cfg.CDNTLS {
				port = 443
			}
		}
		return []string{net.JoinHostPort(cfg.ConnectHost, fmt.Sprint(port))}
	}
	nodes, err := listNodes(h.s.db, `WHERE group_id=? AND last_seen>?`, g.ID, now()-nodeRetention)
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, n := range nodes {
		host := n.ConnectHost
		if host == "" {
			host = cfg.ConnectHost
		}
		if host == "" {
			host = n.IP
		}
		port := cfg.ConnectPort
		if port == 0 {
			port = n.TunnelPort
		}
		if host == "" || port == 0 {
			continue
		}
		ep := net.JoinHostPort(host, fmt.Sprint(port))
		if !seen[ep] {
			seen[ep] = true
			out = append(out, ep)
		}
	}
	return out
}

// groupSet 是按 ID 索引的全部设备组。
type groupSet map[int64]*Group

func (h *Hub) loadGroups() ([]*Group, groupSet, error) {
	all, err := listGroups(h.s.db)
	if err != nil {
		return nil, nil, err
	}
	gs := make(groupSet, len(all))
	for _, g := range all {
		gs[g.ID] = g
	}
	return all, gs, nil
}

// hops 返回一条规则依次经过的出口组;直接转发返回空。chain 非 nil 表示规则选的是链式出口。
// 出口不存在、类型不对或链路不完整时 ok 为 false,这样的规则不会下发。
func (gs groupSet) hops(outGroup int64) (hops []*Group, chain *Group, ok bool) {
	if outGroup == 0 {
		return nil, nil, true
	}
	g := gs[outGroup]
	switch {
	case g == nil:
		return nil, nil, false
	case g.Type == proto.RoleOut:
		return []*Group{g}, nil, true
	case g.Type == proto.RoleChain:
		if n := len(g.Config.ChainHops); n < 2 || n > 3 {
			return nil, nil, false
		}
		for _, id := range g.Config.ChainHops {
			hg := gs[id]
			if hg == nil || hg.Type != proto.RoleOut {
				return nil, nil, false
			}
			hops = append(hops, hg)
		}
		return hops, g, true
	}
	return nil, nil, false
}

// reverseFor 报告入口组 in 连接出口组 out 时是否使用反向隧道(由出口主动拨入)。
// CDN 模式的出口不支持:它与入口之间隔着 CDN。
func reverseFor(in, out *Group) bool {
	return in != nil && in.Type == proto.RoleIn && in.Config.RevCertPEM != "" && in.Config.RevCertPin != "" &&
		out.Type == proto.RoleOut && !out.Config.CDN && matchGroupList(in.Config.ReverseGroups, out.ID)
}

// tunnelSpec 生成"连接出口组 g"所需的隧道配置。from 是发起连接的入口组(出口之间的链路传 nil)。
func (h *Hub) tunnelSpec(g *Group, withFallback bool, groups groupSet, from *Group) *proto.TunnelSpec {
	cfg := &g.Config
	spec := &proto.TunnelSpec{
		GroupID: g.ID, Endpoints: h.endpoints(g), Transport: cfg.Transport, Mux: cfg.Mux, MuxConns: cfg.MuxConns,
		Key: cfg.TunnelKey, SNI: cfg.SNI, Host: cfg.WSHost, Path: cfg.WSPath, UDPOverTCP: cfg.UDPOverTCP,
		Reverse: reverseFor(from, g),
	}
	switch {
	case cfg.CDN:
		spec.Transport = tunnel.TransportWS
		if cfg.CDNTLS {
			spec.Transport = tunnel.TransportWSS
		}
		if spec.Host == "" {
			spec.Host = cfg.ConnectHost
		}
		if spec.SNI == "" {
			spec.SNI = spec.Host
		}
	case tunnel.TransportUsesTLS(cfg.Transport):
		spec.CertPin = cfg.CertPin
	}
	if tunnel.TransportUsesTLS(spec.Transport) {
		spec.Fingerprint = cfg.Fingerprint
	}
	if withFallback && cfg.FailoverGroup != 0 && cfg.FailoverGroup != g.ID {
		if fb := groups[cfg.FailoverGroup]; fb != nil && fb.Type == proto.RoleOut {
			spec.Fallback = h.tunnelSpec(fb, false, groups, from)
		}
	}
	return spec
}

// 入口配置里隧道的键:普通规则用出口组 ID(与 1.0 相同);链式出口的第一跳用它的相反数,
// 对应一份不带故障转移组的配置——链路上的每一跳都是固定的,不能半路换到链路之外的组。
func chainFirstHopKey(groupID int64) int64 { return -groupID }

// 出口配置里"到下一跳"隧道的键:同一个下一跳按是否复用分成两份。
func nextHopKey(groupID int64, mux bool) int64 {
	if mux {
		return groupID*2 + 1
	}
	return groupID * 2
}

func (h *Hub) buildConfig(groupID int64) (*proto.NodeConfig, error) {
	all, groups, err := h.loadGroups()
	if err != nil {
		return nil, err
	}
	g := groups[groupID]
	if g == nil {
		return nil, fmt.Errorf("设备组不存在")
	}
	cfg := &proto.NodeConfig{Role: g.Type, GroupID: g.ID, ReportInterval: reportInterval}
	switch g.Type {
	case proto.RoleIn:
		cfg.Inbound, err = h.buildInbound(g, all, groups)
	case proto.RoleOut:
		cfg.Outbound, err = h.buildOutbound(g, all, groups)
	default:
		err = fmt.Errorf("设备组 #%d 不是入口组或出口组,不能对接节点", g.ID)
	}
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func (h *Hub) buildInbound(g *Group, all []*Group, groups groupSet) (*proto.InboundConfig, error) {
	gc := &g.Config
	in := &proto.InboundConfig{
		Rules: []proto.Rule{}, Users: map[int64]proto.UserLimit{}, Tunnels: map[int64]*proto.TunnelSpec{},
		BlockedProtocols: gc.BlockedProtocols, BlockedHosts: gc.BlockedHosts, AllowedHosts: gc.AllowedHosts,
		AllowPrivate: gc.AllowPrivate, DisableUDP: gc.DisableUDP, MaxFail: gc.MaxFail, FailTimeout: gc.FailTimeout,
		TLSRejectEmptySNI: gc.TLSRejectEmptySNI,
	}
	// 反向隧道:名单里的出口组都可能拨入,不论当前有没有规则在用它们
	if gc.RevCertPEM != "" {
		allowed := map[int64]string{}
		for _, og := range all {
			if reverseFor(g, og) && og.Config.TunnelKey != "" {
				allowed[og.ID] = og.Config.TunnelKey
			}
		}
		if len(allowed) > 0 {
			in.Reverse = &proto.ReverseListen{CertPEM: gc.RevCertPEM, KeyPEM: gc.RevKeyPEM, Groups: allowed}
		}
	}
	rows, err := h.s.db.Query(`SELECT `+ruleCols+`,u.speed_limit,u.conn_limit,u.ip_limit FROM rules r
		JOIN users u ON u.id=r.user_id WHERE r.in_group=? AND r.paused=0 AND `+activeUserSQL+` ORDER BY r.id`, g.ID, now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var us, uc, ui int
		r, err := scanRule(rows, &us, &uc, &ui)
		if err != nil {
			return nil, err
		}
		pr := proto.Rule{
			ID: r.ID, UserID: r.UserID, ListenPort: r.ListenPort, Proto: r.Proto,
			LB: r.LB, SpeedLimit: mbps(r.SpeedLimit), ConnLimit: r.ConnLimit, IPLimit: r.IPLimit,
			TLS: r.tlsInbound(),
		}
		if r.TLSMode != proto.TLSModeParent { // 母规则只负责监听和分流,自己不转发
			hops, chain, ok := groups.hops(r.OutGroup)
			// 回源 TLS 由最后一跳执行。经隧道时也告诉入口一声:它据此决定要不要把协商出的 ALPN 带给最后一跳。
			pr.OriginTLS = r.originTLS()
			switch {
			case !ok:
				continue
			case len(hops) == 0:
				pr.Targets, pr.ProxyProtocol = r.Targets, r.ProxyProtocol
			case chain == nil:
				pr.OutGroup = hops[0].ID
				if in.Tunnels[pr.OutGroup] == nil {
					in.Tunnels[pr.OutGroup] = h.tunnelSpec(hops[0], true, groups, g)
				}
			default:
				pr.OutGroup, pr.UDPStream = chainFirstHopKey(hops[0].ID), true
				if in.Tunnels[pr.OutGroup] == nil {
					in.Tunnels[pr.OutGroup] = h.tunnelSpec(hops[0], false, groups, g)
				}
			}
		}
		in.Rules = append(in.Rules, pr)
		if us != 0 || uc != 0 || ui != 0 {
			in.Users[r.UserID] = proto.UserLimit{SpeedLimit: mbps(us), ConnLimit: uc, IPLimit: ui}
		}
	}
	return in, rows.Err()
}

func (h *Hub) buildOutbound(g *Group, all []*Group, groups groupSet) (*proto.OutboundConfig, error) {
	gc := &g.Config
	out := &proto.OutboundConfig{
		ListenPort: gc.TunnelPort, Transport: gc.Transport, Key: gc.TunnelKey, Path: gc.WSPath,
		Rules: []proto.OutRule{}, AllowPrivate: gc.AllowPrivate, MaxFail: gc.MaxFail, FailTimeout: gc.FailTimeout,
	}
	switch {
	case gc.CDN:
		out.Transport = tunnel.TransportWS // CDN 回源走明文 ws,TLS 由 CDN 终结
	case tunnel.TransportUsesTLS(gc.Transport):
		out.CertPEM, out.KeyPEM = gc.CertPEM, gc.KeyPEM
	}

	// 反向隧道:把本组列入反向名单的入口组里,所有开了反向端口的机器
	for _, ig := range all {
		if !reverseFor(ig, g) {
			continue
		}
		nodes, err := listNodes(h.s.db, `WHERE group_id=? AND rev_port>0 AND last_seen>?`, ig.ID, now()-nodeRetention)
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for _, n := range nodes {
			host := n.ConnectHost
			if host == "" {
				host = n.IP
			}
			ep := net.JoinHostPort(host, fmt.Sprint(n.RevPort))
			if host == "" || seen[ep] {
				continue
			}
			seen[ep] = true
			out.Reverse = append(out.Reverse, proto.ReverseSpec{
				Endpoint: ep, CertPin: ig.Config.RevCertPin, SNI: ig.Config.ReverseSNI,
				Fingerprint: gc.Fingerprint, Conns: ig.Config.ReverseConns,
			})
		}
	}

	// 与本组有关的规则:选了本组的、选了"以本组为故障转移组"的出口组的,以及选了经过本组的链式出口的
	ids, ph := []any{g.ID}, "?"
	for _, og := range all {
		related := og.Type == proto.RoleOut && og.ID != g.ID && og.Config.FailoverGroup == g.ID
		if og.Type == proto.RoleChain {
			for _, id := range og.Config.ChainHops {
				related = related || id == g.ID
			}
		}
		if related {
			ids, ph = append(ids, og.ID), ph+",?"
		}
	}
	rows, err := h.s.db.Query(`SELECT `+ruleCols+` FROM rules r JOIN users u ON u.id=r.user_id
		WHERE r.out_group IN (`+ph+`) AND r.paused=0 AND r.tls_mode<>'parent' AND `+activeUserSQL+` ORDER BY r.id`, append(ids, now())...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		hops, chain, ok := groups.hops(r.OutGroup)
		if !ok || len(hops) == 0 {
			continue
		}
		last := proto.OutRule{ID: r.ID, Targets: r.Targets, LB: r.LB, ProxyProtocol: r.ProxyProtocol, OriginTLS: r.originTLS()}
		if chain == nil { // 普通出口:本组是规则选的出口,或是它的故障转移组
			out.Rules = append(out.Rules, last)
			continue
		}
		pos := -1
		for i, hg := range hops {
			if hg.ID == g.ID {
				pos = i
				break
			}
		}
		switch {
		case pos < 0:
		case pos == len(hops)-1:
			out.Rules = append(out.Rules, last)
		default:
			next := hops[pos+1]
			key := nextHopKey(next.ID, chain.Config.ChainMux)
			if out.Tunnels == nil {
				out.Tunnels = map[int64]*proto.TunnelSpec{}
			}
			if out.Tunnels[key] == nil {
				spec := h.tunnelSpec(next, false, groups, nil)
				spec.Mux = chain.Config.ChainMux
				out.Tunnels[key] = spec
			}
			out.Rules = append(out.Rules, proto.OutRule{ID: r.ID, Next: key})
		}
	}
	return out, rows.Err()
}

// ---- 节点连接 ----

var nodeUpgrader = websocket.Upgrader{ReadBufferSize: 16 << 10, WriteBufferSize: 16 << 10}

func (h *Hub) serveWS(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	g, err := scanGroup(h.s.db.QueryRow(`SELECT `+groupCols+` FROM device_groups WHERE token=?`, token))
	if err != nil || (g.Type != proto.RoleIn && g.Type != proto.RoleOut) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ws, err := nodeUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()
	ws.SetReadLimit(8 << 20)

	// 首帧必须是 hello
	ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, data, err := ws.ReadMessage()
	if err != nil {
		return
	}
	var m proto.Msg
	var hello proto.Hello
	if json.Unmarshal(data, &m) != nil || m.T != proto.THello || json.Unmarshal(m.D, &hello) != nil || hello.UID == "" {
		return
	}
	ip := h.s.clientIP(r)
	t := now()
	if hello.RevPort < 0 || hello.RevPort > 65535 || g.Type != proto.RoleIn {
		hello.RevPort = 0
	}
	// 入口节点的地址或反向端口变了,出口那边的反向连接目标也要跟着变
	var oldIP, oldHost string
	oldRev := -1
	h.s.db.QueryRow(`SELECT ip, connect_host, rev_port FROM nodes WHERE group_id=? AND uid=?`, g.ID, hello.UID).Scan(&oldIP, &oldHost, &oldRev)
	revChanged := (hello.RevPort > 0 || oldRev > 0) && (oldRev != hello.RevPort || oldIP != ip || oldHost != hello.ConnectHost)
	if _, err := h.s.db.Exec(`INSERT INTO nodes(group_id,uid,hostname,ip,version,os,arch,connect_host,tunnel_port,first_seen,last_seen,rev_port)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(group_id,uid) DO UPDATE SET hostname=excluded.hostname, ip=excluded.ip, version=excluded.version,
		os=excluded.os, arch=excluded.arch, connect_host=excluded.connect_host, last_seen=excluded.last_seen, rev_port=excluded.rev_port`,
		g.ID, hello.UID, hello.Hostname, ip, hello.Version, hello.OS, hello.Arch, hello.ConnectHost, 0, t, t, hello.RevPort); err != nil {
		log.Printf("[hub] 记录节点失败: %v", err)
		return
	}
	c := &nodeConn{
		key: fmt.Sprintf("%d/%s", g.ID, hello.UID), groupID: g.ID, role: g.Type, hello: hello, ip: ip,
		ws: ws, send: make(chan []byte, 64), since: t,
	}
	h.s.db.QueryRow(`SELECT id FROM nodes WHERE group_id=? AND uid=?`, g.ID, hello.UID).Scan(&c.nodeID)

	h.mu.Lock()
	if old := h.conns[c.key]; old != nil {
		old.ws.Close() // 同一实例重复连接:保留新的
	}
	h.conns[c.key] = c
	h.mu.Unlock()
	log.Printf("[hub] 节点上线: %s (%s) 组 #%d %s", hello.Hostname, ip, g.ID, g.Name)

	defer func() {
		h.mu.Lock()
		if h.conns[c.key] == c {
			delete(h.conns, c.key)
		}
		h.mu.Unlock()
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		h.s.db.Exec(`UPDATE nodes SET last_seen=? WHERE id=?`, now(), c.nodeID)
		log.Printf("[hub] 节点离线: %s (%s)", hello.Hostname, ip)
	}()

	// 写协程
	done := make(chan struct{})
	defer close(done)
	go func() {
		ping := time.NewTicker(25 * time.Second)
		defer ping.Stop()
		for {
			select {
			case <-done:
				return
			case b := <-c.send:
				ws.SetWriteDeadline(time.Now().Add(15 * time.Second))
				if ws.WriteMessage(websocket.TextMessage, b) != nil {
					ws.Close()
					return
				}
			case <-ping.C:
				ws.SetWriteDeadline(time.Now().Add(15 * time.Second))
				if ws.WriteMessage(websocket.PingMessage, nil) != nil {
					ws.Close()
					return
				}
			}
		}
	}()

	if cfg, err := h.buildConfig(g.ID); err == nil {
		h.pushConfig(c, cfg, true)
	} else {
		log.Printf("[hub] 生成配置失败: %v", err)
	}
	if g.Type == proto.RoleOut || revChanged {
		h.Dirty() // 出口节点上线,或入口的反向端口有变化:对端的连接地址列表可能变化
	}

	lastTouch := t
	for {
		ws.SetReadDeadline(time.Now().Add(75 * time.Second))
		_, data, err := ws.ReadMessage()
		if err != nil {
			return
		}
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		switch m.T {
		case proto.TMetrics:
			var mt proto.Metrics
			if json.Unmarshal(m.D, &mt) == nil {
				c.mu.Lock()
				c.metrics, c.metricsAt = &mt, now()
				c.mu.Unlock()
			}
			if n := now(); n-lastTouch > 60 {
				lastTouch = n
				h.s.db.Exec(`UPDATE nodes SET last_seen=? WHERE id=?`, n, c.nodeID)
			}
		case proto.TReport:
			var rep proto.Report
			if json.Unmarshal(m.D, &rep) != nil {
				continue
			}
			if g.Type == proto.RoleIn {
				h.seqMu.Lock()
				dup := h.lastSeq[c.key] == rep.Seq
				h.seqMu.Unlock()
				if !dup {
					if err := h.ingest(g.ID, &rep); err != nil {
						log.Printf("[hub] 流量入库失败: %v", err)
						continue // 不确认,节点稍后会重发
					}
					h.seqMu.Lock()
					h.lastSeq[c.key] = rep.Seq
					h.seqMu.Unlock()
				}
			}
			c.trySend(proto.Pack(proto.TAck, proto.Ack{Seq: rep.Seq}))
		case proto.TStatus:
			var st proto.Status
			if json.Unmarshal(m.D, &st) != nil {
				continue
			}
			c.mu.Lock()
			c.ruleErrors = st.RuleErrors
			c.mu.Unlock()
			if g.Type == proto.RoleOut && st.TunnelPort > 0 {
				res, _ := h.s.db.Exec(`UPDATE nodes SET tunnel_port=? WHERE id=? AND tunnel_port<>?`, st.TunnelPort, c.nodeID, st.TunnelPort)
				if res != nil {
					if n, _ := res.RowsAffected(); n > 0 {
						h.Dirty()
					}
				}
			}
		case proto.TDiagResult:
			var dr proto.DiagResult
			if json.Unmarshal(m.D, &dr) == nil {
				h.diagMu.Lock()
				ch := h.diagWait[dr.ID]
				h.diagMu.Unlock()
				if ch != nil {
					select {
					case ch <- dr:
					default:
					}
				}
			}
		}
	}
}

// ingest 把一次流量上报入库:规则流量、用户已用流量(按倍率)、设备组流量、小时统计。
// 计费口径:用户扣除 = 实际流量 ×(入口倍率 + 出口倍率),直出只计入口倍率;
// 链式出口取链式出口自己的倍率,不累加途经各出口组的倍率。
func (h *Hub) ingest(inGroupID int64, rep *proto.Report) error {
	if len(rep.Items) == 0 {
		return nil
	}
	db := h.s.db
	ratios := map[int64]float64{}
	chainHops := map[int64][]int64{}
	rows, err := db.Query(`SELECT id, ratio, type, config FROM device_groups`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var r float64
		var typ, cfg string
		rows.Scan(&id, &r, &typ, &cfg)
		ratios[id] = r
		if typ == proto.RoleChain {
			var c struct {
				ChainHops []int64 `json:"chain_hops"`
			}
			json.Unmarshal([]byte(cfg), &c)
			chainHops[id] = c.ChainHops
		}
	}
	rows.Close()

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	hour := now() / 3600 * 3600
	crossed := false
	for _, it := range rep.Items {
		if it.Up < 0 || it.Down < 0 || it.Up+it.Down == 0 {
			continue
		}
		var uid, outGroup int64
		err := tx.QueryRow(`UPDATE rules SET traffic_up=traffic_up+?, traffic_down=traffic_down+? WHERE id=? AND in_group=?
			RETURNING user_id, out_group`, it.Up, it.Down, it.RuleID, inGroupID).Scan(&uid, &outGroup)
		if err != nil {
			continue // 规则已删除
		}
		raw := it.Up + it.Down
		ratio := ratios[inGroupID]
		if outGroup != 0 {
			ratio += ratios[outGroup]
		}
		billed := int64(float64(raw) * ratio)
		var used, quota int64
		var role string
		if err := tx.QueryRow(`UPDATE users SET traffic_used=traffic_used+? WHERE id=? RETURNING traffic_used, traffic_quota, role`,
			billed, uid).Scan(&used, &quota, &role); err == nil {
			if role != "admin" && used >= quota && used-billed < quota {
				crossed = true
			}
		}
		if _, err := tx.Exec(`INSERT INTO traffic_hourly(user_id,hour,up,down,billed) VALUES(?,?,?,?,?)
			ON CONFLICT(user_id,hour) DO UPDATE SET up=up+excluded.up, down=down+excluded.down, billed=billed+excluded.billed`,
			uid, hour, it.Up, it.Down, billed); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE device_groups SET traffic=traffic+? WHERE id=? OR (id=? AND ?<>0)`,
			raw, inGroupID, outGroup, outGroup); err != nil {
			return err
		}
		// 链式出口:途经的每个出口组也记上这笔流量(只影响设备组的累计流量,不影响用户计费)
		for _, hid := range chainHops[outGroup] {
			if _, err := tx.Exec(`UPDATE device_groups SET traffic=traffic+? WHERE id=?`, raw, hid); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if crossed {
		h.Dirty() // 有用户流量用尽:停掉其规则
	}
	return nil
}

// ---- 查询 ----

// NodeStatus 是节点的实时状态。
type NodeStatus struct {
	Online  bool           `json:"online"`
	Since   int64          `json:"since,omitempty"`
	Metrics *proto.Metrics `json:"metrics,omitempty"`
	Error   string         `json:"error,omitempty"` // 出口节点应用配置失败的原因(如隧道端口被占用)
}

func (h *Hub) status(groupID int64, uid string) NodeStatus {
	h.mu.RLock()
	c := h.conns[fmt.Sprintf("%d/%s", groupID, uid)]
	h.mu.RUnlock()
	if c == nil {
		return NodeStatus{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st := NodeStatus{Online: true, Since: c.since, Error: c.ruleErrors[0]}
	if c.metrics != nil && now()-c.metricsAt <= nodeOfflineSecs {
		st.Metrics = c.metrics
	}
	return st
}

// onlineCount 返回各设备组的在线节点数。
func (h *Hub) onlineCount() map[int64]int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := map[int64]int{}
	for _, c := range h.conns {
		out[c.groupID]++
	}
	return out
}

// ruleErrors 汇总各节点上规则没能生效的原因:节点上报的启动失败,以及因节点端版本过旧而没有下发的规则。
func (h *Hub) ruleErrors() map[int64]string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := map[int64]string{}
	for _, c := range h.conns {
		c.mu.Lock()
		for id, e := range c.skipped {
			out[id] = c.hello.Hostname + ": " + e
		}
		for id, e := range c.ruleErrors {
			if id != 0 {
				out[id] = c.hello.Hostname + ": " + e
			}
		}
		c.mu.Unlock()
	}
	return out
}

// kickGroup 断开某个设备组的全部节点(组被删除或令牌重置)。
func (h *Hub) kickGroup(groupID int64) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, c := range h.conns {
		if c.groupID == groupID {
			c.ws.Close()
		}
	}
}

// diag 让规则涉及的在线节点各自测量到下一跳的建连耗时。
func (h *Hub) diag(r *Rule) []proto.DiagHop {
	fail := func(msg string) []proto.DiagHop { return []proto.DiagHop{{From: "面板", To: "-", Error: msg}} }
	_, groups, err := h.loadGroups()
	if err != nil {
		return fail("读取设备组失败")
	}
	// 规则经过的设备组,按先后顺序:入口,然后是各个出口
	path := []int64{r.InGroup}
	if r.TLSMode != proto.TLSModeParent {
		hops, _, ok := groups.hops(r.OutGroup)
		if !ok {
			return fail("规则选择的出口已不存在,或链式出口的配置不完整")
		}
		for _, hg := range hops {
			path = append(path, hg.ID)
		}
	}
	pos := make(map[int64]int, len(path))
	for i, gid := range path {
		pos[gid] = i
	}

	h.mu.RLock()
	picked := map[int64]int{}
	var targets []*nodeConn
	for _, c := range h.conns {
		if _, ok := pos[c.groupID]; ok && picked[c.groupID] < 3 { // 每个组最多问 3 台机器
			picked[c.groupID]++
			targets = append(targets, c)
		}
	}
	h.mu.RUnlock()

	// 每个位置一个诊断号,节点原样带回,据此把结果放回路径上对应的位置
	base := randHex(8)
	ch := make(chan proto.DiagResult, len(targets)+1)
	ids := make([]string, len(path))
	h.diagMu.Lock()
	for i := range path {
		ids[i] = fmt.Sprintf("%s.%d", base, i)
		h.diagWait[ids[i]] = ch
	}
	h.diagMu.Unlock()
	defer func() {
		h.diagMu.Lock()
		for _, id := range ids {
			delete(h.diagWait, id)
		}
		h.diagMu.Unlock()
	}()
	for _, c := range targets {
		c.trySend(proto.Pack(proto.TDiag, proto.Diag{ID: ids[pos[c.groupID]], RuleID: r.ID}))
	}

	results := make([][]proto.DiagHop, len(path))
	timedOut := false
	timeout := time.After(6 * time.Second)
wait:
	for range targets {
		select {
		case res := <-ch:
			var p int
			if _, err := fmt.Sscanf(strings.TrimPrefix(res.ID, base+"."), "%d", &p); err == nil && p >= 0 && p < len(path) {
				results[p] = append(results[p], res.Hops...)
			}
		case <-timeout:
			timedOut = true
			break wait
		}
	}
	var out []proto.DiagHop
	for i, gid := range path {
		if picked[gid] == 0 {
			name := fmt.Sprintf("设备组 #%d", gid)
			if g := groups[gid]; g != nil {
				name = g.Name
			}
			out = append(out, proto.DiagHop{From: name, To: "-", Error: "这个设备组没有在线节点"})
			continue
		}
		sort.SliceStable(results[i], func(a, b int) bool {
			x, y := results[i][a], results[i][b]
			return x.From < y.From || (x.From == y.From && x.To < y.To)
		})
		out = append(out, results[i]...)
	}
	if timedOut {
		out = append(out, proto.DiagHop{From: "面板", To: "-", Error: "部分节点诊断超时"})
	}
	return out
}

// ruleOffline 检查规则经过的入口组和各出口组是否都有在线节点;有缺口时返回说明,否则返回空串。
func ruleOffline(r *Rule, groups groupSet, online map[int64]int) string {
	if online[r.InGroup] == 0 {
		return "入口组没有在线节点"
	}
	if r.TLSMode == proto.TLSModeParent {
		return ""
	}
	hops, chain, ok := groups.hops(r.OutGroup)
	if !ok {
		return "规则选择的出口已不存在,或链式出口的配置不完整"
	}
	for i, hg := range hops {
		if online[hg.ID] == 0 {
			if chain != nil {
				return fmt.Sprintf("链式出口的第 %d 跳没有在线节点", i+1)
			}
			return "出口组没有在线节点"
		}
	}
	return ""
}
