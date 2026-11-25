package panel

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
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
	ruleErrors map[int64]string
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
	body, _ := json.Marshal(struct {
		I *proto.InboundConfig
		O *proto.OutboundConfig
	}{out.Inbound, out.Outbound})
	sum := sha256.Sum256(body)
	c.mu.Lock()
	same := sum == c.cfgHash
	c.cfgHash = sum
	c.mu.Unlock()
	if same && !force {
		return
	}
	out.Version = h.version.Add(1)
	out.Now = time.Now().UnixMilli()
	c.trySend(proto.Pack(proto.TConfig, &out))
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

func (h *Hub) tunnelSpec(g *Group, withFallback bool, groups map[int64]*Group) *proto.TunnelSpec {
	cfg := &g.Config
	spec := &proto.TunnelSpec{
		GroupID: g.ID, Endpoints: h.endpoints(g), Transport: cfg.Transport, Mux: cfg.Mux, MuxConns: cfg.MuxConns,
		Key: cfg.TunnelKey, SNI: cfg.SNI, Host: cfg.WSHost, Path: cfg.WSPath, UDPOverTCP: cfg.UDPOverTCP,
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
	case cfg.Transport == tunnel.TransportTLS || cfg.Transport == tunnel.TransportWSS:
		spec.CertPin = cfg.CertPin
	}
	if withFallback && cfg.FailoverGroup != 0 && cfg.FailoverGroup != g.ID {
		if fb := groups[cfg.FailoverGroup]; fb != nil && fb.Type == proto.RoleOut {
			spec.Fallback = h.tunnelSpec(fb, false, groups)
		}
	}
	return spec
}

func (h *Hub) buildConfig(groupID int64) (*proto.NodeConfig, error) {
	db := h.s.db
	all, err := listGroups(db)
	if err != nil {
		return nil, err
	}
	groups := make(map[int64]*Group, len(all))
	for _, g := range all {
		groups[g.ID] = g
	}
	g := groups[groupID]
	if g == nil {
		return nil, fmt.Errorf("设备组不存在")
	}
	cfg := &proto.NodeConfig{Role: g.Type, GroupID: g.ID, ReportInterval: reportInterval}
	gc := &g.Config

	if g.Type == proto.RoleIn {
		in := &proto.InboundConfig{
			Rules: []proto.Rule{}, Users: map[int64]proto.UserLimit{}, Tunnels: map[int64]*proto.TunnelSpec{},
			BlockedProtocols: gc.BlockedProtocols, BlockedHosts: gc.BlockedHosts, AllowedHosts: gc.AllowedHosts,
			AllowPrivate: gc.AllowPrivate, DisableUDP: gc.DisableUDP, MaxFail: gc.MaxFail, FailTimeout: gc.FailTimeout,
		}
		rows, err := db.Query(`SELECT `+ruleCols+`,u.speed_limit,u.conn_limit,u.ip_limit FROM rules r
			JOIN users u ON u.id=r.user_id WHERE r.in_group=? AND r.paused=0 AND `+activeUserSQL+` ORDER BY r.id`, groupID, now())
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
				ID: r.ID, UserID: r.UserID, ListenPort: r.ListenPort, Proto: r.Proto, OutGroup: r.OutGroup,
				LB: r.LB, SpeedLimit: mbps(r.SpeedLimit), ConnLimit: r.ConnLimit, IPLimit: r.IPLimit,
			}
			if r.OutGroup == 0 {
				pr.Targets, pr.ProxyProtocol = r.Targets, r.ProxyProtocol
			} else {
				og := groups[r.OutGroup]
				if og == nil || og.Type != proto.RoleOut {
					continue
				}
				if in.Tunnels[og.ID] == nil {
					in.Tunnels[og.ID] = h.tunnelSpec(og, true, groups)
				}
			}
			in.Rules = append(in.Rules, pr)
			if us != 0 || uc != 0 || ui != 0 {
				in.Users[r.UserID] = proto.UserLimit{SpeedLimit: mbps(us), ConnLimit: uc, IPLimit: ui}
			}
		}
		cfg.Inbound = in
		return cfg, rows.Err()
	}

	// 出口:本组的规则 + 以本组为故障转移组的出口组的规则
	ids := []any{groupID}
	ph := "?"
	for _, og := range all {
		if og.Type == proto.RoleOut && og.ID != groupID && og.Config.FailoverGroup == groupID {
			ids = append(ids, og.ID)
			ph += ",?"
		}
	}
	out := &proto.OutboundConfig{
		ListenPort: gc.TunnelPort, Transport: gc.Transport, Key: gc.TunnelKey, Path: gc.WSPath,
		Rules: []proto.OutRule{}, AllowPrivate: gc.AllowPrivate, MaxFail: gc.MaxFail, FailTimeout: gc.FailTimeout,
	}
	switch {
	case gc.CDN:
		out.Transport = tunnel.TransportWS // CDN 回源走明文 ws,TLS 由 CDN 终结
	case gc.Transport == tunnel.TransportTLS || gc.Transport == tunnel.TransportWSS:
		out.CertPEM, out.KeyPEM = gc.CertPEM, gc.KeyPEM
	}
	rows, err := db.Query(`SELECT `+ruleCols+` FROM rules r JOIN users u ON u.id=r.user_id
		WHERE r.out_group IN (`+ph+`) AND r.paused=0 AND `+activeUserSQL+` ORDER BY r.id`, append(ids, now())...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out.Rules = append(out.Rules, proto.OutRule{ID: r.ID, Targets: r.Targets, LB: r.LB, ProxyProtocol: r.ProxyProtocol})
	}
	cfg.Outbound = out
	return cfg, rows.Err()
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
	if err != nil {
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
	if _, err := h.s.db.Exec(`INSERT INTO nodes(group_id,uid,hostname,ip,version,os,arch,connect_host,tunnel_port,first_seen,last_seen)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(group_id,uid) DO UPDATE SET hostname=excluded.hostname, ip=excluded.ip, version=excluded.version,
		os=excluded.os, arch=excluded.arch, connect_host=excluded.connect_host, last_seen=excluded.last_seen`,
		g.ID, hello.UID, hello.Hostname, ip, hello.Version, hello.OS, hello.Arch, hello.ConnectHost, 0, t, t); err != nil {
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
	if g.Type == proto.RoleOut {
		h.Dirty() // 出口节点上线:入口的连接地址列表可能变化
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
// 计费口径:用户扣除 = 实际流量 ×(入口倍率 + 出口倍率),直出只计入口倍率。
func (h *Hub) ingest(inGroupID int64, rep *proto.Report) error {
	if len(rep.Items) == 0 {
		return nil
	}
	db := h.s.db
	ratios := map[int64]float64{}
	rows, err := db.Query(`SELECT id, ratio FROM device_groups`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var r float64
		rows.Scan(&id, &r)
		ratios[id] = r
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

// ruleErrors 汇总各入口节点上报的规则同步错误。
func (h *Hub) ruleErrors() map[int64]string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := map[int64]string{}
	for _, c := range h.conns {
		c.mu.Lock()
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
	h.mu.RLock()
	var targets []*nodeConn
	for _, c := range h.conns {
		if c.groupID == r.InGroup || (r.OutGroup != 0 && c.groupID == r.OutGroup) {
			targets = append(targets, c)
		}
	}
	h.mu.RUnlock()
	if len(targets) > 8 {
		targets = targets[:8]
	}
	id := randHex(8)
	ch := make(chan proto.DiagResult, len(targets)+1)
	h.diagMu.Lock()
	h.diagWait[id] = ch
	h.diagMu.Unlock()
	defer func() {
		h.diagMu.Lock()
		delete(h.diagWait, id)
		h.diagMu.Unlock()
	}()
	hasIn := false
	for _, c := range targets {
		if c.groupID == r.InGroup {
			hasIn = true
		}
		c.trySend(proto.Pack(proto.TDiag, proto.Diag{ID: id, RuleID: r.ID}))
	}
	var hops []proto.DiagHop
	if !hasIn {
		hops = append(hops, proto.DiagHop{From: "入口", To: "-", Error: "入口组没有在线节点"})
	}
	timeout := time.After(6 * time.Second)
	for i := 0; i < len(targets); i++ {
		select {
		case res := <-ch:
			hops = append(hops, res.Hops...)
		case <-timeout:
			return append(hops, proto.DiagHop{From: "面板", To: "-", Error: "部分节点诊断超时"})
		}
	}
	return hops
}
