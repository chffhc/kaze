package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"kaze/internal/proto"
	"kaze/internal/relay"
	"kaze/internal/tunnel"
)

// ---- 仪表盘 ----

type trafficPoint struct {
	T      int64 `json:"t"`
	Up     int64 `json:"up"`
	Down   int64 `json:"down"`
	Billed int64 `json:"billed"`
}

// trafficSeries 返回最近 24 小时(按小时)与最近 30 天(按天)的流量序列;userID=0 表示全站。
func (s *Server) trafficSeries(userID int64) (hourly, daily []trafficPoint, err error) {
	nowT := time.Now()
	since := nowT.AddDate(0, 0, -29)
	dayStart := time.Date(since.Year(), since.Month(), since.Day(), 0, 0, 0, 0, time.Local)
	q := `SELECT hour, SUM(up), SUM(down), SUM(billed) FROM traffic_hourly WHERE hour>=?`
	args := []any{dayStart.Unix() - 3600}
	if userID != 0 {
		q += ` AND user_id=?`
		args = append(args, userID)
	}
	rows, err := s.db.Query(q+` GROUP BY hour ORDER BY hour`, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	hourIdx, dayIdx := map[int64]int{}, map[int64]int{}
	h0 := nowT.Unix()/3600*3600 - 23*3600
	for i := 0; i < 24; i++ {
		t := h0 + int64(i)*3600
		hourIdx[t] = i
		hourly = append(hourly, trafficPoint{T: t})
	}
	for i := 0; i < 30; i++ {
		t := dayStart.AddDate(0, 0, i).Unix()
		dayIdx[t] = i
		daily = append(daily, trafficPoint{T: t})
	}
	for rows.Next() {
		var p trafficPoint
		if err := rows.Scan(&p.T, &p.Up, &p.Down, &p.Billed); err != nil {
			return nil, nil, err
		}
		if i, ok := hourIdx[p.T]; ok {
			hourly[i].Up, hourly[i].Down, hourly[i].Billed = p.Up, p.Down, p.Billed
		}
		lt := time.Unix(p.T, 0).In(time.Local)
		d := time.Date(lt.Year(), lt.Month(), lt.Day(), 0, 0, 0, 0, time.Local).Unix()
		if i, ok := dayIdx[d]; ok {
			daily[i].Up += p.Up
			daily[i].Down += p.Down
			daily[i].Billed += p.Billed
		}
	}
	return hourly, daily, rows.Err()
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request, u *User) {
	hourly, daily, err := s.trafficSeries(u.ID)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	s.ok(w, H{
		"user": u, "hourly": hourly, "daily": daily,
		"announcement": s.setting("announcement", ""),
	})
}

// ---- 设备组(用户视角)----

type tlsPortView struct {
	Port int    `json:"port"`
	Name string `json:"name"`
}

type groupView struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Ratio       float64  `json:"ratio"`
	Note        string   `json:"note"`
	Hosts       []string `json:"hosts"` // 入口地址
	PortRange   string   `json:"port_range,omitempty"`
	DirectMode  int      `json:"direct_mode"`
	AllowedOut  []int64  `json:"allowed_out"`
	DisableUDP  bool     `json:"disable_udp"`
	Blocked     []string `json:"blocked,omitempty"`
	Transport   string   `json:"transport,omitempty"`
	Online      int      `json:"online"`
	NodeCount   int      `json:"node_count"`
	TrafficUsed int64    `json:"traffic,omitempty"`

	// 入口组的 TLS 入站
	TLSPolicy    int           `json:"tls_policy"`              // 0 不限制 / 1 只允许 TLS 入站 / 2 只允许子规则
	TLSPorts     []tlsPortView `json:"tls_ports"`               // 可以挂子规则的共享 TLS 端口
	AllowedHosts []string      `json:"allowed_hosts,omitempty"` // 域名白名单(SNI 后缀)
	BlockedHosts []string      `json:"blocked_hosts,omitempty"` // 域名黑名单
	// 链式出口
	ChainHops int `json:"chain_hops,omitempty"` // 跳数
}

// accessibleFrom 从全部设备组里筛出用户可用的:公开组 + 套餐额外授权的组;管理员可用全部。
func (s *Server) accessibleFrom(q dbq, all []*Group, u *User) []*Group {
	if u.IsAdmin() {
		return all
	}
	allowed := map[int64]bool{}
	if u.PlanID != 0 {
		if p, err := getPlan(q, u.PlanID); err == nil {
			for _, id := range p.Groups {
				allowed[id] = true
			}
		}
	}
	var out []*Group
	for _, g := range all {
		if g.Public || allowed[g.ID] {
			out = append(out, g)
		}
	}
	return out
}

func (s *Server) accessibleGroups(u *User) ([]*Group, error) {
	all, err := listGroups(s.db)
	if err != nil {
		return nil, err
	}
	return s.accessibleFrom(s.db, all, u), nil
}

func toGroupSet(all []*Group) groupSet {
	gs := make(groupSet, len(all))
	for _, g := range all {
		gs[g.ID] = g
	}
	return gs
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request, u *User) {
	all, err := listGroups(s.db)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	gs := toGroupSet(all)
	nodes, err := listNodes(s.db, "")
	if err != nil {
		s.dbErr(w, err)
		return
	}
	// 各入口组里的母规则 = 可供子规则挂载的共享 TLS 端口(暂停中的也列出,否则编辑挂在它下面的子规则时选不到原来的端口)
	tlsPorts := map[int64][]tlsPortView{}
	rows, err := s.db.Query(`SELECT in_group, listen_port, name || (CASE WHEN paused=1 THEN ',已暂停' ELSE '' END) FROM rules WHERE tls_mode='parent' ORDER BY listen_port`)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	for rows.Next() {
		var gid int64
		var v tlsPortView
		rows.Scan(&gid, &v.Port, &v.Name)
		tlsPorts[gid] = append(tlsPorts[gid], v)
	}
	rows.Close()

	online := s.hub.onlineCount()
	out := []groupView{}
	for _, g := range s.accessibleFrom(s.db, all, u) {
		v := groupView{
			ID: g.ID, Name: g.Name, Type: g.Type, Ratio: g.Ratio, Note: g.Note, Online: online[g.ID],
			AllowedOut: g.Config.AllowedOut, Hosts: []string{}, TLSPorts: []tlsPortView{},
		}
		for _, n := range nodes {
			if n.GroupID == g.ID {
				v.NodeCount++
				if g.Type == proto.RoleIn && g.Config.DisplayHost == "" && n.IP != "" {
					v.Hosts = append(v.Hosts, n.IP)
				}
			}
		}
		switch g.Type {
		case proto.RoleIn:
			if g.Config.DisplayHost != "" {
				for _, h := range strings.Split(g.Config.DisplayHost, ",") {
					if h = strings.TrimSpace(h); h != "" {
						v.Hosts = append(v.Hosts, h)
					}
				}
			}
			v.PortRange, v.DirectMode, v.DisableUDP = g.Config.PortRange, g.Config.DirectMode, g.Config.DisableUDP
			v.Blocked = g.Config.BlockedProtocols
			v.TLSPolicy, v.AllowedHosts, v.BlockedHosts = g.Config.TLSInboundPolicy, g.Config.AllowedHosts, g.Config.BlockedHosts
			if ps := tlsPorts[g.ID]; ps != nil {
				v.TLSPorts = ps
			}
		case proto.RoleOut:
			v.Transport = g.Config.Transport
			if g.Config.CDN {
				v.Transport = "ws (CDN)"
			}
		case proto.RoleChain:
			hops, _, ok := gs.hops(g.ID)
			if !ok {
				continue // 链路不完整(途经的出口组被删了):不展示给用户
			}
			v.ChainHops, v.Transport = len(hops), fmt.Sprintf("链式 %d 跳", len(hops))
			// 在线数取各跳里最少的:任何一跳没有在线节点,整条链就不通
			v.Online = online[hops[0].ID]
			for _, hg := range hops[1:] {
				v.Online = min(v.Online, online[hg.ID])
			}
		}
		if u.IsAdmin() {
			v.TrafficUsed = g.Traffic
		}
		out = append(out, v)
	}
	s.ok(w, out)
}

// handleNodeStatus 是探针页:用户能看到可用设备组里每台机器的在线状态与负载。
func (s *Server) handleNodeStatus(w http.ResponseWriter, r *http.Request, u *User) {
	groups, err := s.accessibleGroups(u)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	nodes, err := listNodes(s.db, `WHERE last_seen>?`, now()-nodeRetention)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	type nodeView struct {
		ID       int64  `json:"id"`
		Hostname string `json:"hostname"`
		IP       string `json:"ip,omitempty"`
		Version  string `json:"version"`
		LastSeen int64  `json:"last_seen"`
		NodeStatus
	}
	type groupStatus struct {
		ID    int64      `json:"id"`
		Name  string     `json:"name"`
		Type  string     `json:"type"`
		Nodes []nodeView `json:"nodes"`
	}
	out := []groupStatus{}
	for _, g := range groups {
		if g.Type == proto.RoleChain { // 链式出口没有自己的机器
			continue
		}
		gs := groupStatus{ID: g.ID, Name: g.Name, Type: g.Type, Nodes: []nodeView{}}
		for _, n := range nodes {
			if n.GroupID != g.ID {
				continue
			}
			v := nodeView{ID: n.ID, Hostname: n.Hostname, Version: n.Version, LastSeen: n.LastSeen, NodeStatus: s.hub.status(g.ID, n.UID)}
			if u.IsAdmin() {
				v.IP = n.IP
			} else {
				v.Error = ""
			}
			gs.Nodes = append(gs.Nodes, v)
		}
		out = append(out, gs)
	}
	s.ok(w, out)
}

// ---- 转发规则 ----

type ruleInput struct {
	UserID        int64    `json:"user_id"` // 仅管理员可指定
	Name          string   `json:"name"`
	InGroup       int64    `json:"in_group"`
	OutGroup      int64    `json:"out_group"`
	ListenPort    int      `json:"listen_port"` // 0 = 自动分配;子规则填共享 TLS 端口
	Proto         string   `json:"proto"`
	Targets       []string `json:"targets"`
	LB            string   `json:"lb"`
	ProxyProtocol int      `json:"proxy_protocol"`
	SpeedLimit    int      `json:"speed_limit"`
	ConnLimit     int      `json:"conn_limit"`
	IPLimit       int      `json:"ip_limit"`
	TLSMode       string   `json:"tls_mode"`
	TLS           RuleTLS  `json:"tls"`
}

var hostRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9_.-]{0,251}[a-zA-Z0-9])?$`)

func normalizeTarget(t string) (string, error) {
	t = strings.TrimSpace(t)
	host, port, err := net.SplitHostPort(t)
	if err != nil {
		return "", fmt.Errorf("目标地址格式应为 主机:端口: %s", t)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", fmt.Errorf("目标端口无效: %s", t)
	}
	if net.ParseIP(host) == nil && !hostRe.MatchString(host) {
		return "", fmt.Errorf("目标主机无效: %s", t)
	}
	return net.JoinHostPort(host, strconv.Itoa(p)), nil
}

func containsID(list []int64, id int64) bool {
	for _, x := range list {
		if x == id {
			return true
		}
	}
	return false
}

// normalizeSNI 规范化一组 SNI:转小写、去重,只接受完整的域名(SNI 里不会出现 IP,也不支持通配符)。
func normalizeSNI(in []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, x := range in {
		x = strings.ToLower(strings.TrimSpace(x))
		if x == "" || seen[x] {
			continue
		}
		if !hostRe.MatchString(x) || !strings.Contains(x, ".") || net.ParseIP(x) != nil {
			return nil, fmt.Errorf("SNI 需要是完整的域名: %s", x)
		}
		seen[x] = true
		out = append(out, x)
	}
	if len(out) > 16 {
		return nil, errors.New("每条规则最多 16 个 SNI")
	}
	return out, nil
}

var alpnRe = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,32}$`)

func normalizeALPN(in []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, x := range in {
		if x = strings.TrimSpace(x); x == "" || seen[x] {
			continue
		}
		if !alpnRe.MatchString(x) {
			return nil, fmt.Errorf("ALPN 无效: %s", x)
		}
		seen[x] = true
		out = append(out, x)
	}
	if len(out) > 8 {
		return nil, errors.New("最多 8 个 ALPN")
	}
	return out, nil
}

func suffixMatch(host string, list []string) bool {
	for _, sfx := range list {
		if sfx = strings.ToLower(strings.TrimSpace(sfx)); sfx != "" && strings.HasSuffix(host, sfx) {
			return true
		}
	}
	return false
}

// prepareTLS 校验并规范化规则的 TLS 入站设置。old 为编辑时的原规则(用于沿用已保存的私钥)。
func prepareTLS(r *Rule, in *RuleTLS, ig *Group, old *Rule) error {
	var err error
	t := RuleTLS{SNI: []string{}, ALPN: []string{}}
	if r.TLSMode != proto.TLSModeParent {
		if t.SNI, err = normalizeSNI(in.SNI); err != nil {
			return err
		}
		if t.ALPN, err = normalizeALPN(in.ALPN); err != nil {
			return err
		}
		if r.TLSMode == proto.TLSModeChild && len(t.SNI) == 0 {
			return errors.New("子规则至少需要一个 SNI,入口靠它把连接分给这条规则")
		}
		for _, name := range t.SNI {
			if len(ig.Config.AllowedHosts) > 0 && !suffixMatch(name, ig.Config.AllowedHosts) {
				return fmt.Errorf("SNI %s 不在该入口组的域名白名单内(允许的后缀: %s)", name, strings.Join(ig.Config.AllowedHosts, " "))
			}
			if suffixMatch(name, ig.Config.BlockedHosts) {
				return fmt.Errorf("SNI %s 在该入口组的域名黑名单内", name)
			}
		}
		if t.OriginTLS = in.OriginTLS; t.OriginTLS {
			t.OriginVerify = in.OriginVerify
			if t.OriginSNI = strings.ToLower(strings.TrimSpace(in.OriginSNI)); t.OriginSNI != "" && !hostRe.MatchString(t.OriginSNI) {
				return errors.New("回源 SNI 无效")
			}
		}
	}
	cert, key := strings.TrimSpace(in.CertPEM), strings.TrimSpace(in.KeyPEM)
	switch {
	case cert == "" && key == "":
	case len(cert) > 64<<10 || len(key) > 16<<10:
		return errors.New("证书或私钥过大")
	case key == "":
		// 接口不返回私钥:编辑时证书没变就沿用已保存的私钥
		if old == nil || strings.TrimSpace(old.TLS.CertPEM) != cert || old.TLS.KeyPEM == "" {
			return errors.New("请同时填写证书对应的私钥")
		}
		t.CertPEM, t.KeyPEM = old.TLS.CertPEM, old.TLS.KeyPEM
	default:
		if _, err := tunnel.ParseCert(cert, key); err != nil {
			return fmt.Errorf("证书与私钥不匹配或格式有误: %v", err)
		}
		t.CertPEM, t.KeyPEM = cert, key
	}
	r.TLS = t
	return nil
}

// prepareRule 校验输入并补全默认值。owner 是规则归属用户,old 为编辑时的原规则。
func (policy *rulePolicy) prepareRule(q dbq, actor, owner *User, in *ruleInput, old *Rule) (*Rule, error) {
	r := &Rule{
		UserID: owner.ID, Name: strings.TrimSpace(in.Name), InGroup: in.InGroup, OutGroup: in.OutGroup,
		ListenPort: in.ListenPort, Proto: in.Proto, LB: in.LB, ProxyProtocol: in.ProxyProtocol,
		SpeedLimit: max(in.SpeedLimit, 0), ConnLimit: max(in.ConnLimit, 0), IPLimit: max(in.IPLimit, 0),
		TLSMode: in.TLSMode, Targets: []string{}, TLS: RuleTLS{SNI: []string{}, ALPN: []string{}},
	}
	if len([]rune(r.Name)) > 64 {
		return nil, errors.New("规则名称过长")
	}
	switch r.TLSMode {
	case "", proto.TLSModeAlone, proto.TLSModeParent, proto.TLSModeChild:
	default:
		return nil, errors.New("TLS 入站模式只能是 tls / parent / child")
	}
	isTLS, isParent, isChild := r.TLSMode != "", r.TLSMode == proto.TLSModeParent, r.TLSMode == proto.TLSModeChild
	switch {
	case isTLS:
		r.Proto = "tcp" // TLS 只跑在 TCP 上
	case r.Proto == "":
		r.Proto = "tcp+udp"
	case r.Proto != "tcp" && r.Proto != "udp" && r.Proto != "tcp+udp":
		return nil, errors.New("协议只能是 tcp / udp / tcp+udp")
	}
	switch r.LB {
	case "":
		r.LB = relay.LBRoundRobin
	case relay.LBRoundRobin, relay.LBRandom, relay.LBLeastConn, relay.LBIPHash, relay.LBFailover:
	default:
		return nil, errors.New("负载均衡策略无效")
	}
	if r.ProxyProtocol < 0 || r.ProxyProtocol > 2 {
		return nil, errors.New("PROXY protocol 版本只能是 0 / 1 / 2")
	}
	if isParent {
		// 母规则只负责监听端口、终结 TLS 并按 SNI 分流,自己不转发
		if !actor.IsAdmin() {
			return nil, errors.New("共享 TLS 端口(母规则)只能由管理员创建")
		}
		r.OutGroup, r.ProxyProtocol = 0, 0
	} else {
		if len(in.Targets) == 0 || len(in.Targets) > 16 {
			return nil, errors.New("需要 1-16 个转发目标")
		}
		for _, t := range in.Targets {
			nt, err := normalizeTarget(t)
			if err != nil {
				return nil, err
			}
			r.Targets = append(r.Targets, nt)
		}
	}

	ig := policy.groups[r.InGroup]
	if ig == nil {
		return nil, errors.New("入口组不存在")
	}
	if isTLS {
		if err := prepareTLS(r, &in.TLS, ig, old); err != nil {
			return nil, err
		}
	}

	// 端口
	if err := policy.authorize(owner, r); err != nil {
		return nil, err
	}
	if isChild {
		// 子规则不占端口:它挂在一个共享 TLS 端口(母规则)上,靠 SNI 区分
		if r.ListenPort == 0 && old != nil && old.TLSMode == proto.TLSModeChild && old.InGroup == r.InGroup {
			r.ListenPort = old.ListenPort
		}
		ports, err := queryInts(q, `SELECT listen_port FROM rules WHERE in_group=? AND tls_mode='parent' ORDER BY listen_port`, r.InGroup)
		if err != nil {
			return nil, err
		}
		switch {
		case len(ports) == 0:
			return nil, errors.New("该入口组还没有共享 TLS 端口,请联系管理员创建")
		case r.ListenPort == 0 && len(ports) == 1:
			r.ListenPort = ports[0]
		case r.ListenPort == 0:
			return nil, errors.New("请选择要挂载的共享 TLS 端口")
		case !containsInt(ports, r.ListenPort):
			return nil, fmt.Errorf("端口 %d 不是该入口组的共享 TLS 端口", r.ListenPort)
		}
		// 同一个端口下,一个 SNI 只能属于一条子规则
		rows, err := q.Query(`SELECT id, tls_config FROM rules WHERE in_group=? AND listen_port=? AND tls_mode='child'`, r.InGroup, r.ListenPort)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var id int64
			var cfg string
			if err := rows.Scan(&id, &cfg); err != nil {
				return nil, err
			}
			if old != nil && id == old.ID {
				continue
			}
			var other RuleTLS
			json.Unmarshal([]byte(cfg), &other)
			for _, name := range r.TLS.SNI {
				if containsStr(other.SNI, name) {
					return nil, fmt.Errorf("SNI %s 已被端口 %d 下的另一条规则使用", name, r.ListenPort)
				}
			}
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if r.Name == "" {
			r.Name = r.TLS.SNI[0]
		}
		return r, nil
	}

	ranges := rulePortRanges(ig)
	taken := func(p int) bool {
		var id int64
		err := q.QueryRow(`SELECT id FROM rules WHERE in_group=? AND listen_port=? AND tls_mode<>'child'`, r.InGroup, p).Scan(&id)
		return err == nil && (old == nil || id != old.ID)
	}
	if r.ListenPort == 0 {
		if old != nil && old.InGroup == r.InGroup && old.TLSMode != proto.TLSModeChild {
			r.ListenPort = old.ListenPort
		} else {
			// 在全部可用端口里均匀地随机挑(而不是先挑一段再挑端口,那样像 "443" 这种只有一个端口的段会被频繁选中)
			total := 0
			for _, rg := range ranges {
				total += rg[1] - rg[0] + 1
			}
			for try := 0; try < 200 && r.ListenPort == 0; try++ {
				n := rand.IntN(total)
				for _, rg := range ranges {
					if size := rg[1] - rg[0] + 1; n < size {
						if p := rg[0] + n; !taken(p) {
							r.ListenPort = p
						}
						break
					} else {
						n -= size
					}
				}
			}
			if r.ListenPort == 0 {
				return nil, errors.New("该入口组没有可用端口了")
			}
		}
	} else {
		if r.ListenPort < 1 || r.ListenPort > 65535 {
			return nil, errors.New("监听端口无效")
		}
		if taken(r.ListenPort) {
			return nil, errors.New("该端口已被其他规则占用")
		}
	}
	if err := policy.authorize(owner, r); err != nil {
		return nil, err
	}
	if r.Name == "" {
		if r.Name = fmt.Sprintf("规则-%d", r.ListenPort); isParent {
			r.Name = fmt.Sprintf("共享 TLS 端口 %d", r.ListenPort)
		}
	}
	return r, nil
}

func containsStr(list []string, x string) bool {
	for _, v := range list {
		if v == x {
			return true
		}
	}
	return false
}

func containsInt(list []int, x int) bool {
	for _, v := range list {
		if v == x {
			return true
		}
	}
	return false
}

func queryInts(q dbq, query string, args ...any) ([]int, error) {
	rows, err := q.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Server) insertRule(q dbq, r *Rule) (int64, error) {
	tj, _ := json.Marshal(r.Targets)
	cj, _ := json.Marshal(&r.TLS)
	t := now()
	res, err := q.Exec(`INSERT INTO rules(user_id,name,in_group,out_group,listen_port,proto,targets,lb,proxy_protocol,
		speed_limit,conn_limit,ip_limit,created_at,updated_at,tls_mode,tls_config) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.UserID, r.Name, r.InGroup, r.OutGroup, r.ListenPort, r.Proto, string(tj), r.LB, r.ProxyProtocol,
		r.SpeedLimit, r.ConnLimit, r.IPLimit, t, t, r.TLSMode, string(cj))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ruleOwner 确定新规则归属:管理员可替其他用户创建。
func ruleOwner(q dbq, actor *User, userID int64) (*User, error) {
	if userID == 0 || userID == actor.ID || !actor.IsAdmin() {
		userID = actor.ID
	}
	u, err := getUser(q, userID)
	if err != nil {
		return nil, errors.New("指定的用户不存在")
	}
	return u, nil
}

func (s *Server) checkQuota(owner *User, adding int) error {
	if !owner.Active() {
		return errors.New("账号当前不可用(未购买套餐、已到期或流量用尽),无法创建规则")
	}
	if !owner.IsAdmin() && owner.RuleCount+adding > owner.MaxRules {
		return fmt.Errorf("规则数量已达上限(%d 条)", owner.MaxRules)
	}
	return nil
}

func (s *Server) handleRuleList(w http.ResponseWriter, r *http.Request, u *User) {
	policy, err := loadRulePolicy(s.db)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	// 母规则的状态决定挂在它下面的子规则能不能用
	type parentState struct {
		id     int64
		usable bool
	}
	parents := map[[2]int64]parentState{}
	prow, err := s.db.Query(`SELECT r.id, r.in_group, r.listen_port, (CASE WHEN r.paused=0 AND `+activeUserSQL+` THEN 1 ELSE 0 END)
		FROM rules r JOIN users u ON u.id=r.user_id WHERE r.tls_mode='parent'`, now())
	if err != nil {
		s.dbErr(w, err)
		return
	}
	for prow.Next() {
		var p parentState
		var gid, port int64
		prow.Scan(&p.id, &gid, &port, &p.usable)
		parents[[2]int64{gid, port}] = p
	}
	prow.Close()

	q := `SELECT ` + ruleCols + `, u.username,u.role,u.plan_id, (CASE WHEN ` + activeUserSQL + ` THEN 1 ELSE 0 END) FROM rules r JOIN users u ON u.id=r.user_id`
	args := []any{now()}
	if !(u.IsAdmin() && r.URL.Query().Get("all") == "1") {
		q += ` WHERE r.user_id=?`
		args = append(args, u.ID)
	}
	rows, err := s.db.Query(q+` ORDER BY r.id DESC`, args...)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	defer rows.Close()
	online, errs := s.hub.onlineCount(), s.hub.ruleErrors()
	out := []*Rule{}
	for rows.Next() {
		var active bool
		var username string
		var owner User
		x, err := scanRule(rows, &username, &owner.Role, &owner.PlanID, &active)
		if err != nil {
			s.dbErr(w, err)
			return
		}
		if u.IsAdmin() {
			x.Username = username
		}
		runtimeRule := *x
		policyErr := policy.authorize(&owner, &runtimeRule)
		x.Status = "ok"
		switch {
		case x.Paused:
			x.Status = "paused"
		case !active:
			x.Status, x.Error = "inactive", "账号不可用(到期、流量用尽或被封禁)"
		case policyErr != nil:
			x.Status, x.Error = "inactive", policyErr.Error()
		case errs[x.ID] != "":
			x.Status, x.Error = "error", errs[x.ID]
		default:
			if x.TLSMode == proto.TLSModeChild {
				p, ok := parents[[2]int64{x.InGroup, int64(x.ListenPort)}]
				switch {
				case !ok:
					x.Status, x.Error = "error", fmt.Sprintf("共享 TLS 端口 %d 已被管理员删除", x.ListenPort)
				case !p.usable:
					x.Status, x.Error = "offline", fmt.Sprintf("共享 TLS 端口 %d 已被暂停", x.ListenPort)
				case errs[p.id] != "":
					x.Status, x.Error = "error", fmt.Sprintf("共享 TLS 端口 %d 同步失败: %s", x.ListenPort, errs[p.id])
				}
			}
			if x.Status == "ok" {
				if msg := ruleOffline(x, policy.groups, online); msg != "" {
					x.Status, x.Error = "offline", msg
				}
			}
		}
		out = append(out, x.redact())
	}
	s.ok(w, out)
}

func (s *Server) handleRuleCreate(w http.ResponseWriter, r *http.Request, u *User) {
	var in ruleInput
	if err := bind(r, &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	s.ruleMu.Lock()
	defer s.ruleMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		s.dbErr(w, err)
		return
	}
	defer tx.Rollback()
	owner, err := ruleOwner(tx, u, in.UserID)
	if err == nil {
		err = s.checkQuota(owner, 1)
	}
	if err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	policy, err := loadRulePolicy(tx)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	rule, err := policy.prepareRule(tx, u, owner, &in, nil)
	if err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	id, err := s.insertRule(tx, rule)
	if err != nil {
		s.fail(w, http.StatusConflict, "端口冲突,请重试")
		return
	}
	if err := tx.Commit(); err != nil {
		s.dbErr(w, err)
		return
	}
	s.hub.Dirty()
	rule.ID = id
	s.ok(w, rule.redact())
}

// dirtyRule 标记规则涉及的设备组需要重新下发配置:入口组、途经的每个出口组,
// 以及这些出口组的故障转移组(它们的规则表里也有这条规则,要随时能顶上)。
func (s *Server) dirtyRule(rules ...*Rule) {
	_, groups, err := s.hub.loadGroups()
	if err != nil {
		s.hub.Dirty()
		return
	}
	ids := make([]int64, 0, 4*len(rules))
	for _, r := range rules {
		ids = append(ids, r.InGroup)
		hops, _, ok := groups.hops(r.OutGroup)
		if !ok { // 出口已不存在:保守起见全部重新生成(内容没变的节点不会收到推送)
			s.hub.Dirty()
			return
		}
		for _, hg := range hops {
			ids = append(ids, hg.ID)
			if hg.Config.FailoverGroup != 0 {
				ids = append(ids, hg.Config.FailoverGroup)
			}
		}
	}
	s.hub.Dirty(ids...)
}

// ownedRule 读取规则并检查操作权限。
func (s *Server) ownedRule(w http.ResponseWriter, r *http.Request, u *User) *Rule {
	rule, err := getRule(s.db, pathID(r))
	if err != nil {
		s.dbErr(w, err)
		return nil
	}
	if rule.UserID != u.ID && !u.IsAdmin() {
		s.fail(w, http.StatusForbidden, "无权操作该规则")
		return nil
	}
	return rule
}

// childCount 返回挂在某个共享 TLS 端口下的子规则数。
func childCount(q dbq, inGroup int64, port int) (n int) {
	q.QueryRow(`SELECT COUNT(*) FROM rules WHERE in_group=? AND listen_port=? AND tls_mode='child'`, inGroup, port).Scan(&n)
	return
}

func (s *Server) handleRuleUpdate(w http.ResponseWriter, r *http.Request, u *User) {
	var in ruleInput
	if err := bind(r, &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	s.ruleMu.Lock()
	defer s.ruleMu.Unlock()
	old := s.ownedRule(w, r, u)
	if old == nil {
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		s.dbErr(w, err)
		return
	}
	defer tx.Rollback()
	owner, err := getUser(tx, old.UserID)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	policy, err := loadRulePolicy(tx)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	rule, err := policy.prepareRule(tx, u, owner, &in, old)
	if err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	// 母规则下面挂着子规则时:换端口会带着子规则一起走;换入口组或改成别的模式会让它们失效,不允许
	if old.TLSMode == proto.TLSModeParent {
		if n := childCount(tx, old.InGroup, old.ListenPort); n > 0 {
			if rule.TLSMode != proto.TLSModeParent || rule.InGroup != old.InGroup {
				s.fail(w, 400, fmt.Sprintf("这个共享 TLS 端口下还有 %d 条子规则,不能更换入口组或改成其它类型", n))
				return
			}
			if rule.ListenPort != old.ListenPort {
				if _, err := tx.Exec(`UPDATE rules SET listen_port=?, updated_at=? WHERE in_group=? AND listen_port=? AND tls_mode='child'`,
					rule.ListenPort, now(), old.InGroup, old.ListenPort); err != nil {
					s.dbErr(w, err)
					return
				}
			}
		}
	}
	tj, _ := json.Marshal(rule.Targets)
	cj, _ := json.Marshal(&rule.TLS)
	if _, err := tx.Exec(`UPDATE rules SET name=?,in_group=?,out_group=?,listen_port=?,proto=?,targets=?,lb=?,proxy_protocol=?,
		speed_limit=?,conn_limit=?,ip_limit=?,updated_at=?,tls_mode=?,tls_config=? WHERE id=?`,
		rule.Name, rule.InGroup, rule.OutGroup, rule.ListenPort, rule.Proto, string(tj), rule.LB, rule.ProxyProtocol,
		rule.SpeedLimit, rule.ConnLimit, rule.IPLimit, now(), rule.TLSMode, string(cj), old.ID); err != nil {
		s.fail(w, http.StatusConflict, "端口冲突,请重试")
		return
	}
	if err := tx.Commit(); err != nil {
		s.dbErr(w, err)
		return
	}
	s.dirtyRule(old, rule)
	s.ok(w, H{"ok": true})
}

func (s *Server) handleRuleDelete(w http.ResponseWriter, r *http.Request, u *User) {
	s.ruleMu.Lock()
	defer s.ruleMu.Unlock()
	old := s.ownedRule(w, r, u)
	if old == nil {
		return
	}
	if old.TLSMode == proto.TLSModeParent {
		if n := childCount(s.db, old.InGroup, old.ListenPort); n > 0 {
			s.fail(w, http.StatusConflict, fmt.Sprintf("这个共享 TLS 端口下还有 %d 条子规则,请先删除它们", n))
			return
		}
	}
	if _, err := s.db.Exec(`DELETE FROM rules WHERE id=?`, old.ID); err != nil {
		s.dbErr(w, err)
		return
	}
	s.hub.Dirty()
	s.ok(w, H{"ok": true})
}

func (s *Server) handleRulePause(w http.ResponseWriter, r *http.Request, u *User) {
	old := s.ownedRule(w, r, u)
	if old == nil {
		return
	}
	var in struct {
		Paused bool `json:"paused"`
	}
	if err := bind(r, &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	if _, err := s.db.Exec(`UPDATE rules SET paused=?, updated_at=? WHERE id=?`, in.Paused, now(), old.ID); err != nil {
		s.dbErr(w, err)
		return
	}
	s.hub.Dirty()
	s.ok(w, H{"ok": true})
}

func (s *Server) handleRuleDiag(w http.ResponseWriter, r *http.Request, u *User) {
	rule := s.ownedRule(w, r, u)
	if rule == nil {
		return
	}
	if rule.Paused {
		s.ok(w, H{"hops": []proto.DiagHop{{From: "面板", To: "-", Error: "规则已暂停,恢复后才能诊断"}}})
		return
	}
	owner, err := getUser(s.db, rule.UserID)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	policy, err := loadRulePolicy(s.db)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	if !owner.Active() || policy.authorize(owner, rule) != nil {
		s.fail(w, http.StatusForbidden, "规则当前未获授权")
		return
	}
	hops := s.hub.diag(rule)
	if !u.IsAdmin() { // 普通用户不展示出口节点的真实地址
		for i := range hops {
			if strings.HasPrefix(hops[i].To, "出口 ") {
				hops[i].To = "出口节点"
			}
		}
	}
	s.ok(w, H{"hops": hops})
}

// handleRuleBatch 批量导入。每行一条:名称#监听端口#目标地址#目标端口(监听端口留空 = 自动分配)。
func (s *Server) handleRuleBatch(w http.ResponseWriter, r *http.Request, u *User) {
	var in struct {
		InGroup  int64  `json:"in_group"`
		OutGroup int64  `json:"out_group"`
		Proto    string `json:"proto"`
		Text     string `json:"text"`
	}
	if err := bind(r, &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	var lines []string
	for _, l := range strings.Split(in.Text, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 || len(lines) > 500 {
		s.fail(w, 400, "需要 1-500 行规则")
		return
	}
	s.ruleMu.Lock()
	defer s.ruleMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		s.dbErr(w, err)
		return
	}
	defer tx.Rollback()
	owner, err := getUser(tx, u.ID)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	if err = s.checkQuota(owner, len(lines)); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	policy, err := loadRulePolicy(tx)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	for i, l := range lines {
		f := strings.Split(l, "#")
		if len(f) != 4 {
			s.fail(w, 400, fmt.Sprintf("第 %d 行格式错误,应为 名称#监听端口#目标地址#目标端口", i+1))
			return
		}
		port := 0
		if p := strings.TrimSpace(f[1]); p != "" {
			if port, err = strconv.Atoi(p); err != nil {
				s.fail(w, 400, fmt.Sprintf("第 %d 行监听端口无效", i+1))
				return
			}
		}
		ri := ruleInput{
			Name: f[0], InGroup: in.InGroup, OutGroup: in.OutGroup, ListenPort: port, Proto: in.Proto,
			Targets: []string{net.JoinHostPort(strings.TrimSpace(f[2]), strings.TrimSpace(f[3]))},
		}
		rule, err := policy.prepareRule(tx, u, owner, &ri, nil)
		if err == nil {
			_, err = s.insertRule(tx, rule)
		}
		if err != nil {
			s.fail(w, 400, fmt.Sprintf("第 %d 行: %v", i+1, err))
			return
		}
	}
	if err := tx.Commit(); err != nil {
		s.dbErr(w, err)
		return
	}
	s.hub.Dirty()
	s.ok(w, H{"created": len(lines)})
}
