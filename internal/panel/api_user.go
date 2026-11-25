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
}

// accessibleGroups 返回用户可用的设备组:公开组 + 套餐额外授权的组;管理员可用全部。
func (s *Server) accessibleGroups(u *User) ([]*Group, error) {
	all, err := listGroups(s.db)
	if err != nil || u.IsAdmin() {
		return all, err
	}
	allowed := map[int64]bool{}
	if u.PlanID != 0 {
		if p, err := getPlan(s.db, u.PlanID); err == nil {
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
	return out, nil
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request, u *User) {
	groups, err := s.accessibleGroups(u)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	nodes, err := listNodes(s.db, "")
	if err != nil {
		s.dbErr(w, err)
		return
	}
	online := s.hub.onlineCount()
	out := []groupView{}
	for _, g := range groups {
		v := groupView{
			ID: g.ID, Name: g.Name, Type: g.Type, Ratio: g.Ratio, Note: g.Note, Online: online[g.ID],
			AllowedOut: g.Config.AllowedOut, Hosts: []string{},
		}
		for _, n := range nodes {
			if n.GroupID == g.ID {
				v.NodeCount++
				if g.Type == proto.RoleIn && g.Config.DisplayHost == "" && n.IP != "" {
					v.Hosts = append(v.Hosts, n.IP)
				}
			}
		}
		if g.Type == proto.RoleIn {
			if g.Config.DisplayHost != "" {
				for _, h := range strings.Split(g.Config.DisplayHost, ",") {
					if h = strings.TrimSpace(h); h != "" {
						v.Hosts = append(v.Hosts, h)
					}
				}
			}
			v.PortRange, v.DirectMode, v.DisableUDP = g.Config.PortRange, g.Config.DirectMode, g.Config.DisableUDP
			v.Blocked = g.Config.BlockedProtocols
		} else {
			v.Transport = g.Config.Transport
			if g.Config.CDN {
				v.Transport = "ws (CDN)"
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
	ListenPort    int      `json:"listen_port"` // 0 = 自动分配
	Proto         string   `json:"proto"`
	Targets       []string `json:"targets"`
	LB            string   `json:"lb"`
	ProxyProtocol int      `json:"proxy_protocol"`
	SpeedLimit    int      `json:"speed_limit"`
	ConnLimit     int      `json:"conn_limit"`
	IPLimit       int      `json:"ip_limit"`
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

// prepareRule 校验输入并补全默认值。owner 是规则归属用户,old 为编辑时的原规则。
func (policy *rulePolicy) prepareRule(q dbq, owner *User, in *ruleInput, old *Rule) (*Rule, error) {
	r := &Rule{
		UserID: owner.ID, Name: strings.TrimSpace(in.Name), InGroup: in.InGroup, OutGroup: in.OutGroup,
		ListenPort: in.ListenPort, Proto: in.Proto, LB: in.LB, ProxyProtocol: in.ProxyProtocol,
		SpeedLimit: max(in.SpeedLimit, 0), ConnLimit: max(in.ConnLimit, 0), IPLimit: max(in.IPLimit, 0),
	}
	if len([]rune(r.Name)) > 64 {
		return nil, errors.New("规则名称过长")
	}
	switch r.Proto {
	case "":
		r.Proto = "tcp+udp"
	case "tcp", "udp", "tcp+udp":
	default:
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

	if err := policy.authorize(owner, r); err != nil {
		return nil, err
	}
	ig := policy.groups[r.InGroup]
	ranges := rulePortRanges(ig)
	taken := func(p int) bool {
		var id int64
		err := q.QueryRow(`SELECT id FROM rules WHERE in_group=? AND listen_port=?`, r.InGroup, p).Scan(&id)
		return err == nil && (old == nil || id != old.ID)
	}
	if r.ListenPort == 0 {
		if old != nil && old.InGroup == r.InGroup {
			r.ListenPort = old.ListenPort
		} else {
			for try := 0; try < 200 && r.ListenPort == 0; try++ {
				rg := ranges[rand.IntN(len(ranges))]
				if p := rg[0] + rand.IntN(rg[1]-rg[0]+1); !taken(p) {
					r.ListenPort = p
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
	if r.Name == "" {
		r.Name = fmt.Sprintf("规则-%d", r.ListenPort)
	}
	return r, nil
}

func (s *Server) insertRule(q dbq, r *Rule) (int64, error) {
	tj, _ := json.Marshal(r.Targets)
	t := now()
	res, err := q.Exec(`INSERT INTO rules(user_id,name,in_group,out_group,listen_port,proto,targets,lb,proxy_protocol,
		speed_limit,conn_limit,ip_limit,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.UserID, r.Name, r.InGroup, r.OutGroup, r.ListenPort, r.Proto, string(tj), r.LB, r.ProxyProtocol,
		r.SpeedLimit, r.ConnLimit, r.IPLimit, t, t)
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
		switch {
		case x.Paused:
			x.Status = "paused"
		case !active:
			x.Status, x.Error = "inactive", "账号不可用(到期、流量用尽或被封禁)"
		case policyErr != nil:
			x.Status, x.Error = "inactive", policyErr.Error()
		case errs[x.ID] != "":
			x.Status, x.Error = "error", errs[x.ID]
		case online[x.InGroup] == 0:
			x.Status, x.Error = "offline", "入口组没有在线节点"
		case x.OutGroup != 0 && online[x.OutGroup] == 0:
			x.Status, x.Error = "offline", "出口组没有在线节点"
		default:
			x.Status = "ok"
		}
		out = append(out, x)
	}
	s.ok(w, out)
}

func (s *Server) handleRuleCreate(w http.ResponseWriter, r *http.Request, u *User) {
	var in ruleInput
	if err := bind(r, &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
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
	rule, err := policy.prepareRule(tx, owner, &in, nil)
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
	s.ok(w, rule)
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

func (s *Server) handleRuleUpdate(w http.ResponseWriter, r *http.Request, u *User) {
	old := s.ownedRule(w, r, u)
	if old == nil {
		return
	}
	var in ruleInput
	if err := bind(r, &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	owner, err := getUser(s.db, old.UserID)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	policy, err := loadRulePolicy(s.db)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	rule, err := policy.prepareRule(s.db, owner, &in, old)
	if err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	tj, _ := json.Marshal(rule.Targets)
	if _, err := s.db.Exec(`UPDATE rules SET name=?,in_group=?,out_group=?,listen_port=?,proto=?,targets=?,lb=?,proxy_protocol=?,
		speed_limit=?,conn_limit=?,ip_limit=?,updated_at=? WHERE id=?`,
		rule.Name, rule.InGroup, rule.OutGroup, rule.ListenPort, rule.Proto, string(tj), rule.LB, rule.ProxyProtocol,
		rule.SpeedLimit, rule.ConnLimit, rule.IPLimit, now(), old.ID); err != nil {
		s.fail(w, http.StatusConflict, "端口冲突,请重试")
		return
	}
	s.hub.Dirty()
	s.ok(w, H{"ok": true})
}

func (s *Server) handleRuleDelete(w http.ResponseWriter, r *http.Request, u *User) {
	old := s.ownedRule(w, r, u)
	if old == nil {
		return
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
		rule, err := policy.prepareRule(tx, owner, &ri, nil)
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
