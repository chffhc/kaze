package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"kaze/internal/proto"
	"kaze/internal/tunnel"
)

// ---- 概览 ----

func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request, u *User) {
	var users, rules, nodes, groups int
	s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users)
	s.db.QueryRow(`SELECT COUNT(*) FROM rules`).Scan(&rules)
	s.db.QueryRow(`SELECT COUNT(*) FROM nodes`).Scan(&nodes)
	s.db.QueryRow(`SELECT COUNT(*) FROM device_groups`).Scan(&groups)
	online := 0
	for _, n := range s.hub.onlineCount() {
		online += n
	}
	hourly, daily, err := s.trafficSeries(0)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	nowT := time.Now()
	day := time.Date(nowT.Year(), nowT.Month(), nowT.Day(), 0, 0, 0, 0, time.Local).Unix()
	month := time.Date(nowT.Year(), nowT.Month(), 1, 0, 0, 0, 0, time.Local).Unix()
	income := func(since int64) (v int64) {
		s.db.QueryRow(`SELECT COALESCE(SUM(amount),0) FROM orders WHERE type='recharge' AND status='paid' AND paid_at>=?`, since).Scan(&v)
		return
	}
	sales := func(since int64) (v int64) {
		s.db.QueryRow(`SELECT COALESCE(SUM(amount),0) FROM orders WHERE type IN ('plan','renew') AND status='paid' AND paid_at>=?`, since).Scan(&v)
		return
	}
	// 流量排行(近 24 小时)
	type top struct {
		Username string `json:"username"`
		Billed   int64  `json:"billed"`
	}
	tops := []top{}
	if rows, err := s.db.Query(`SELECT u.username, SUM(t.billed) b FROM traffic_hourly t JOIN users u ON u.id=t.user_id
		WHERE t.hour>=? GROUP BY t.user_id ORDER BY b DESC LIMIT 8`, now()-86400); err == nil {
		for rows.Next() {
			var t top
			rows.Scan(&t.Username, &t.Billed)
			tops = append(tops, t)
		}
		rows.Close()
	}
	s.ok(w, H{
		"users": users, "rules": rules, "nodes": nodes, "nodes_online": online, "groups": groups,
		"hourly": hourly, "daily": daily, "top_users": tops,
		"recharge_today": income(day), "recharge_month": income(month),
		"sales_today": sales(day), "sales_month": sales(month),
		"version": proto.Version,
	})
}

// ---- 用户 ----

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request, u *User) {
	q := `SELECT ` + userCols + ` FROM users u`
	var args []any
	if kw := strings.TrimSpace(r.URL.Query().Get("q")); kw != "" {
		q += ` WHERE u.username LIKE ? OR u.note LIKE ?`
		args = append(args, "%"+kw+"%", "%"+kw+"%")
	}
	rows, err := s.db.Query(q+` ORDER BY u.id LIMIT 2000`, args...)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	defer rows.Close()
	out := []*User{}
	for rows.Next() {
		x, err := scanUser(rows)
		if err != nil {
			s.dbErr(w, err)
			return
		}
		out = append(out, x)
	}
	s.ok(w, out)
}

type userInput struct {
	Username     *string `json:"username"`
	Password     *string `json:"password"`
	Role         *string `json:"role"`
	Balance      *int64  `json:"balance"`
	PlanID       *int64  `json:"plan_id"`
	TrafficQuota *int64  `json:"traffic_quota"`
	TrafficUsed  *int64  `json:"traffic_used"`
	ExpireAt     *int64  `json:"expire_at"`
	MaxRules     *int    `json:"max_rules"`
	SpeedLimit   *int    `json:"speed_limit"`
	ConnLimit    *int    `json:"conn_limit"`
	IPLimit      *int    `json:"ip_limit"`
	AutoRenew    *bool   `json:"auto_renew"`
	Banned       *bool   `json:"banned"`
	Note         *string `json:"note"`
}

func (s *Server) handleAdminUserCreate(w http.ResponseWriter, r *http.Request, u *User) {
	var in userInput
	if err := bind(r, &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	if in.Username == nil || !validUsername(strings.TrimSpace(*in.Username)) {
		s.fail(w, 400, "用户名需为 3-32 位字母、数字或 _ - . @")
		return
	}
	if in.Password == nil || len(*in.Password) < 8 {
		s.fail(w, 400, "密码至少 8 位")
		return
	}
	res, err := s.db.Exec(`INSERT INTO users(username,password,role,created_at) VALUES(?,?,'user',?)`,
		strings.TrimSpace(*in.Username), hashPassword(*in.Password), now())
	if err != nil {
		s.fail(w, http.StatusConflict, "用户名已被占用")
		return
	}
	id, _ := res.LastInsertId()
	in.Username, in.Password = nil, nil
	if err := s.updateUser(u, id, &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	nu, _ := getUser(s.db, id)
	s.ok(w, nu)
}

// updateUser 按"只改传入字段"的方式更新用户。
func (s *Server) updateUser(actor *User, id int64, in *userInput) error {
	old, err := getUser(s.db, id)
	if err != nil {
		return fmt.Errorf("用户不存在")
	}
	var sets []string
	var args []any
	set := func(col string, v any) {
		sets = append(sets, col+"=?")
		args = append(args, v)
	}
	if in.Username != nil {
		name := strings.TrimSpace(*in.Username)
		if !validUsername(name) {
			return fmt.Errorf("用户名需为 3-32 位字母、数字或 _ - . @")
		}
		set("username", name)
	}
	if in.Password != nil && *in.Password != "" {
		if len(*in.Password) < 8 {
			return fmt.Errorf("密码至少 8 位")
		}
		set("password", hashPassword(*in.Password))
		sets = append(sets, "token_ver=token_ver+1")
	}
	if in.Role != nil {
		if *in.Role != "admin" && *in.Role != "user" {
			return fmt.Errorf("角色无效")
		}
		if id == actor.ID && *in.Role != "admin" {
			return fmt.Errorf("不能取消自己的管理员身份")
		}
		set("role", *in.Role)
	}
	if in.Banned != nil {
		if id == actor.ID && *in.Banned {
			return fmt.Errorf("不能封禁自己")
		}
		set("banned", *in.Banned)
	}
	if in.Balance != nil {
		set("balance", *in.Balance)
	}
	if in.PlanID != nil {
		set("plan_id", *in.PlanID)
	}
	if in.TrafficQuota != nil {
		set("traffic_quota", max(*in.TrafficQuota, 0))
	}
	if in.TrafficUsed != nil {
		set("traffic_used", max(*in.TrafficUsed, 0))
	}
	if in.ExpireAt != nil {
		set("expire_at", max(*in.ExpireAt, 0))
	}
	if in.MaxRules != nil {
		set("max_rules", max(*in.MaxRules, 0))
	}
	if in.SpeedLimit != nil {
		set("speed_limit", max(*in.SpeedLimit, 0))
	}
	if in.ConnLimit != nil {
		set("conn_limit", max(*in.ConnLimit, 0))
	}
	if in.IPLimit != nil {
		set("ip_limit", max(*in.IPLimit, 0))
	}
	if in.AutoRenew != nil {
		set("auto_renew", *in.AutoRenew)
	}
	if in.Note != nil {
		set("note", *in.Note)
	}
	if len(sets) == 0 {
		return nil
	}
	args = append(args, id)
	if _, err := s.db.Exec(`UPDATE users SET `+strings.Join(sets, ",")+` WHERE id=?`, args...); err != nil {
		return fmt.Errorf("保存失败(用户名可能已被占用)")
	}
	if in.Balance != nil && *in.Balance != old.Balance {
		t := now()
		s.db.Exec(`INSERT INTO orders(order_no,user_id,type,amount,status,pay_method,note,created_at,paid_at)
			VALUES(?,?,'admin',?,'paid','admin',?,?,?)`, orderNo(), id, *in.Balance-old.Balance,
			"管理员 "+actor.Username+" 调整余额", t, t)
	}
	s.hub.Dirty()
	return nil
}

func (s *Server) handleAdminUserUpdate(w http.ResponseWriter, r *http.Request, u *User) {
	var in userInput
	if err := bind(r, &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	if err := s.updateUser(u, pathID(r), &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	nu, err := getUser(s.db, pathID(r))
	if err != nil {
		s.dbErr(w, err)
		return
	}
	s.ok(w, nu)
}

func (s *Server) handleAdminUserDelete(w http.ResponseWriter, r *http.Request, u *User) {
	id := pathID(r)
	if id == u.ID {
		s.fail(w, 400, "不能删除自己")
		return
	}
	s.ruleMu.Lock()
	defer s.ruleMu.Unlock()
	// 管理员名下的共享 TLS 端口还挂着别人的子规则时,不能连带删掉
	var orphans int
	s.db.QueryRow(`SELECT COUNT(*) FROM rules c JOIN rules p ON p.in_group=c.in_group AND p.listen_port=c.listen_port AND p.tls_mode='parent'
		WHERE c.tls_mode='child' AND p.user_id=? AND c.user_id<>?`, id, id).Scan(&orphans)
	if orphans > 0 {
		s.fail(w, 400, fmt.Sprintf("该用户创建的共享 TLS 端口下还有其他用户的 %d 条子规则,请先处理这些规则", orphans))
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		s.dbErr(w, err)
		return
	}
	defer tx.Rollback()
	tx.Exec(`DELETE FROM rules WHERE user_id=?`, id)
	tx.Exec(`DELETE FROM traffic_hourly WHERE user_id=?`, id)
	tx.Exec(`DELETE FROM users WHERE id=?`, id)
	if err := tx.Commit(); err != nil {
		s.dbErr(w, err)
		return
	}
	s.hub.Dirty()
	s.ok(w, H{"ok": true})
}

// ---- 设备组 ----

type adminGroupView struct {
	*Group
	Online     int    `json:"online"`
	NodeCount  int    `json:"node_count"`
	RuleCount  int    `json:"rule_count"`
	InstallCmd string `json:"install_cmd"`
}

func (s *Server) installCmd(r *http.Request, g *Group) string {
	if g.Type == proto.RoleChain {
		return "" // 链式出口没有自己的机器
	}
	base := s.baseURL(r)
	return fmt.Sprintf("bash <(curl -fsSL %s/install.sh) -u %s -t %s", base, base, g.Token)
}

func (s *Server) handleAdminGroups(w http.ResponseWriter, r *http.Request, u *User) {
	groups, err := listGroups(s.db)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	gs := toGroupSet(groups)
	online := s.hub.onlineCount()
	count := func(q string) map[int64]int {
		m := map[int64]int{}
		if rows, err := s.db.Query(q); err == nil {
			for rows.Next() {
				var id int64
				var n int
				rows.Scan(&id, &n)
				m[id] += n
			}
			rows.Close()
		}
		return m
	}
	nodeN := count(`SELECT group_id, COUNT(*) FROM nodes GROUP BY group_id`)
	ruleIn := count(`SELECT in_group, COUNT(*) FROM rules GROUP BY in_group`)
	ruleOut := count(`SELECT out_group, COUNT(*) FROM rules WHERE out_group<>0 GROUP BY out_group`)
	out := []adminGroupView{}
	for _, g := range groups {
		v := adminGroupView{
			Group: g, Online: online[g.ID], NodeCount: nodeN[g.ID], RuleCount: ruleIn[g.ID] + ruleOut[g.ID],
			InstallCmd: s.installCmd(r, g),
		}
		if g.Type == proto.RoleChain {
			// 在线数取各跳里最少的;链路不完整时为 0
			if hops, _, ok := gs.hops(g.ID); ok {
				v.Online = online[hops[0].ID]
				for _, hg := range hops[1:] {
					v.Online = min(v.Online, online[hg.ID])
				}
			}
		}
		out = append(out, v)
	}
	s.ok(w, out)
}

type groupInput struct {
	Name   string      `json:"name"`
	Type   string      `json:"type"`
	Ratio  float64     `json:"ratio"`
	Public bool        `json:"public"`
	Sort   int         `json:"sort"`
	Note   string      `json:"note"`
	Config GroupConfig `json:"config"`
}

var wsPathRe = regexp.MustCompile(`^/[A-Za-z0-9/_.~-]*$`)

func randomHostname() string { return "www." + strings.ToLower(randString(8)) + ".com" }

func uniqueIDs(in []int64) []int64 {
	out := []int64{}
	for _, id := range in {
		if id >= 0 && !containsID(out, id) {
			out = append(out, id)
		}
	}
	return out
}

func trimList(in []string) []string {
	out := []string{}
	for _, x := range in {
		if x = strings.ToLower(strings.TrimSpace(x)); x != "" && !containsStr(out, x) {
			out = append(out, x)
		}
	}
	return out
}

// normalizeGroup 校验设备组并补全默认值。只保留与该类型相关的配置项;
// old 非空时沿用原有的密钥材料,gs 是现有的全部设备组(校验链式出口用)。
func normalizeGroup(in *groupInput, old *Group, gs groupSet) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len([]rune(in.Name)) > 64 {
		return errors.New("名称不能为空且不超过 64 个字符")
	}
	if old != nil && old.Type != in.Type {
		return errors.New("设备组类型创建后不可更改")
	}
	if in.Ratio < 0 || in.Ratio > 1000 {
		return errors.New("倍率无效")
	}
	var c GroupConfig
	var err error
	switch in.Type {
	case proto.RoleIn:
		c, err = normalizeInGroup(&in.Config, old)
	case proto.RoleOut:
		c, err = normalizeOutGroup(&in.Config, old)
	case proto.RoleChain:
		c, err = normalizeChain(&in.Config, gs)
	default:
		return errors.New("类型只能是 in(入口)、out(出口)或 chain(链式出口)")
	}
	if err != nil {
		return err
	}
	in.Config = c
	return nil
}

// pemPair 原样返回一对证书与私钥;任何一个为空白就都当作没填。
// 不去改动它们的文本(哪怕只是末尾的换行):节点拿证书文本判断隧道参数有没有变,变了就会重启监听。
func pemPair(cert, key string) (string, string) {
	if strings.TrimSpace(cert) == "" || strings.TrimSpace(key) == "" {
		return "", ""
	}
	return cert, key
}

func failoverDefaults(maxFail, failTimeout int) (int, int) {
	if maxFail <= 0 {
		maxFail = 3
	}
	if failTimeout <= 0 {
		failTimeout = 30
	}
	return maxFail, failTimeout
}

func normalizeInGroup(in *GroupConfig, old *Group) (GroupConfig, error) {
	c := GroupConfig{
		DisplayHost: strings.TrimSpace(in.DisplayHost), PortRange: strings.TrimSpace(in.PortRange), DirectMode: in.DirectMode,
		AllowedOut: uniqueIDs(in.AllowedOut), BlockedProtocols: trimList(in.BlockedProtocols),
		BlockedHosts: trimList(in.BlockedHosts), AllowedHosts: trimList(in.AllowedHosts),
		DisableUDP: in.DisableUDP, AllowPrivate: in.AllowPrivate,
		TLSInboundPolicy: in.TLSInboundPolicy, TLSRejectEmptySNI: in.TLSRejectEmptySNI,
		ReverseGroups: uniqueIDs(in.ReverseGroups), ReverseSNI: strings.ToLower(strings.TrimSpace(in.ReverseSNI)), ReverseConns: in.ReverseConns,
	}
	c.RevCertPEM, c.RevKeyPEM = pemPair(in.RevCertPEM, in.RevKeyPEM)
	c.MaxFail, c.FailTimeout = failoverDefaults(in.MaxFail, in.FailTimeout)
	if c.PortRange == "" {
		c.PortRange = "10000-60000"
	}
	if _, err := parsePortRange(c.PortRange); err != nil {
		return c, err
	}
	if c.DirectMode < 0 || c.DirectMode > 2 {
		return c, errors.New("直出策略无效")
	}
	for _, p := range c.BlockedProtocols {
		if p != "http" && p != "tls" && p != "socks" {
			return c, errors.New("屏蔽协议只支持 http / tls / socks")
		}
	}
	if c.TLSInboundPolicy < 0 || c.TLSInboundPolicy > 2 {
		return c, errors.New("TLS 入站策略只能是 0 / 1 / 2")
	}
	if c.TLSInboundPolicy > 0 && containsStr(c.BlockedProtocols, "tls") {
		return c, errors.New("入站屏蔽了 TLS 协议,就不能再要求用户只建 TLS 入站规则")
	}
	if c.ReverseSNI != "" && !hostRe.MatchString(c.ReverseSNI) {
		return c, errors.New("反向隧道的 SNI 无效")
	}
	if c.ReverseConns <= 0 {
		c.ReverseConns = 2
	}
	c.ReverseConns = min(c.ReverseConns, 16)

	// 反向隧道证书:沿用旧的;开启了反向隧道而还没有证书时生成一张。
	// 出口拨入时固定校验它的指纹,所以这里不需要 CA 签发的证书。
	if (c.RevCertPEM == "" || c.RevKeyPEM == "") && old != nil {
		c.RevCertPEM, c.RevKeyPEM = old.Config.RevCertPEM, old.Config.RevKeyPEM
	}
	switch {
	case c.RevCertPEM != "" && c.RevKeyPEM != "":
		cert, err := tunnel.ParseCert(c.RevCertPEM, c.RevKeyPEM)
		if err != nil {
			return c, fmt.Errorf("反向隧道的证书或私钥无效: %v", err)
		}
		c.RevCertPin = tunnel.CertPin(&cert)
	case len(c.ReverseGroups) > 0:
		name := c.ReverseSNI
		if name == "" {
			name = randomHostname()
		}
		var err error
		if c.RevCertPEM, c.RevKeyPEM, c.RevCertPin, err = tunnel.GenerateCert(name); err != nil {
			return c, err
		}
	default:
		c.RevCertPEM, c.RevKeyPEM = "", ""
	}
	return c, nil
}

func normalizeOutGroup(in *GroupConfig, old *Group) (GroupConfig, error) {
	c := GroupConfig{
		Transport: in.Transport, Mux: in.Mux, MuxConns: in.MuxConns, TunnelPort: in.TunnelPort,
		ConnectHost: strings.TrimSpace(in.ConnectHost), ConnectPort: in.ConnectPort,
		SNI: strings.ToLower(strings.TrimSpace(in.SNI)), WSHost: strings.TrimSpace(in.WSHost), WSPath: strings.TrimSpace(in.WSPath),
		CDN: in.CDN, CDNTLS: in.CDNTLS, UDPOverTCP: in.UDPOverTCP, FailoverGroup: max(in.FailoverGroup, 0),
		Fingerprint: strings.ToLower(strings.TrimSpace(in.Fingerprint)), AllowPrivate: in.AllowPrivate,
		TunnelKey: strings.TrimSpace(in.TunnelKey),
	}
	c.CertPEM, c.KeyPEM = pemPair(in.CertPEM, in.KeyPEM)
	c.MaxFail, c.FailTimeout = failoverDefaults(in.MaxFail, in.FailTimeout)
	if c.Transport == "" {
		c.Transport = tunnel.TransportTLS
	}
	if !tunnel.ValidTransport(c.Transport) {
		return c, errors.New("传输层只能是 tls / wss / ws / http / tcp")
	}
	if c.Transport == tunnel.TransportWS || c.Transport == tunnel.TransportWSS || c.CDN {
		c.Mux = true // WebSocket 没有半关闭,必须走复用层
	}
	if c.CDN && c.ConnectHost == "" {
		return c, errors.New("CDN 模式必须填写连接地址(CDN 域名或优选 IP)")
	}
	if !tunnel.ValidFingerprint(c.Fingerprint) {
		return c, errors.New("TLS 指纹只能是 " + strings.Join(tunnel.Fingerprints(), " / ") + ",或留空")
	}
	if c.SNI != "" && !hostRe.MatchString(c.SNI) {
		return c, errors.New("TLS SNI 无效")
	}
	if c.MuxConns <= 0 {
		c.MuxConns = 4
	}
	c.MuxConns = min(c.MuxConns, 32)
	if c.TunnelPort < 0 || c.TunnelPort > 65535 || c.ConnectPort < 0 || c.ConnectPort > 65535 {
		return c, errors.New("端口无效")
	}
	if c.WSPath == "" {
		c.WSPath = "/"
	}
	if !wsPathRe.MatchString(c.WSPath) {
		return c, errors.New("路径无效:需以 / 开头,只能包含字母、数字和 / _ . ~ -")
	}
	// 密钥材料:沿用旧值,缺失则生成
	if old != nil {
		if c.TunnelKey == "" {
			c.TunnelKey = old.Config.TunnelKey
		}
		if c.CertPEM == "" || c.KeyPEM == "" {
			c.CertPEM, c.KeyPEM = old.Config.CertPEM, old.Config.KeyPEM
		}
	}
	if _, err := tunnel.DeriveKeys(c.TunnelKey); err != nil {
		c.TunnelKey = tunnel.NewKey()
	}
	if c.CertPEM == "" || c.KeyPEM == "" {
		name := c.SNI
		if name == "" {
			name = randomHostname()
		}
		var err error
		if c.CertPEM, c.KeyPEM, c.CertPin, err = tunnel.GenerateCert(name); err != nil {
			return c, err
		}
	} else {
		cert, err := tunnel.ParseCert(c.CertPEM, c.KeyPEM)
		if err != nil {
			return c, fmt.Errorf("证书或私钥无效: %v", err)
		}
		c.CertPin = tunnel.CertPin(&cert)
	}
	return c, nil
}

func normalizeChain(in *GroupConfig, gs groupSet) (GroupConfig, error) {
	c := GroupConfig{ChainHops: in.ChainHops, ChainMux: in.ChainMux}
	if n := len(c.ChainHops); n < 2 || n > 3 {
		return c, errors.New("链式出口需要依次选择 2 到 3 个出口组")
	}
	for i, id := range c.ChainHops {
		if containsID(c.ChainHops[:i], id) {
			return c, errors.New("链式出口里同一个出口组只能出现一次")
		}
		if hg := gs[id]; hg == nil || hg.Type != proto.RoleOut {
			return c, fmt.Errorf("第 %d 跳不是一个出口组", i+1)
		}
	}
	return c, nil
}

// keyMaterialBase 决定修改设备组时沿用哪些原有的密钥材料。
// 请求里没有带某一项(或原样带回)时沿用原值;明确把它写成空字符串,表示要重新生成:
//
//	tunnel_key   -> 出口组的隧道密钥
//	cert_pem     -> 出口组的隧道证书与私钥
//	rev_cert_pem -> 入口组的反向隧道证书与私钥
func keyMaterialBase(old *Group, body []byte) *Group {
	var raw struct {
		Config map[string]json.RawMessage `json:"config"`
	}
	json.Unmarshal(body, &raw)
	emptied := func(k string) bool { return strings.TrimSpace(string(raw.Config[k])) == `""` }
	base := *old
	if emptied("tunnel_key") {
		base.Config.TunnelKey = ""
	}
	if emptied("cert_pem") {
		base.Config.CertPEM, base.Config.KeyPEM = "", ""
	}
	if emptied("rev_cert_pem") {
		base.Config.RevCertPEM, base.Config.RevKeyPEM = "", ""
	}
	return &base
}

func (s *Server) handleAdminGroupCreate(w http.ResponseWriter, r *http.Request, u *User) {
	var in groupInput
	in.Ratio, in.Public = 1, true
	in.Config.Mux = true
	if err := bind(r, &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	all, err := listGroups(s.db)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	if err := normalizeGroup(&in, nil, toGroupSet(all)); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	cj, _ := json.Marshal(&in.Config)
	res, err := s.db.Exec(`INSERT INTO device_groups(name,type,token,ratio,public,sort,note,config,created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		in.Name, in.Type, randHex(20), in.Ratio, in.Public, in.Sort, in.Note, string(cj), now())
	if err != nil {
		s.dbErr(w, err)
		return
	}
	id, _ := res.LastInsertId()
	g, err := getGroup(s.db, id)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	s.ok(w, adminGroupView{Group: g, InstallCmd: s.installCmd(r, g)})
}

func (s *Server) handleAdminGroupUpdate(w http.ResponseWriter, r *http.Request, u *User) {
	old, err := getGroup(s.db, pathID(r))
	if err != nil {
		s.dbErr(w, err)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	var in groupInput
	if err != nil || json.Unmarshal(body, &in) != nil {
		s.fail(w, 400, "请求格式错误")
		return
	}
	if in.Type == "" {
		in.Type = old.Type
	}
	all, err := listGroups(s.db)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	if err := normalizeGroup(&in, keyMaterialBase(old, body), toGroupSet(all)); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	if in.Config.FailoverGroup == old.ID {
		in.Config.FailoverGroup = 0
	}
	cj, _ := json.Marshal(&in.Config)
	if _, err := s.db.Exec(`UPDATE device_groups SET name=?,ratio=?,public=?,sort=?,note=?,config=? WHERE id=?`,
		in.Name, in.Ratio, in.Public, in.Sort, in.Note, string(cj), old.ID); err != nil {
		s.dbErr(w, err)
		return
	}
	s.hub.Dirty()
	s.ok(w, H{"ok": true})
}

func (s *Server) handleAdminGroupDelete(w http.ResponseWriter, r *http.Request, u *User) {
	id := pathID(r)
	all, err := listGroups(s.db)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	for _, g := range all {
		if g.Type == proto.RoleChain && containsID(g.Config.ChainHops, id) {
			s.fail(w, 400, fmt.Sprintf("链式出口「%s」经过这个出口组,请先修改或删除它", g.Name))
			return
		}
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM rules WHERE in_group=? OR out_group=?`, id, id).Scan(&n)
	if n > 0 && r.URL.Query().Get("force") != "1" {
		s.fail(w, http.StatusConflict, fmt.Sprintf("该设备组下还有 %d 条规则,确认后将一并删除", n))
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
	tx.Exec(`DELETE FROM rules WHERE in_group=? OR out_group=?`, id, id)
	tx.Exec(`DELETE FROM nodes WHERE group_id=?`, id)
	tx.Exec(`DELETE FROM device_groups WHERE id=?`, id)
	if err := tx.Commit(); err != nil {
		s.dbErr(w, err)
		return
	}
	s.hub.kickGroup(id)
	s.hub.Dirty()
	s.ok(w, H{"ok": true})
}

func (s *Server) handleAdminGroupResetToken(w http.ResponseWriter, r *http.Request, u *User) {
	g, err := getGroup(s.db, pathID(r))
	if err != nil {
		s.dbErr(w, err)
		return
	}
	if g.Type == proto.RoleChain {
		s.fail(w, 400, "链式出口没有对接令牌")
		return
	}
	g.Token = randHex(20)
	if _, err := s.db.Exec(`UPDATE device_groups SET token=? WHERE id=?`, g.Token, g.ID); err != nil {
		s.dbErr(w, err)
		return
	}
	s.hub.kickGroup(g.ID)
	s.ok(w, H{"token": g.Token, "install_cmd": s.installCmd(r, g)})
}

// ---- 节点 ----

func (s *Server) handleAdminNodes(w http.ResponseWriter, r *http.Request, u *User) {
	nodes, err := listNodes(s.db, "")
	if err != nil {
		s.dbErr(w, err)
		return
	}
	type view struct {
		*Node
		NodeStatus
		Outdated bool `json:"outdated"` // 节点端版本低于面板:新功能在这台机器上不可用
	}
	out := []view{}
	for _, n := range nodes {
		out = append(out, view{Node: n, NodeStatus: s.hub.status(n.GroupID, n.UID), Outdated: !versionAtLeast(n.Version, proto.Version)})
	}
	s.ok(w, out)
}

func (s *Server) handleAdminNodeDelete(w http.ResponseWriter, r *http.Request, u *User) {
	var gid int64
	var uid string
	if err := s.db.QueryRow(`SELECT group_id, uid FROM nodes WHERE id=?`, pathID(r)).Scan(&gid, &uid); err != nil {
		s.dbErr(w, err)
		return
	}
	if s.hub.status(gid, uid).Online {
		s.fail(w, 400, "节点仍在线,请先在机器上停止节点端再删除")
		return
	}
	s.db.Exec(`DELETE FROM nodes WHERE id=?`, pathID(r))
	s.hub.Dirty()
	s.ok(w, H{"ok": true})
}

// ---- 套餐 ----

func (s *Server) handleAdminPlans(w http.ResponseWriter, r *http.Request, u *User) {
	plans, err := listPlans(s.db, true)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	s.ok(w, plans)
}

func (s *Server) handleAdminPlanSave(w http.ResponseWriter, r *http.Request, u *User) {
	var p Plan
	if err := bind(r, &p); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || p.Price < 0 || p.Traffic < 0 || p.Days < 0 || p.MaxRules < 0 {
		s.fail(w, 400, "套餐名称不能为空,价格、流量、天数、规则数不能为负")
		return
	}
	if p.Groups == nil {
		p.Groups = []int64{}
	}
	gj, _ := json.Marshal(p.Groups)
	id := pathID(r)
	var err error
	if id == 0 {
		_, err = s.db.Exec(`INSERT INTO plans(name,description,price,traffic,days,max_rules,speed_limit,conn_limit,ip_limit,groups,hidden,sort,created_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, p.Name, p.Description, p.Price, p.Traffic, p.Days, p.MaxRules,
			p.SpeedLimit, p.ConnLimit, p.IPLimit, string(gj), p.Hidden, p.Sort, now())
	} else {
		_, err = s.db.Exec(`UPDATE plans SET name=?,description=?,price=?,traffic=?,days=?,max_rules=?,speed_limit=?,conn_limit=?,
			ip_limit=?,groups=?,hidden=?,sort=? WHERE id=?`, p.Name, p.Description, p.Price, p.Traffic, p.Days, p.MaxRules,
			p.SpeedLimit, p.ConnLimit, p.IPLimit, string(gj), p.Hidden, p.Sort, id)
	}
	if err != nil {
		s.dbErr(w, err)
		return
	}
	s.hub.Dirty()
	s.ok(w, H{"ok": true})
}

func (s *Server) handleAdminPlanDelete(w http.ResponseWriter, r *http.Request, u *User) {
	if _, err := s.db.Exec(`DELETE FROM plans WHERE id=?`, pathID(r)); err != nil {
		s.dbErr(w, err)
		return
	}
	s.hub.Dirty()
	s.ok(w, H{"ok": true})
}

// ---- 订单与兑换码 ----

func (s *Server) handleAdminOrders(w http.ResponseWriter, r *http.Request, u *User) {
	out, err := s.queryOrders("")
	if err != nil {
		s.dbErr(w, err)
		return
	}
	s.ok(w, out)
}

func (s *Server) handleAdminCodes(w http.ResponseWriter, r *http.Request, u *User) {
	rows, err := s.db.Query(`SELECT c.id,c.code,c.type,c.amount,c.plan_id,c.used_by,COALESCE(u.username,''),c.used_at,c.note,c.created_at
		FROM redeem_codes c LEFT JOIN users u ON u.id=c.used_by ORDER BY c.id DESC LIMIT 2000`)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	defer rows.Close()
	type code struct {
		ID        int64  `json:"id"`
		Code      string `json:"code"`
		Type      string `json:"type"`
		Amount    int64  `json:"amount"`
		PlanID    int64  `json:"plan_id"`
		UsedBy    int64  `json:"used_by"`
		UsedName  string `json:"used_name"`
		UsedAt    int64  `json:"used_at"`
		Note      string `json:"note"`
		CreatedAt int64  `json:"created_at"`
	}
	out := []code{}
	for rows.Next() {
		var c code
		if err := rows.Scan(&c.ID, &c.Code, &c.Type, &c.Amount, &c.PlanID, &c.UsedBy, &c.UsedName, &c.UsedAt, &c.Note, &c.CreatedAt); err != nil {
			s.dbErr(w, err)
			return
		}
		out = append(out, c)
	}
	s.ok(w, out)
}

func (s *Server) handleAdminCodeCreate(w http.ResponseWriter, r *http.Request, u *User) {
	var in struct {
		Type   string `json:"type"` // balance / plan
		Amount int64  `json:"amount"`
		PlanID int64  `json:"plan_id"`
		Count  int    `json:"count"`
		Note   string `json:"note"`
	}
	if err := bind(r, &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	if in.Count < 1 || in.Count > 500 {
		s.fail(w, 400, "数量需在 1-500 之间")
		return
	}
	switch in.Type {
	case "balance":
		if in.Amount <= 0 {
			s.fail(w, 400, "面额必须大于 0")
			return
		}
		in.PlanID = 0
	case "plan":
		if _, err := getPlan(s.db, in.PlanID); err != nil {
			s.fail(w, 400, "套餐不存在")
			return
		}
		in.Amount = 0
	default:
		s.fail(w, 400, "类型只能是 balance 或 plan")
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		s.dbErr(w, err)
		return
	}
	defer tx.Rollback()
	codes := make([]string, 0, in.Count)
	for i := 0; i < in.Count; i++ {
		c := strings.ToUpper(randString(16))
		if _, err := tx.Exec(`INSERT INTO redeem_codes(code,type,amount,plan_id,note,created_at) VALUES(?,?,?,?,?,?)`,
			c, in.Type, in.Amount, in.PlanID, in.Note, now()); err != nil {
			s.dbErr(w, err)
			return
		}
		codes = append(codes, c)
	}
	if err := tx.Commit(); err != nil {
		s.dbErr(w, err)
		return
	}
	s.ok(w, H{"codes": codes})
}

func (s *Server) handleAdminCodeDelete(w http.ResponseWriter, r *http.Request, u *User) {
	if _, err := s.db.Exec(`DELETE FROM redeem_codes WHERE id=?`, pathID(r)); err != nil {
		s.dbErr(w, err)
		return
	}
	s.ok(w, H{"ok": true})
}

// ---- 站点设置 ----

// 可通过界面修改的设置项;epay_key 只写不读。
var settingKeys = []string{"site_name", "allow_register", "announcement", "panel_url",
	"epay_url", "epay_pid", "epay_key", "epay_types", "recharge_min"}

func (s *Server) handleAdminSettings(w http.ResponseWriter, r *http.Request, u *User) {
	out := H{}
	for _, k := range settingKeys {
		if k == "epay_key" {
			out["epay_key_set"] = s.setting(k, "") != ""
			continue
		}
		out[k] = s.setting(k, "")
	}
	if out["allow_register"] == "" {
		out["allow_register"] = "1"
	}
	s.ok(w, out)
}

func (s *Server) handleAdminSettingsSave(w http.ResponseWriter, r *http.Request, u *User) {
	var in map[string]string
	if err := bind(r, &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	for _, k := range settingKeys {
		v, ok := in[k]
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if k == "epay_key" && v == "" {
			continue // 留空表示不修改
		}
		if (k == "panel_url" || k == "epay_url") && v != "" && !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
			s.fail(w, 400, k+" 必须以 http:// 或 https:// 开头")
			return
		}
		if err := s.setSetting(k, v); err != nil {
			s.dbErr(w, err)
			return
		}
	}
	s.ok(w, H{"ok": true})
}

// ---- 节点端分发 ----

var dlNameRe = regexp.MustCompile(`^kaze-node-linux-(amd64|arm64)$`)

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if !dlNameRe.MatchString(name) || s.opt.DistDir == "" {
		http.NotFound(w, r)
		return
	}
	p := filepath.Join(s.opt.DistDir, name)
	if _, err := os.Stat(p); err != nil {
		http.Error(w, "面板的 dist 目录中没有 "+name+",请先运行 scripts/build.sh 并用 --dist 指向输出目录", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, p)
}

func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Write(installScript)
}
