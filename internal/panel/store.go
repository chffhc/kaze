// Package panel 是面板端:REST API、SQLite 存储、节点 Hub、计费与内嵌的 Web 界面。
package panel

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password      TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'user',
  balance       INTEGER NOT NULL DEFAULT 0,
  plan_id       INTEGER NOT NULL DEFAULT 0,
  traffic_quota INTEGER NOT NULL DEFAULT 0,
  traffic_used  INTEGER NOT NULL DEFAULT 0,
  expire_at     INTEGER NOT NULL DEFAULT 0,
  max_rules     INTEGER NOT NULL DEFAULT 0,
  speed_limit   INTEGER NOT NULL DEFAULT 0,
  conn_limit    INTEGER NOT NULL DEFAULT 0,
  ip_limit      INTEGER NOT NULL DEFAULT 0,
  auto_renew    INTEGER NOT NULL DEFAULT 0,
  banned        INTEGER NOT NULL DEFAULT 0,
  note          TEXT NOT NULL DEFAULT '',
  token_ver     INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS device_groups (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL,
  type       TEXT NOT NULL,
  token      TEXT NOT NULL UNIQUE,
  ratio      REAL NOT NULL DEFAULT 1,
  public     INTEGER NOT NULL DEFAULT 1,
  sort       INTEGER NOT NULL DEFAULT 0,
  note       TEXT NOT NULL DEFAULT '',
  config     TEXT NOT NULL DEFAULT '{}',
  traffic    INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id     INTEGER NOT NULL,
  uid          TEXT NOT NULL,
  hostname     TEXT NOT NULL DEFAULT '',
  ip           TEXT NOT NULL DEFAULT '',
  version      TEXT NOT NULL DEFAULT '',
  os           TEXT NOT NULL DEFAULT '',
  arch         TEXT NOT NULL DEFAULT '',
  connect_host TEXT NOT NULL DEFAULT '',
  tunnel_port  INTEGER NOT NULL DEFAULT 0,
  first_seen   INTEGER NOT NULL,
  last_seen    INTEGER NOT NULL,
  UNIQUE(group_id, uid)
);
CREATE TABLE IF NOT EXISTS rules (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id        INTEGER NOT NULL,
  name           TEXT NOT NULL DEFAULT '',
  in_group       INTEGER NOT NULL,
  out_group      INTEGER NOT NULL DEFAULT 0,
  listen_port    INTEGER NOT NULL,
  proto          TEXT NOT NULL DEFAULT 'tcp+udp',
  targets        TEXT NOT NULL DEFAULT '[]',
  lb             TEXT NOT NULL DEFAULT 'round_robin',
  proxy_protocol INTEGER NOT NULL DEFAULT 0,
  speed_limit    INTEGER NOT NULL DEFAULT 0,
  conn_limit     INTEGER NOT NULL DEFAULT 0,
  ip_limit       INTEGER NOT NULL DEFAULT 0,
  paused         INTEGER NOT NULL DEFAULT 0,
  traffic_up     INTEGER NOT NULL DEFAULT 0,
  traffic_down   INTEGER NOT NULL DEFAULT 0,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL,
  UNIQUE(in_group, listen_port)
);
CREATE INDEX IF NOT EXISTS idx_rules_user ON rules(user_id);
CREATE INDEX IF NOT EXISTS idx_rules_out ON rules(out_group);
CREATE TABLE IF NOT EXISTS plans (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  price       INTEGER NOT NULL DEFAULT 0,
  traffic     INTEGER NOT NULL DEFAULT 0,
  days        INTEGER NOT NULL DEFAULT 30,
  max_rules   INTEGER NOT NULL DEFAULT 10,
  speed_limit INTEGER NOT NULL DEFAULT 0,
  conn_limit  INTEGER NOT NULL DEFAULT 0,
  ip_limit    INTEGER NOT NULL DEFAULT 0,
  groups      TEXT NOT NULL DEFAULT '[]',
  hidden      INTEGER NOT NULL DEFAULT 0,
  sort        INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  order_no   TEXT NOT NULL UNIQUE,
  user_id    INTEGER NOT NULL,
  type       TEXT NOT NULL,
  plan_id    INTEGER NOT NULL DEFAULT 0,
  amount     INTEGER NOT NULL DEFAULT 0,
  status     TEXT NOT NULL DEFAULT 'pending',
  pay_method TEXT NOT NULL DEFAULT '',
  trade_no   TEXT NOT NULL DEFAULT '',
  note       TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  paid_at    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id);
CREATE TABLE IF NOT EXISTS redeem_codes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  code       TEXT NOT NULL UNIQUE,
  type       TEXT NOT NULL,
  amount     INTEGER NOT NULL DEFAULT 0,
  plan_id    INTEGER NOT NULL DEFAULT 0,
  used_by    INTEGER NOT NULL DEFAULT 0,
  used_at    INTEGER NOT NULL DEFAULT 0,
  note       TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS traffic_hourly (
  user_id INTEGER NOT NULL,
  hour    INTEGER NOT NULL,
  up      INTEGER NOT NULL DEFAULT 0,
  down    INTEGER NOT NULL DEFAULT 0,
  billed  INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(user_id, hour)
);
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`

func openDB(dir string) (*sql.DB, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.ToSlash(filepath.Join(dir, "kaze.db")) +
		"?_pragma=busy_timeout(8000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("初始化数据库失败: %w", err)
	}
	return db, nil
}

func now() int64 { return time.Now().Unix() }

// ---- 模型 ----

// User 是面板用户。
type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	Role         string `json:"role"`
	Balance      int64  `json:"balance"` // 分
	PlanID       int64  `json:"plan_id"`
	PlanName     string `json:"plan_name"`
	TrafficQuota int64  `json:"traffic_quota"` // 字节
	TrafficUsed  int64  `json:"traffic_used"`
	ExpireAt     int64  `json:"expire_at"` // Unix 秒,0 = 不过期
	MaxRules     int    `json:"max_rules"`
	SpeedLimit   int    `json:"speed_limit"` // Mbps
	ConnLimit    int    `json:"conn_limit"`
	IPLimit      int    `json:"ip_limit"`
	AutoRenew    bool   `json:"auto_renew"`
	Banned       bool   `json:"banned"`
	Note         string `json:"note,omitempty"`
	CreatedAt    int64  `json:"created_at"`
	RuleCount    int    `json:"rule_count"`

	password string
	tokenVer int64
}

// IsAdmin 报告是否管理员。
func (u *User) IsAdmin() bool { return u.Role == "admin" }

// Active 报告用户当前是否可以使用转发(未封禁、未过期、流量未用尽)。
func (u *User) Active() bool {
	if u.Banned {
		return false
	}
	if u.ExpireAt != 0 && u.ExpireAt <= now() {
		return false
	}
	return u.IsAdmin() || u.TrafficUsed < u.TrafficQuota
}

// activeUserSQL 与 User.Active 等价的 SQL 条件(u 为 users 表别名,参数为当前时间)。
const activeUserSQL = `u.banned=0 AND (u.expire_at=0 OR u.expire_at>?) AND (u.role='admin' OR u.traffic_used<u.traffic_quota)`

const userCols = `u.id,u.username,u.password,u.role,u.balance,u.plan_id,u.traffic_quota,u.traffic_used,u.expire_at,
u.max_rules,u.speed_limit,u.conn_limit,u.ip_limit,u.auto_renew,u.banned,u.note,u.token_ver,u.created_at,
COALESCE((SELECT name FROM plans WHERE id=u.plan_id),''),(SELECT COUNT(*) FROM rules WHERE user_id=u.id)`

type scanner interface{ Scan(dest ...any) error }

func scanUser(r scanner) (*User, error) {
	u := &User{}
	err := r.Scan(&u.ID, &u.Username, &u.password, &u.Role, &u.Balance, &u.PlanID, &u.TrafficQuota, &u.TrafficUsed,
		&u.ExpireAt, &u.MaxRules, &u.SpeedLimit, &u.ConnLimit, &u.IPLimit, &u.AutoRenew, &u.Banned, &u.Note,
		&u.tokenVer, &u.CreatedAt, &u.PlanName, &u.RuleCount)
	return u, err
}

type dbq interface {
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
	Exec(query string, args ...any) (sql.Result, error)
}

func getUser(q dbq, id int64) (*User, error) {
	return scanUser(q.QueryRow(`SELECT `+userCols+` FROM users u WHERE u.id=?`, id))
}

// GroupConfig 是设备组的详细配置(以 JSON 存储,可在界面的"高级编辑"里直接修改)。
type GroupConfig struct {
	// —— 入口组 ——
	DisplayHost      string   `json:"display_host"`      // 展示给用户的入口地址(域名或 IP)
	PortRange        string   `json:"port_range"`        // 用户可用的端口范围,如 10000-60000,443
	DirectMode       int      `json:"direct_mode"`       // 入口直出策略:0 可选 / 1 禁止直出 / 2 仅直出
	AllowedOut       []int64  `json:"allowed_out"`       // 限制可用的出口组,空 = 不限制
	BlockedProtocols []string `json:"blocked_protocols"` // http / tls / socks
	BlockedHosts     []string `json:"blocked_hosts"`     // SNI / Host 后缀黑名单
	AllowedHosts     []string `json:"allowed_hosts"`     // SNI / Host 后缀白名单
	DisableUDP       bool     `json:"disable_udp"`
	MaxFail          int      `json:"max_fail"`     // 故障转移:连续失败次数
	FailTimeout      int      `json:"fail_timeout"` // 故障转移:摘除时长(秒)

	// —— 通用 ——
	AllowPrivate bool `json:"allow_private"` // 允许转发目标为内网/本机地址

	// —— 出口组 ——
	Transport     string `json:"transport"`      // tcp / tls / ws / wss
	Mux           bool   `json:"mux"`            // 多路复用
	MuxConns      int    `json:"mux_conns"`      // 每个出口节点的复用连接数
	TunnelPort    int    `json:"tunnel_port"`    // 出口监听端口,0 = 节点自选
	ConnectHost   string `json:"connect_host"`   // 入口连接出口使用的地址(空 = 节点公网 IP)
	ConnectPort   int    `json:"connect_port"`   // 入口连接出口使用的端口(空 = 节点监听端口)
	SNI           string `json:"sni"`            // TLS SNI
	WSHost        string `json:"ws_host"`        // WebSocket Host 头
	WSPath        string `json:"ws_path"`        // WebSocket 路径
	CDN           bool   `json:"cdn"`            // CDN 模式:出口监听明文 ws,入口经 CDN 连接
	CDNTLS        bool   `json:"cdn_tls"`        // CDN 模式下入口到 CDN 是否使用 TLS(wss)
	UDPOverTCP    bool   `json:"udp_over_tcp"`   // UDP 封装进隧道流
	FailoverGroup int64  `json:"failover_group"` // 出口故障转移组

	// —— 出口组密钥材料(仅管理员可见)——
	TunnelKey string `json:"tunnel_key,omitempty"`
	CertPEM   string `json:"cert_pem,omitempty"`
	KeyPEM    string `json:"key_pem,omitempty"`
	CertPin   string `json:"cert_pin,omitempty"`
}

// Group 是设备组:入口组的多台机器共用一套入口规则,出口组的多台机器之间做负载均衡。
type Group struct {
	ID        int64       `json:"id"`
	Name      string      `json:"name"`
	Type      string      `json:"type"` // in | out
	Token     string      `json:"token,omitempty"`
	Ratio     float64     `json:"ratio"`
	Public    bool        `json:"public"`
	Sort      int         `json:"sort"`
	Note      string      `json:"note"`
	Config    GroupConfig `json:"config"`
	Traffic   int64       `json:"traffic"`
	CreatedAt int64       `json:"created_at"`
}

const groupCols = `id,name,type,token,ratio,public,sort,note,config,traffic,created_at`

func scanGroup(r scanner) (*Group, error) {
	g := &Group{}
	var cfg string
	if err := r.Scan(&g.ID, &g.Name, &g.Type, &g.Token, &g.Ratio, &g.Public, &g.Sort, &g.Note, &cfg, &g.Traffic, &g.CreatedAt); err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(cfg), &g.Config)
	return g, nil
}

func getGroup(q dbq, id int64) (*Group, error) {
	return scanGroup(q.QueryRow(`SELECT `+groupCols+` FROM device_groups WHERE id=?`, id))
}

func listGroups(q dbq) ([]*Group, error) {
	rows, err := q.Query(`SELECT ` + groupCols + ` FROM device_groups ORDER BY sort, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// Node 是对接到某个设备组的一台机器。
type Node struct {
	ID          int64  `json:"id"`
	GroupID     int64  `json:"group_id"`
	UID         string `json:"uid"`
	Hostname    string `json:"hostname"`
	IP          string `json:"ip"`
	Version     string `json:"version"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	ConnectHost string `json:"connect_host"`
	TunnelPort  int    `json:"tunnel_port"`
	FirstSeen   int64  `json:"first_seen"`
	LastSeen    int64  `json:"last_seen"`
}

const nodeCols = `id,group_id,uid,hostname,ip,version,os,arch,connect_host,tunnel_port,first_seen,last_seen`

func scanNode(r scanner) (*Node, error) {
	n := &Node{}
	err := r.Scan(&n.ID, &n.GroupID, &n.UID, &n.Hostname, &n.IP, &n.Version, &n.OS, &n.Arch, &n.ConnectHost,
		&n.TunnelPort, &n.FirstSeen, &n.LastSeen)
	return n, err
}

func listNodes(q dbq, where string, args ...any) ([]*Node, error) {
	rows, err := q.Query(`SELECT `+nodeCols+` FROM nodes `+where+` ORDER BY group_id, id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// Rule 是一条转发规则。
type Rule struct {
	ID            int64    `json:"id"`
	UserID        int64    `json:"user_id"`
	Username      string   `json:"username,omitempty"`
	Name          string   `json:"name"`
	InGroup       int64    `json:"in_group"`
	OutGroup      int64    `json:"out_group"` // 0 = 入口直出
	ListenPort    int      `json:"listen_port"`
	Proto         string   `json:"proto"`
	Targets       []string `json:"targets"`
	LB            string   `json:"lb"`
	ProxyProtocol int      `json:"proxy_protocol"`
	SpeedLimit    int      `json:"speed_limit"` // Mbps
	ConnLimit     int      `json:"conn_limit"`
	IPLimit       int      `json:"ip_limit"`
	Paused        bool     `json:"paused"`
	TrafficUp     int64    `json:"traffic_up"`
	TrafficDown   int64    `json:"traffic_down"`
	CreatedAt     int64    `json:"created_at"`
	UpdatedAt     int64    `json:"updated_at"`

	Status string `json:"status"` // ok / paused / inactive / offline / error
	Error  string `json:"error,omitempty"`
}

const ruleCols = `r.id,r.user_id,r.name,r.in_group,r.out_group,r.listen_port,r.proto,r.targets,r.lb,r.proxy_protocol,
r.speed_limit,r.conn_limit,r.ip_limit,r.paused,r.traffic_up,r.traffic_down,r.created_at,r.updated_at`

func scanRule(r scanner, extra ...any) (*Rule, error) {
	x := &Rule{}
	var targets string
	dest := []any{&x.ID, &x.UserID, &x.Name, &x.InGroup, &x.OutGroup, &x.ListenPort, &x.Proto, &targets, &x.LB,
		&x.ProxyProtocol, &x.SpeedLimit, &x.ConnLimit, &x.IPLimit, &x.Paused, &x.TrafficUp, &x.TrafficDown,
		&x.CreatedAt, &x.UpdatedAt}
	if err := r.Scan(append(dest, extra...)...); err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(targets), &x.Targets)
	return x, nil
}

func getRule(q dbq, id int64) (*Rule, error) {
	return scanRule(q.QueryRow(`SELECT `+ruleCols+` FROM rules r WHERE r.id=?`, id))
}

// Plan 是商城套餐。
type Plan struct {
	ID          int64   `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Price       int64   `json:"price"`   // 分
	Traffic     int64   `json:"traffic"` // 字节
	Days        int     `json:"days"`    // 0 = 不限期
	MaxRules    int     `json:"max_rules"`
	SpeedLimit  int     `json:"speed_limit"`
	ConnLimit   int     `json:"conn_limit"`
	IPLimit     int     `json:"ip_limit"`
	Groups      []int64 `json:"groups"` // 额外授权的非公开设备组
	Hidden      bool    `json:"hidden"`
	Sort        int     `json:"sort"`
	CreatedAt   int64   `json:"created_at"`
}

const planCols = `id,name,description,price,traffic,days,max_rules,speed_limit,conn_limit,ip_limit,groups,hidden,sort,created_at`

func scanPlan(r scanner) (*Plan, error) {
	p := &Plan{}
	var groups string
	if err := r.Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.Traffic, &p.Days, &p.MaxRules, &p.SpeedLimit,
		&p.ConnLimit, &p.IPLimit, &groups, &p.Hidden, &p.Sort, &p.CreatedAt); err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(groups), &p.Groups)
	if p.Groups == nil {
		p.Groups = []int64{}
	}
	return p, nil
}

func getPlan(q dbq, id int64) (*Plan, error) {
	return scanPlan(q.QueryRow(`SELECT `+planCols+` FROM plans WHERE id=?`, id))
}

func listPlans(q dbq, includeHidden bool) ([]*Plan, error) {
	where := ""
	if !includeHidden {
		where = " WHERE hidden=0"
	}
	rows, err := q.Query(`SELECT ` + planCols + ` FROM plans` + where + ` ORDER BY sort, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Plan{}
	for rows.Next() {
		p, err := scanPlan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Order 是订单(购买套餐、充值、兑换、管理员调整)。
type Order struct {
	ID        int64  `json:"id"`
	OrderNo   string `json:"order_no"`
	UserID    int64  `json:"user_id"`
	Username  string `json:"username,omitempty"`
	Type      string `json:"type"` // plan / recharge / redeem / renew / admin
	PlanID    int64  `json:"plan_id"`
	Amount    int64  `json:"amount"`
	Status    string `json:"status"` // pending / paid / cancelled
	PayMethod string `json:"pay_method"`
	TradeNo   string `json:"trade_no"`
	Note      string `json:"note"`
	CreatedAt int64  `json:"created_at"`
	PaidAt    int64  `json:"paid_at"`
}

// ---- 设置 ----

func (s *Server) setting(key, def string) string {
	s.setMu.RLock()
	v, ok := s.settings[key]
	s.setMu.RUnlock()
	if !ok || v == "" {
		return def
	}
	return v
}

func (s *Server) loadSettings() error {
	rows, err := s.db.Query(`SELECT key,value FROM settings`)
	if err != nil {
		return err
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		m[k] = v
	}
	s.setMu.Lock()
	s.settings = m
	s.setMu.Unlock()
	return rows.Err()
}

func (s *Server) setSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	if err == nil {
		s.setMu.Lock()
		s.settings[key] = value
		s.setMu.Unlock()
	}
	return err
}

// parsePortRange 解析 "10000-60000,443" 形式的端口范围。
func parsePortRange(s string) ([][2]int, error) {
	var out [][2]int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var a, b int
		if strings.Contains(part, "-") {
			if _, err := fmt.Sscanf(part, "%d-%d", &a, &b); err != nil {
				return nil, fmt.Errorf("端口范围格式错误: %s", part)
			}
		} else {
			if _, err := fmt.Sscanf(part, "%d", &a); err != nil {
				return nil, fmt.Errorf("端口范围格式错误: %s", part)
			}
			b = a
		}
		if a < 1 || b > 65535 || a > b {
			return nil, fmt.Errorf("端口范围无效: %s", part)
		}
		out = append(out, [2]int{a, b})
	}
	return out, nil
}

func portInRange(rs [][2]int, p int) bool {
	for _, r := range rs {
		if p >= r[0] && p <= r[1] {
			return true
		}
	}
	return false
}
