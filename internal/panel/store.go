// Package panel 是面板端:REST API、SQLite 存储、节点 Hub、计费与内嵌的 Web 界面。
package panel

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"kaze/internal/proto"
)

// 数据库结构版本(PRAGMA user_version)。
//
//	0 / 1  1.0.x:rules 表带 UNIQUE(in_group, listen_port)
//	2      1.1.0:rules 增加 TLS 入站字段,端口唯一性改为"子规则除外"的部分唯一索引;nodes 增加 rev_port
//	3      增加流量上报游标和未归属流量表
//	4      保留删除和移组规则的计费归属
const schemaVersion = 4

const ruleBillingDDL = `
CREATE TABLE IF NOT EXISTS rule_billing_history (
  rule_id INTEGER NOT NULL, in_group INTEGER NOT NULL, user_id INTEGER NOT NULL,
  out_group INTEGER NOT NULL, ratio REAL NOT NULL, hops TEXT NOT NULL,
  PRIMARY KEY(rule_id,in_group)
) WITHOUT ROWID;
CREATE TRIGGER IF NOT EXISTS rule_billing_before_move
BEFORE UPDATE OF in_group ON rules WHEN OLD.in_group <> NEW.in_group
BEGIN
  INSERT OR REPLACE INTO rule_billing_history
  SELECT OLD.id, OLD.in_group, OLD.user_id, OLD.out_group,
    COALESCE((SELECT SUM(ratio) FROM device_groups WHERE id=OLD.in_group OR id=OLD.out_group),1),
    COALESCE((SELECT json_extract(config,'$.chain_hops') FROM device_groups
      WHERE id=OLD.out_group AND type='chain' AND json_valid(config)),'[]');
END;
CREATE TRIGGER IF NOT EXISTS rule_billing_before_delete
BEFORE DELETE ON rules
BEGIN
  INSERT OR REPLACE INTO rule_billing_history
  SELECT OLD.id, OLD.in_group, OLD.user_id, OLD.out_group,
    COALESCE((SELECT SUM(ratio) FROM device_groups WHERE id=OLD.in_group OR id=OLD.out_group),1),
    COALESCE((SELECT json_extract(config,'$.chain_hops') FROM device_groups
      WHERE id=OLD.out_group AND type='chain' AND json_valid(config)),'[]');
END;
`

const trafficDDL = `
-- One durable cursor per ingress node / reporting stream, independent of node retention.
CREATE TABLE IF NOT EXISTS traffic_unattributed (
 group_id INTEGER NOT NULL, uid TEXT NOT NULL, stream TEXT NOT NULL,
 seq INTEGER NOT NULL, rule_id INTEGER NOT NULL, up INTEGER NOT NULL, down INTEGER NOT NULL, hour INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS traffic_cursors (
 group_id INTEGER NOT NULL, uid TEXT NOT NULL, stream TEXT NOT NULL,
 seq INTEGER NOT NULL, digest BLOB NOT NULL,
 PRIMARY KEY(group_id,uid,stream)
) WITHOUT ROWID;
`

const schemaBase = `
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
` + trafficDDL + `
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
  rev_port     INTEGER NOT NULL DEFAULT 0,
  UNIQUE(group_id, uid)
);
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

// rulesDDL 返回 rules 表的建表语句(全新安装与升级迁移共用同一份定义)。
// 子规则(tls_mode='child')不监听端口,listen_port 存的是所挂母规则的端口,因此可以重复。
func rulesDDL(table string) string {
	return `CREATE TABLE ` + table + ` (
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
  tls_mode       TEXT NOT NULL DEFAULT '',
  tls_config     TEXT NOT NULL DEFAULT '{}'
);`
}

// 1.0.x 的 rules 表里就有的列,迁移时原样拷贝。
const rulesV1Cols = `id,user_id,name,in_group,out_group,listen_port,proto,targets,lb,proxy_protocol,
speed_limit,conn_limit,ip_limit,paused,traffic_up,traffic_down,created_at,updated_at`

const rulesIndexes = `
CREATE INDEX idx_rules_user ON rules(user_id);
CREATE INDEX idx_rules_out ON rules(out_group);
CREATE UNIQUE INDEX idx_rules_port ON rules(in_group, listen_port) WHERE tls_mode<>'child';
CREATE INDEX idx_rules_child ON rules(in_group, listen_port) WHERE tls_mode='child';
`

func openDB(dir string) (*sql.DB, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.ToSlash(filepath.Join(dir, "kaze.db")) +
		"?_pragma=busy_timeout(8000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	if err := migrate(db, dir); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// migrate 把数据库带到当前的结构版本:全新安装直接建表;旧版本逐级升级,升级前先留一份备份。
func migrate(db *sql.DB, dir string) error {
	var ver, hasRules int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&ver); err != nil {
		return fmt.Errorf("读取数据库版本失败: %w", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rules'`).Scan(&hasRules); err != nil {
		return fmt.Errorf("读取数据库结构失败: %w", err)
	}
	switch {
	case ver > schemaVersion:
		return fmt.Errorf("数据库是由更新版本的面板创建的(结构版本 %d,本程序最高支持 %d),请使用对应版本的面板", ver, schemaVersion)
	case ver == schemaVersion:
		return nil
	case hasRules == 0: // 全新安装
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err := tx.Exec(schemaBase + rulesDDL("rules") + rulesIndexes + ruleBillingDDL + fmt.Sprintf("PRAGMA user_version = %d;", schemaVersion)); err != nil {
			return fmt.Errorf("初始化数据库失败: %w", err)
		}
		return tx.Commit()
	}

	backup := filepath.Join(dir, fmt.Sprintf("kaze.db.v%d.bak", max(ver, 1)))
	if _, err := os.Stat(backup); os.IsNotExist(err) {
		// VACUUM INTO 得到一份一致的快照(直接拷贝文件会漏掉 WAL 里尚未合并的内容)
		if _, err := db.Exec(`VACUUM INTO ?`, backup); err != nil {
			return fmt.Errorf("升级前备份数据库失败: %w", err)
		}
	}
	var err error
	if ver >= 2 {
		err = migrateLedger(db)
	} else {
		err = migrateV2(db)
	}
	if err != nil {
		return fmt.Errorf("升级数据库结构失败(数据未改动,备份在 %s): %w", backup, err)
	}
	log.Printf("数据库结构已升级到版本 %d,升级前的备份保存在 %s", schemaVersion, backup)
	return nil
}

func migrateLedger(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(trafficDDL + ruleBillingDDL + fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return err
	}
	return tx.Commit()
}

// migrateV2 重建 rules 表(SQLite 不能直接去掉表级的 UNIQUE 约束)并给 nodes 加列,整个过程在一个事务里。
func migrateV2(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// 规则号会出现在隧道流头和流量上报里,不能因为重建表而被复用:记下自增计数,重建后写回去。
	var oldSeq int64
	tx.QueryRow(`SELECT seq FROM sqlite_sequence WHERE name='rules'`).Scan(&oldSeq)
	var before int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM rules`).Scan(&before); err != nil {
		return err
	}
	if _, err := tx.Exec(schemaBase + `DROP TABLE IF EXISTS rules_v2;` + rulesDDL("rules_v2") +
		`INSERT INTO rules_v2(` + rulesV1Cols + `) SELECT ` + rulesV1Cols + ` FROM rules;
		DROP TABLE rules;
		ALTER TABLE rules_v2 RENAME TO rules;` + rulesIndexes + ruleBillingDDL); err != nil {
		return err
	}
	var after int
	var maxID int64
	if err := tx.QueryRow(`SELECT COUNT(*), COALESCE(MAX(id),0) FROM rules`).Scan(&after, &maxID); err != nil {
		return err
	}
	if after != before {
		return fmt.Errorf("规则数量在迁移前后不一致(%d -> %d)", before, after)
	}
	if _, err := tx.Exec(`DELETE FROM sqlite_sequence WHERE name='rules'`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO sqlite_sequence(name, seq) VALUES('rules', ?)`, max(oldSeq, maxID)); err != nil {
		return err
	}
	var hasRev int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('nodes') WHERE name='rev_port'`).Scan(&hasRev); err != nil {
		return err
	}
	if hasRev == 0 {
		if _, err := tx.Exec(`ALTER TABLE nodes ADD COLUMN rev_port INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
		return err
	}
	return tx.Commit()
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
	if u.IsAdmin() {
		return true
	}
	if u.ExpireAt != 0 && u.ExpireAt <= now() {
		return false
	}
	return u.TrafficUsed < u.TrafficQuota
}

// activeUserSQL 与 User.Active 等价的 SQL 条件(u 为 users 表别名,参数为当前时间)。
const activeUserSQL = `u.banned=0 AND (u.role='admin' OR ((u.expire_at=0 OR u.expire_at>?) AND u.traffic_used<u.traffic_quota))`

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

	// —— 入口组:TLS 入站 ——
	TLSInboundPolicy  int  `json:"tls_inbound_policy"`   // 0 不限制 / 1 用户只能建 TLS 入站规则 / 2 用户只能建子规则(共享管理员的 TLS 端口)
	TLSRejectEmptySNI bool `json:"tls_reject_empty_sni"` // TLS 入站拒绝不带 SNI 的握手

	// —— 入口组:反向隧道(出口主动连入本组里以 -rev-port 启动的机器)——
	ReverseGroups []int64 `json:"reverse_groups"` // 走反向隧道的出口组;[0] = 全部,[0,3,4] = 除 3、4 以外的全部
	ReverseSNI    string  `json:"reverse_sni"`    // 出口拨入时使用的 TLS SNI
	ReverseConns  int     `json:"reverse_conns"`  // 每台出口到每台入口保持的连接数

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
	Fingerprint   string `json:"fingerprint"`    // tls / wss 握手模拟的浏览器指纹(utls),空 = 不伪装

	// —— 链式出口 ——
	ChainHops []int64 `json:"chain_hops"` // 依次经过的出口组(2~3 个)
	ChainMux  bool    `json:"chain_mux"`  // 各跳之间是否多路复用(入口到第一跳沿用第一跳出口组自己的设置)

	// —— 密钥材料(仅管理员可见)——
	TunnelKey  string `json:"tunnel_key,omitempty"` // 出口组:隧道预共享密钥
	CertPEM    string `json:"cert_pem,omitempty"`   // 出口组:隧道证书
	KeyPEM     string `json:"key_pem,omitempty"`
	CertPin    string `json:"cert_pin,omitempty"`
	RevCertPEM string `json:"rev_cert_pem,omitempty"` // 入口组:反向隧道证书
	RevKeyPEM  string `json:"rev_key_pem,omitempty"`
	RevCertPin string `json:"rev_cert_pin,omitempty"`
}

// matchGroupList 按"设备组列表"的约定判断 id 是否命中:
// 普通列表表示"只有这些";含 0 表示"全部",此时列表里的其它 ID 是例外。
func matchGroupList(list []int64, id int64) bool {
	all, listed := false, false
	for _, x := range list {
		if x == 0 {
			all = true
		} else if x == id {
			listed = true
		}
	}
	return all != listed
}

// Group 是设备组:入口组的多台机器共用一套入口规则,出口组的多台机器之间做负载均衡;
// 链式出口没有自己的机器,它把 2~3 个出口组串成一条用户可选的线路。
type Group struct {
	ID        int64       `json:"id"`
	Name      string      `json:"name"`
	Type      string      `json:"type"` // in | out | chain
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
	RevPort     int    `json:"rev_port"`
	FirstSeen   int64  `json:"first_seen"`
	LastSeen    int64  `json:"last_seen"`
}

const nodeCols = `id,group_id,uid,hostname,ip,version,os,arch,connect_host,tunnel_port,first_seen,last_seen,rev_port`

func scanNode(r scanner) (*Node, error) {
	n := &Node{}
	err := r.Scan(&n.ID, &n.GroupID, &n.UID, &n.Hostname, &n.IP, &n.Version, &n.OS, &n.Arch, &n.ConnectHost,
		&n.TunnelPort, &n.FirstSeen, &n.LastSeen, &n.RevPort)
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

	// TLS 入站:"" 普通规则 / tls 独占端口 / parent 母规则 / child 子规则(listen_port 是母规则的端口)
	TLSMode string  `json:"tls_mode"`
	TLS     RuleTLS `json:"tls"`

	Status string `json:"status"` // ok / paused / inactive / offline / error
	Error  string `json:"error,omitempty"`
}

// RuleTLS 是规则的 TLS 入站设置。
type RuleTLS struct {
	SNI          []string `json:"sni"`                // 允许的 SNI;子规则必填,独占端口时为空表示不校验
	ALPN         []string `json:"alpn"`               // 非空时校验并协商 ALPN
	CertPEM      string   `json:"cert_pem,omitempty"` // 留空则由入口自动生成自签名证书
	KeyPEM       string   `json:"key_pem,omitempty"`  // 不会通过接口返回
	HasKey       bool     `json:"has_key,omitempty"`  // 仅用于接口输出:已保存私钥
	OriginTLS    bool     `json:"origin_tls"`         // 最后一跳连接目标时再做一层 TLS
	OriginSNI    string   `json:"origin_sni,omitempty"`
	OriginVerify bool     `json:"origin_verify"`
}

// redact 去掉不应通过接口返回的私钥。
func (r *Rule) redact() *Rule {
	r.TLS.HasKey = r.TLS.KeyPEM != ""
	r.TLS.KeyPEM = ""
	return r
}

// originTLS 返回下发给节点的回源 TLS 设置(未开启时为 nil)。
func (r *Rule) originTLS() *proto.OriginTLS {
	if r.TLSMode == "" || r.TLSMode == proto.TLSModeParent || !r.TLS.OriginTLS {
		return nil
	}
	return &proto.OriginTLS{SNI: r.TLS.OriginSNI, Verify: r.TLS.OriginVerify}
}

// tlsInbound 返回下发给入口节点的 TLS 入站设置(普通规则为 nil)。
func (r *Rule) tlsInbound() *proto.TLSInbound {
	if r.TLSMode == "" {
		return nil
	}
	return &proto.TLSInbound{Mode: r.TLSMode, SNI: r.TLS.SNI, ALPN: r.TLS.ALPN, CertPEM: r.TLS.CertPEM, KeyPEM: r.TLS.KeyPEM}
}

const ruleCols = `r.id,r.user_id,r.name,r.in_group,r.out_group,r.listen_port,r.proto,r.targets,r.lb,r.proxy_protocol,
r.speed_limit,r.conn_limit,r.ip_limit,r.paused,r.traffic_up,r.traffic_down,r.created_at,r.updated_at,r.tls_mode,r.tls_config`

func scanRule(r scanner, extra ...any) (*Rule, error) {
	x := &Rule{}
	var targets, tlsCfg string
	dest := []any{&x.ID, &x.UserID, &x.Name, &x.InGroup, &x.OutGroup, &x.ListenPort, &x.Proto, &targets, &x.LB,
		&x.ProxyProtocol, &x.SpeedLimit, &x.ConnLimit, &x.IPLimit, &x.Paused, &x.TrafficUp, &x.TrafficDown,
		&x.CreatedAt, &x.UpdatedAt, &x.TLSMode, &tlsCfg}
	if err := r.Scan(append(dest, extra...)...); err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(targets), &x.Targets)
	json.Unmarshal([]byte(tlsCfg), &x.TLS)
	if x.Targets == nil {
		x.Targets = []string{}
	}
	if x.TLS.SNI == nil {
		x.TLS.SNI = []string{}
	}
	if x.TLS.ALPN == nil {
		x.TLS.ALPN = []string{}
	}
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
