// Package proto 定义面板与节点之间的控制面协议(JSON over WebSocket)。
//
// 节点主动连接面板 /api/node/ws,首帧发送 hello,之后:
//
//	面板 -> 节点: config(完整配置快照) / ack(流量上报确认) / diag(诊断请求)
//	节点 -> 面板: report(流量增量) / metrics(探针) / status(规则同步状态) / diag_result
package proto

import "encoding/json"

// Version 是面板与节点共用的版本号。
const Version = "1.0.0"

// 消息类型
const (
	THello      = "hello"
	TConfig     = "config"
	TReport     = "report"
	TAck        = "ack"
	TMetrics    = "metrics"
	TStatus     = "status"
	TDiag       = "diag"
	TDiagResult = "diag_result"
)

// 设备组角色
const (
	RoleIn  = "in"
	RoleOut = "out"
)

// Msg 是控制连接上的信封。
type Msg struct {
	T string          `json:"t"`
	D json.RawMessage `json:"d,omitempty"`
}

// Pack 把任意负载打包成一帧消息。
func Pack(t string, v any) []byte {
	var raw json.RawMessage
	if v != nil {
		raw, _ = json.Marshal(v)
	}
	b, _ := json.Marshal(Msg{T: t, D: raw})
	return b
}

// Hello 是节点上线后的第一帧。
type Hello struct {
	UID         string `json:"uid"`          // 节点实例唯一 ID(持久化在本地)
	Hostname    string `json:"hostname"`     // 主机名
	Version     string `json:"version"`      // 节点端版本
	OS          string `json:"os"`           //
	Arch        string `json:"arch"`         //
	ConnectHost string `json:"connect_host"` // 出口:入口连接本机使用的地址(可选,专线内网 IP 等)
	TunnelPort  int    `json:"tunnel_port"`  // 出口:命令行指定的隧道监听端口(可选)
}

// TunnelSpec 描述入口如何连接某个出口组。
type TunnelSpec struct {
	GroupID    int64       `json:"group_id"`
	Endpoints  []string    `json:"endpoints"`          // 出口节点地址 host:port
	Transport  string      `json:"transport"`          // tcp | tls | ws | wss
	Mux        bool        `json:"mux"`                // 多路复用(ws/wss 恒为 true)
	MuxConns   int         `json:"mux_conns"`          // 每个出口节点保持的复用连接数
	Key        string      `json:"key"`                // 预共享密钥(hex)
	SNI        string      `json:"sni,omitempty"`      // TLS SNI
	Host       string      `json:"host,omitempty"`     // WS Host 头
	Path       string      `json:"path,omitempty"`     // WS 路径
	CertPin    string      `json:"cert_pin,omitempty"` // 出口证书 SHA-256 指纹(hex);为空则走系统 CA 校验(CDN 模式)
	UDPOverTCP bool        `json:"udp_over_tcp"`       // UDP 走隧道流;否则走原生 UDP 加密通道
	Fallback   *TunnelSpec `json:"fallback,omitempty"` // 故障转移组
}

// Rule 是下发给入口节点的一条转发规则。
type Rule struct {
	ID            int64    `json:"id"`
	UserID        int64    `json:"uid"`
	ListenPort    int      `json:"port"`
	Proto         string   `json:"proto"`   // tcp | udp | tcp+udp
	OutGroup      int64    `json:"out"`     // 0 = 入口直出
	Targets       []string `json:"targets"` // 仅直出时由入口使用
	LB            string   `json:"lb"`      // round_robin | random | least_conn | ip_hash | failover
	ProxyProtocol int      `json:"pp"`      // 0 关闭 / 1 / 2
	SpeedLimit    int64    `json:"speed"`   // 规则级限速,字节/秒,0 不限
	ConnLimit     int      `json:"conns"`   // 规则级连接数限制
	IPLimit       int      `json:"ips"`     // 规则级 IP 数限制
}

// UserLimit 是用户级限制(同一入口节点上该用户的所有规则共享)。
type UserLimit struct {
	SpeedLimit int64 `json:"speed"`
	ConnLimit  int   `json:"conns"`
	IPLimit    int   `json:"ips"`
}

// InboundConfig 是入口节点的配置。
type InboundConfig struct {
	Rules            []Rule                `json:"rules"`
	Users            map[int64]UserLimit   `json:"users"`
	Tunnels          map[int64]*TunnelSpec `json:"tunnels"`
	BlockedProtocols []string              `json:"blocked_protocols,omitempty"` // http | tls | socks
	BlockedHosts     []string              `json:"blocked_hosts,omitempty"`     // SNI / Host 后缀黑名单
	AllowedHosts     []string              `json:"allowed_hosts,omitempty"`     // SNI / Host 后缀白名单
	AllowPrivate     bool                  `json:"allow_private"`               // 直出时是否允许目标为内网/本机地址
	DisableUDP       bool                  `json:"disable_udp"`
	MaxFail          int                   `json:"max_fail"`
	FailTimeout      int                   `json:"fail_timeout"`
}

// OutRule 是下发给出口节点的规则(出口负责连接目标)。
type OutRule struct {
	ID            int64    `json:"id"`
	Targets       []string `json:"targets"`
	LB            string   `json:"lb"`
	ProxyProtocol int      `json:"pp"`
}

// OutboundConfig 是出口节点的配置。
type OutboundConfig struct {
	ListenPort   int       `json:"listen_port"` // 0 = 节点自选并上报
	Transport    string    `json:"transport"`   // tcp | tls | ws | wss
	Key          string    `json:"key"`
	CertPEM      string    `json:"cert,omitempty"`
	KeyPEM       string    `json:"cert_key,omitempty"`
	Path         string    `json:"path,omitempty"`
	Rules        []OutRule `json:"rules"`
	AllowPrivate bool      `json:"allow_private"`
	MaxFail      int       `json:"max_fail"`
	FailTimeout  int       `json:"fail_timeout"`
}

// NodeConfig 是面板推送的完整配置快照。
type NodeConfig struct {
	Version        int64           `json:"version"`
	Now            int64           `json:"now"` // 面板时间(毫秒),节点据此校准隧道鉴权时钟
	Role           string          `json:"role"`
	GroupID        int64           `json:"group_id"`
	ReportInterval int             `json:"report_interval"` // 流量上报间隔(秒)
	Inbound        *InboundConfig  `json:"inbound,omitempty"`
	Outbound       *OutboundConfig `json:"outbound,omitempty"`
}

// Traffic 是一条规则的流量增量。
type Traffic struct {
	RuleID int64 `json:"id"`
	Up     int64 `json:"up"`   // 客户端 -> 目标
	Down   int64 `json:"down"` // 目标 -> 客户端
}

// Report 是流量上报;面板以 ack{seq} 确认,未确认的会重发。
type Report struct {
	Seq   int64     `json:"seq"`
	Items []Traffic `json:"items"`
}

// Ack 确认一次流量上报。
type Ack struct {
	Seq int64 `json:"seq"`
}

// Metrics 是探针数据。
type Metrics struct {
	CPU       float64 `json:"cpu"`        // 0-100
	MemUsed   uint64  `json:"mem_used"`   // 字节
	MemTotal  uint64  `json:"mem_total"`  //
	DiskUsed  uint64  `json:"disk_used"`  //
	DiskTotal uint64  `json:"disk_total"` //
	Load1     float64 `json:"load1"`      //
	NetRx     uint64  `json:"net_rx"`     // 网卡累计接收
	NetTx     uint64  `json:"net_tx"`     // 网卡累计发送
	RxRate    uint64  `json:"rx_rate"`    // 字节/秒
	TxRate    uint64  `json:"tx_rate"`    //
	Uptime    uint64  `json:"uptime"`     // 秒
	TCPConns  int64   `json:"tcp_conns"`  // 当前转发中的 TCP 连接
	UDPSess   int64   `json:"udp_sess"`   // 当前 UDP 会话
	Goroutine int     `json:"goroutines"` //
}

// Status 上报规则同步结果与出口实际监听端口。
type Status struct {
	ConfigVersion int64            `json:"config_version"`
	TunnelPort    int              `json:"tunnel_port,omitempty"` // 出口实际监听端口
	RuleErrors    map[int64]string `json:"rule_errors,omitempty"` // 同步失败的规则(如端口被占用)
}

// Diag 是面板发起的诊断请求。
type Diag struct {
	ID     string `json:"id"`
	RuleID int64  `json:"rule_id"`
}

// DiagHop 是诊断中的一跳。
type DiagHop struct {
	From  string  `json:"from"`
	To    string  `json:"to"`
	Ms    float64 `json:"ms"`
	Error string  `json:"error,omitempty"`
}

// DiagResult 是节点返回的诊断结果。
type DiagResult struct {
	ID   string    `json:"id"`
	Hops []DiagHop `json:"hops"`
}
