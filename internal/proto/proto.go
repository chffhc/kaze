// Package proto 定义面板与节点之间的控制面协议(JSON over WebSocket)。
//
// 节点主动连接面板 /api/node/ws,首帧发送 hello,之后:
//
//	面板 -> 节点: config(完整配置快照) / ack(流量上报确认) / diag(诊断请求)
//	节点 -> 面板: report(流量增量) / metrics(探针) / status(规则同步状态) / diag_result
package proto

import "encoding/json"

// Version 是面板与节点共用的版本号。
const Version = "1.1.0"

// 消息类型
const (
	THello      = "hello"
	TConfig     = "config"
	TReport     = "report" // legacy
	TReportV2   = "report_v2"
	TAck        = "ack"
	TMetrics    = "metrics"
	TStatus     = "status"
	TDiag       = "diag"
	TDiagResult = "diag_result"
)

// 设备组类型。节点只会以 in / out 两种角色运行;chain 是面板侧的"链式出口",没有自己的节点。
const (
	RoleIn    = "in"
	RoleOut   = "out"
	RoleChain = "chain"
)

// TLS 入站模式
const (
	TLSModeAlone  = "tls"    // 规则独占一个端口,入口在该端口上终结 TLS
	TLSModeParent = "parent" // 母规则:监听端口并终结 TLS,按 SNI 分流给子规则(自身不转发)
	TLSModeChild  = "child"  // 子规则:不监听端口,挂在母规则的端口上,按 SNI 匹配
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
	RevPort     int    `json:"rev_port"`     // 入口:反向隧道监听端口(可选,出口主动连入)
}

// TunnelSpec 描述入口如何连接某个出口组。
type TunnelSpec struct {
	GroupID    int64       `json:"group_id"`
	Endpoints  []string    `json:"endpoints"`          // 出口节点地址 host:port
	Transport  string      `json:"transport"`          // tcp | tls | ws | wss | http
	Mux        bool        `json:"mux"`                // 多路复用(ws/wss 恒为 true)
	MuxConns   int         `json:"mux_conns"`          // 每个出口节点保持的复用连接数
	Key        string      `json:"key"`                // 预共享密钥(hex)
	SNI        string      `json:"sni,omitempty"`      // TLS SNI
	Host       string      `json:"host,omitempty"`     // WS Host 头
	Path       string      `json:"path,omitempty"`     // WS 路径
	CertPin    string      `json:"cert_pin,omitempty"` // 出口证书 SHA-256 指纹(hex);为空则走系统 CA 校验(CDN 模式)
	UDPOverTCP bool        `json:"udp_over_tcp"`       // UDP 走隧道流;否则走原生 UDP 加密通道
	Fallback   *TunnelSpec `json:"fallback,omitempty"` // 故障转移组

	// Fingerprint 让 tls / wss 的 ClientHello 模拟指定浏览器(utls):
	// chrome / firefox / safari / ios / android / edge / 360 / qq;为空则使用 Go 自身的握手特征。
	Fingerprint string `json:"fp,omitempty"`
	// Reverse 表示这条隧道由出口主动拨入(反向隧道):入口不再连接 Endpoints,而是在出口保持的连接上开流。
	Reverse bool `json:"reverse,omitempty"`
}

// TLSInbound 是规则的 TLS 入站设置:入口终结 TLS,把内层明文流量交给后续链路。
type TLSInbound struct {
	Mode    string   `json:"mode"`           // tls / parent / child
	SNI     []string `json:"sni,omitempty"`  // 只接受这些 SNI(小写);子规则必填,独占端口时为空表示不校验
	ALPN    []string `json:"alpn,omitempty"` // 非空时与客户端协商 ALPN,没有交集则握手失败
	CertPEM string   `json:"cert,omitempty"` // 为空时节点自动生成自签名证书
	KeyPEM  string   `json:"key,omitempty"`
}

// OriginTLS 表示连接转发目标时再套一层 TLS(TLS 入站规则的"回源加密")。
type OriginTLS struct {
	SNI    string `json:"sni,omitempty"` // 为空则使用目标主机名
	Verify bool   `json:"verify"`        // 是否校验目标证书
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

	TLS              *TLSInbound `json:"tls,omitempty"`               // TLS 入站;子规则的 ListenPort 是母规则的端口
	OriginTLS        *OriginTLS  `json:"origin_tls,omitempty"`        // 回源 TLS:直出时由入口执行;经隧道时由最后一跳执行,入口只据此决定是否传递 ALPN
	RouteFingerprint string      `json:"route_fingerprint,omitempty"` // invalidates established streams when the remote route changes
	UDPStream        bool        `json:"udp_stream,omitempty"`        // UDP 必须封装进隧道流(链式出口)
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

	TLSRejectEmptySNI bool           `json:"tls_reject_empty_sni,omitempty"` // TLS 入站:拒绝不带 SNI 的握手(防扫描)
	Reverse           *ReverseListen `json:"reverse,omitempty"`              // 反向隧道;只下发给以 -rev-port 启动的入口
}

// ReverseListen 是入口接受反向隧道所需的材料。
type ReverseListen struct {
	CertPEM string           `json:"cert"`
	KeyPEM  string           `json:"cert_key"`
	Groups  map[int64]string `json:"groups"` // 允许拨入的出口组 -> 该组的隧道密钥(hex)
}

// ReverseSpec 告诉出口去连接哪个入口节点的反向隧道端口。
type ReverseSpec struct {
	Endpoint    string `json:"endpoint"` // 入口节点 host:rev_port
	CertPin     string `json:"cert_pin"` // 入口组反向隧道证书的 SHA-256 指纹
	SNI         string `json:"sni,omitempty"`
	Fingerprint string `json:"fp,omitempty"`
	Conns       int    `json:"conns,omitempty"` // 保持的连接数,默认 2
}

// OutRule 是下发给出口节点的规则(出口负责连接目标)。
type OutRule struct {
	ID            int64    `json:"id"`
	Targets       []string `json:"targets"`
	LB            string   `json:"lb"`
	ProxyProtocol int      `json:"pp"`

	Next      int64      `json:"next,omitempty"`       // 链式出口:非 0 时本跳不连接目标,而是把流转给 Tunnels[Next]
	OriginTLS *OriginTLS `json:"origin_tls,omitempty"` // 连接目标时再套一层 TLS
}

// OutboundConfig 是出口节点的配置。
type OutboundConfig struct {
	ListenPort   int       `json:"listen_port"` // 0 = 节点自选并上报
	Transport    string    `json:"transport"`   // tcp | tls | ws | wss | http
	Key          string    `json:"key"`
	CertPEM      string    `json:"cert,omitempty"`
	KeyPEM       string    `json:"cert_key,omitempty"`
	Path         string    `json:"path,omitempty"`
	Rules        []OutRule `json:"rules"`
	AllowPrivate bool      `json:"allow_private"`
	MaxFail      int       `json:"max_fail"`
	FailTimeout  int       `json:"fail_timeout"`

	Tunnels map[int64]*TunnelSpec `json:"tunnels,omitempty"` // 链式出口:到下一跳的隧道;键由面板分配,节点不解释其含义
	Reverse []ReverseSpec         `json:"reverse,omitempty"` // 反向隧道:需要主动拨入的入口节点
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
	Stream string    `json:"stream,omitempty"`
	Seq    int64     `json:"seq"`
	Items  []Traffic `json:"items"`
}

// Ack 确认一次流量上报。
type Ack struct {
	Stream string `json:"stream,omitempty"`
	Seq    int64  `json:"seq"`
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

	// 反向隧道。入口:允许拨入的出口组数 / 其中已有连接的组数;出口:需要拨入的入口节点数 / 其中已连上的个数。
	RevTotal int `json:"rev_total,omitempty"`
	RevUp    int `json:"rev_up,omitempty"`
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
