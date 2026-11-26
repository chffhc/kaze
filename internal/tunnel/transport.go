package tunnel

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/libp2p/go-yamux/v5"
	utls "github.com/refraction-networking/utls"
)

// 传输层类型
const (
	TransportTCP  = "tcp"
	TransportTLS  = "tls"
	TransportWS   = "ws"
	TransportWSS  = "wss"
	TransportHTTP = "http"
)

const (
	dialTimeout      = 6 * time.Second
	handshakeTimeout = 10 * time.Second
	ekmLabel         = "EXPORTER-kaze-tunnel-auth"
	wsBufSize        = 64 * 1024
)

// ValidTransport 报告传输层名称是否合法。
func ValidTransport(t string) bool {
	switch t {
	case TransportTCP, TransportTLS, TransportWS, TransportWSS, TransportHTTP:
		return true
	}
	return false
}

// TransportUsesTLS 报告传输层是否自带 TLS(需要证书,可以配置 SNI 与指纹)。
func TransportUsesTLS(t string) bool { return t == TransportTLS || t == TransportWSS }

// fingerprints 是可选的 ClientHello 指纹。每个名字对应 utls 里该浏览器最新的可用预设。
var fingerprints = map[string]utls.ClientHelloID{
	"chrome":  utls.HelloChrome_Auto,
	"firefox": utls.HelloFirefox_Auto,
	"safari":  utls.HelloSafari_Auto,
	"ios":     utls.HelloIOS_Auto,
	"android": utls.HelloAndroid_11_OkHttp,
	"edge":    utls.HelloEdge_Auto,
	"360":     utls.Hello360_Auto,
	"qq":      utls.HelloQQ_Auto,
}

// Fingerprints 返回支持的指纹名称(固定顺序,供界面展示)。
func Fingerprints() []string {
	return []string{"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq"}
}

// ValidFingerprint 报告指纹名称是否合法;空字符串表示不伪装。
func ValidFingerprint(fp string) bool {
	if fp == "" {
		return true
	}
	_, ok := fingerprints[fp]
	return ok
}

// MuxWindow 是单条复用流的最大接收窗口。窗口越大,高延迟链路上的单流吞吐越高,
// 但目标读得慢时每条流最多会多缓冲这么多数据。
var MuxWindow uint32 = 4 * 1024 * 1024

// yamuxConfig 返回复用会话的配置。accept 表示本端是否接受对端开流:
// 只有处理转发的一端(出口)接受;发起转发的一端(入口)从不接受,对端开过来的流会被直接复位。
func yamuxConfig(accept bool) *yamux.Config {
	c := yamux.DefaultConfig()
	c.AcceptBacklog = 1024
	c.MaxIncomingStreams = 0
	if accept {
		c.MaxIncomingStreams = 1 << 20
	}
	c.InitialStreamWindowSize = 256 * 1024
	c.MaxStreamWindowSize = MuxWindow
	c.KeepAliveInterval = 15 * time.Second
	c.MeasureRTTInterval = 15 * time.Second
	c.ConnectionWriteTimeout = 10 * time.Second
	c.ReadBufSize = 16 * 1024
	c.LogOutput = io.Discard
	return c
}

// wsConn 把 WebSocket 连接适配成字节流 net.Conn(每次 Write 一个二进制帧)。
// 上层只会由 yamux 的单个发送协程 / 单个接收协程使用。
type wsConn struct {
	*websocket.Conn
	r   io.Reader
	wmu sync.Mutex
}

func (c *wsConn) Read(p []byte) (int, error) {
	for {
		if c.r == nil {
			mt, r, err := c.Conn.NextReader()
			if err != nil {
				return 0, err
			}
			if mt != websocket.BinaryMessage {
				continue
			}
			c.r = r
		}
		n, err := c.r.Read(p)
		if err == io.EOF {
			c.r = nil
			if n == 0 {
				continue
			}
			err = nil
		}
		return n, err
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.Conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsConn) SetDeadline(t time.Time) error {
	c.Conn.SetReadDeadline(t)
	return c.Conn.SetWriteDeadline(t)
}

var errPinMismatch = errors.New("对端证书指纹不匹配")

func checkPin(certs []*x509.Certificate, pin string) error {
	if len(certs) == 0 {
		return errors.New("对端未提供证书")
	}
	sum := sha256.Sum256(certs[0].Raw)
	if hex.EncodeToString(sum[:]) != pin {
		return errPinMismatch
	}
	return nil
}

// exportEKM 返回本次 TLS 会话的导出密钥,用来把隧道鉴权绑定到这条连接上。
// 协商到 TLS 1.2 且没有 EMS 时无法导出(个别指纹预设会如此),此时返回 nil,
// 两端都会退回到"时间戳 + 一次性随机数"的校验方式。
func exportEKM(export func(label string, context []byte, length int) ([]byte, error)) []byte {
	b, err := export(ekmLabel, nil, 32)
	if err != nil {
		return nil
	}
	return b
}

// tlsDialer 完成入口侧(以及反向隧道里出口侧)的 TLS 握手:
// 有 pin 时固定校验证书指纹,否则走系统 CA;fp 非空时用 utls 模拟对应浏览器的 ClientHello。
type tlsDialer struct {
	sni  string
	pin  string
	fp   string
	alpn []string // 为空时:标准库不发送 ALPN,指纹模式保留预设里的 ALPN
	std  *tls.Config
}

func newTLSDialer(sni, pin, fp string, alpn []string) *tlsDialer {
	d := &tlsDialer{sni: sni, pin: pin, fp: fp, alpn: alpn}
	d.std = &tls.Config{
		ServerName:         sni,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         alpn,
		ClientSessionCache: tls.NewLRUClientSessionCache(128),
	}
	if pin != "" {
		d.std.InsecureSkipVerify = true // 改用下面的指纹校验
		// 用 VerifyConnection 而不是 VerifyPeerCertificate:会话恢复时后者不会被调用。
		d.std.VerifyConnection = func(cs tls.ConnectionState) error { return checkPin(cs.PeerCertificates, pin) }
	}
	return d
}

// handshake 在 raw 上完成握手。握手失败时不关闭 raw,由调用方处理。
// 返回的 ekm 只在固定了证书指纹时才有:经 CDN 的连接两端不是同一个 TLS 会话,没法绑定。
func (d *tlsDialer) handshake(ctx context.Context, raw net.Conn, endpoint string) (net.Conn, []byte, error) {
	name := d.sni
	if name == "" && d.pin == "" { // CA 校验模式必须有服务器名
		name, _, _ = net.SplitHostPort(endpoint)
	}
	if d.fp == "" {
		cfg := d.std
		if cfg.ServerName != name {
			cfg = cfg.Clone()
			cfg.ServerName = name
		}
		tc := tls.Client(raw, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, nil, err
		}
		if d.pin == "" {
			return tc, nil, nil
		}
		cs := tc.ConnectionState()
		return tc, exportEKM(cs.ExportKeyingMaterial), nil
	}

	spec, err := utls.UTLSIdToSpec(fingerprints[d.fp])
	if err != nil {
		return nil, nil, err
	}
	exts := spec.Extensions[:0]
	for _, e := range spec.Extensions {
		switch x := e.(type) {
		case *utls.SNIExtension:
			if name == "" {
				continue // 没有服务器名:不发送 SNI 扩展
			}
		case *utls.RenegotiationInfoExtension:
			// 预设里允许重协商;关掉它才能导出会话密钥,隧道本身也用不到重协商。
			x.Renegotiation = utls.RenegotiateNever
		case *utls.ALPNExtension:
			if len(d.alpn) > 0 {
				x.AlpnProtocols = d.alpn
			}
		}
		exts = append(exts, e)
	}
	spec.Extensions = exts
	cfg := &utls.Config{ServerName: name}
	if d.pin != "" {
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(cs utls.ConnectionState) error { return checkPin(cs.PeerCertificates, d.pin) }
	}
	uc := utls.UClient(raw, cfg, utls.HelloCustom)
	if err := uc.ApplyPreset(&spec); err != nil {
		return nil, nil, err
	}
	if err := uc.HandshakeContext(ctx); err != nil {
		return nil, nil, err
	}
	if d.pin == "" {
		return uc, nil, nil
	}
	cs := uc.ConnectionState()
	return uc, exportEKM(cs.ExportKeyingMaterial), nil
}

// dialSpec 描述入口如何连接出口的某个 endpoint。
type dialSpec struct {
	transport string
	host      string // ws / http 的 Host 头
	path      string
	keys      *Keys
	now       func() time.Time
	tls       *tlsDialer // 仅 tls / wss
	nd        net.Dialer
}

// dial 建立到出口 endpoint 的传输层连接,并把还没发出的连接前导帧追加到 buf 返回。
// 调用方把前导帧和后面的数据(流头)合在一次写里发出;http 传输层的鉴权已经在握手里完成,前导帧为空。
func (s *dialSpec) dial(ctx context.Context, endpoint string, flags byte, buf []byte) (conn net.Conn, preface []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	switch s.transport {
	case TransportTCP:
		if conn, err = s.nd.DialContext(ctx, "tcp", endpoint); err != nil {
			return nil, nil, err
		}
		return conn, appendPreface(buf, s.keys, flags, nil, s.now()), nil

	case TransportHTTP:
		raw, err := s.nd.DialContext(ctx, "tcp", endpoint)
		if err != nil {
			return nil, nil, err
		}
		host := s.host
		if host == "" {
			host = endpoint
		}
		if conn, err = dialHTTP(ctx, raw, s.keys, host, s.path, flags, s.now()); err != nil {
			raw.Close()
			return nil, nil, err
		}
		return conn, buf, nil

	case TransportTLS:
		raw, err := s.nd.DialContext(ctx, "tcp", endpoint)
		if err != nil {
			return nil, nil, err
		}
		tc, ekm, err := s.tls.handshake(ctx, raw, endpoint)
		if err != nil {
			raw.Close()
			return nil, nil, err
		}
		return tc, appendPreface(buf, s.keys, flags, ekm, s.now()), nil

	case TransportWS, TransportWSS:
		var ekm []byte
		d := websocket.Dialer{
			NetDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return s.nd.DialContext(ctx, network, endpoint)
			},
			HandshakeTimeout: handshakeTimeout,
			ReadBufferSize:   wsBufSize,
			WriteBufferSize:  wsBufSize,
		}
		scheme := "ws"
		if s.transport == TransportWSS {
			scheme = "wss"
			// 自己完成 TLS 握手:这样才能套用指纹,并拿到用于绑定鉴权的导出密钥。
			d.NetDialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				raw, err := s.nd.DialContext(ctx, network, endpoint)
				if err != nil {
					return nil, err
				}
				tc, e, err := s.tls.handshake(ctx, raw, endpoint)
				if err != nil {
					raw.Close()
					return nil, err
				}
				ekm = e
				return tc, nil
			}
		}
		host := s.host
		if host == "" {
			host = endpoint
		}
		wc, resp, err := d.DialContext(ctx, scheme+"://"+host+s.path, http.Header{"User-Agent": {httpUserAgent}})
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		if err != nil {
			return nil, nil, err
		}
		return &wsConn{Conn: wc}, appendPreface(buf, s.keys, flags, ekm, s.now()), nil
	}
	return nil, nil, errors.New("未知的隧道传输层: " + s.transport)
}

// ParseCert 解析 PEM 证书与私钥。
func ParseCert(certPEM, keyPEM string) (tls.Certificate, error) {
	c, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return c, err
	}
	if c.Leaf == nil {
		c.Leaf, _ = x509.ParseCertificate(c.Certificate[0])
	}
	return c, nil
}

// CertPin 返回证书的 SHA-256 指纹(hex)。
func CertPin(c *tls.Certificate) string {
	sum := sha256.Sum256(c.Certificate[0])
	return hex.EncodeToString(sum[:])
}
