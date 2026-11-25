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
)

// 传输层类型
const (
	TransportTCP = "tcp"
	TransportTLS = "tls"
	TransportWS  = "ws"
	TransportWSS = "wss"
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
	case TransportTCP, TransportTLS, TransportWS, TransportWSS:
		return true
	}
	return false
}

// MuxWindow 是单条复用流的最大接收窗口。窗口越大,高延迟链路上的单流吞吐越高,
// 但目标读得慢时每条流最多会多缓冲这么多数据。
var MuxWindow uint32 = 4 * 1024 * 1024

func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.AcceptBacklog = 1024
	c.MaxIncomingStreams = 1 << 20
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

// clientTLS 构造入口侧的 TLS 配置:有 pin 时固定校验证书指纹,否则走系统 CA。
func clientTLS(sni, pin string, alpn []string) *tls.Config {
	cfg := &tls.Config{
		ServerName:         sni,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         alpn,
		ClientSessionCache: tls.NewLRUClientSessionCache(128),
	}
	if pin != "" {
		cfg.InsecureSkipVerify = true // 改用下面的指纹校验
		// 用 VerifyConnection 而不是 VerifyPeerCertificate:会话恢复时后者不会被调用。
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("出口未提供证书")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if hex.EncodeToString(sum[:]) != pin {
				return errors.New("出口证书指纹不匹配")
			}
			return nil
		}
	}
	return cfg
}

func exportEKM(cs tls.ConnectionState) ([]byte, error) {
	return cs.ExportKeyingMaterial(ekmLabel, nil, 32)
}

type dialSpec struct {
	transport string
	sni       string
	host      string
	path      string
	pin       string
	tlsCfg    *tls.Config
	nd        net.Dialer
}

// dial 建立到出口 endpoint 的传输层连接。
// 返回的 ekm 仅在"直连出口的 TLS"(有 pin)时非空,用于把鉴权绑定到本次 TLS 会话。
func (s *dialSpec) dial(ctx context.Context, endpoint string) (conn net.Conn, ekm []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	switch s.transport {
	case TransportTCP:
		conn, err = s.nd.DialContext(ctx, "tcp", endpoint)
		return conn, nil, err
	case TransportTLS:
		raw, err := s.nd.DialContext(ctx, "tcp", endpoint)
		if err != nil {
			return nil, nil, err
		}
		cfg := s.tlsCfg
		if cfg.ServerName == "" && s.pin == "" { // CA 校验模式必须有服务器名
			cfg = cfg.Clone()
			cfg.ServerName, _, _ = net.SplitHostPort(endpoint)
		}
		tc := tls.Client(raw, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, nil, err
		}
		if s.pin != "" {
			if ekm, err = exportEKM(tc.ConnectionState()); err != nil {
				raw.Close()
				return nil, nil, err
			}
		}
		return tc, ekm, nil
	case TransportWS, TransportWSS:
		d := websocket.Dialer{
			NetDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return s.nd.DialContext(ctx, network, endpoint)
			},
			TLSClientConfig:  s.tlsCfg,
			HandshakeTimeout: handshakeTimeout,
			ReadBufferSize:   wsBufSize,
			WriteBufferSize:  wsBufSize,
		}
		scheme := "ws"
		if s.transport == TransportWSS {
			scheme = "wss"
		}
		host := s.host
		if host == "" {
			host = endpoint
		}
		hdr := http.Header{"User-Agent": {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"}}
		wc, resp, err := d.DialContext(ctx, scheme+"://"+host+s.path, hdr)
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		if err != nil {
			return nil, nil, err
		}
		if s.transport == TransportWSS && s.pin != "" {
			tc, ok := wc.NetConn().(*tls.Conn)
			if !ok {
				wc.Close()
				return nil, nil, errors.New("wss 底层不是 TLS 连接")
			}
			if ekm, err = exportEKM(tc.ConnectionState()); err != nil {
				wc.Close()
				return nil, nil, err
			}
		}
		return &wsConn{Conn: wc}, ekm, nil
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
