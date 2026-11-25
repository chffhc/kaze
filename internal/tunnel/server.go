package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/libp2p/go-yamux/v5"
)

// Handler 处理一条已通过鉴权并读完流头的隧道流。
type Handler func(conn net.Conn, h StreamHeader)

// ServerConfig 是出口侧隧道服务端的配置。
type ServerConfig struct {
	Bind      string // 监听地址,默认全部
	Port      int    // 0 = 随机
	Transport string
	Keys      *Keys
	Cert      *tls.Certificate // tls / wss 必填
	Path      string           // ws 路径
	Now       func() time.Time
}

// Server 是出口侧的隧道服务端。
type Server struct {
	cfg    ServerConfig
	h      Handler
	ln     net.Listener
	hs     *http.Server
	rc     replayCache
	tlsCfg *tls.Config

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed atomic.Bool

	lastWarn atomic.Int64
}

// NewServer 开始监听并在后台接受连接。
func NewServer(cfg ServerConfig, h Handler) (*Server, error) {
	if !ValidTransport(cfg.Transport) {
		return nil, errors.New("未知的隧道传输层: " + cfg.Transport)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Path == "" {
		cfg.Path = "/"
	}
	s := &Server{cfg: cfg, h: h, conns: make(map[net.Conn]struct{})}
	useTLS := cfg.Transport == TransportTLS || cfg.Transport == TransportWSS
	if useTLS {
		if cfg.Cert == nil {
			return nil, errors.New("tls/wss 传输层缺少证书")
		}
		s.tlsCfg = &tls.Config{Certificates: []tls.Certificate{*cfg.Cert}, MinVersion: tls.VersionTLS12}
		if cfg.Transport == TransportTLS {
			s.tlsCfg.NextProtos = []string{"h2", "http/1.1"}
		} else {
			s.tlsCfg.NextProtos = []string{"http/1.1"}
		}
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(cfg.Bind, fmt.Sprint(cfg.Port)))
	if err != nil {
		return nil, err
	}
	s.ln = ln
	switch cfg.Transport {
	case TransportTCP, TransportTLS:
		go s.acceptLoop()
	default:
		s.hs = &http.Server{
			Handler:           http.HandlerFunc(s.serveWS),
			ReadHeaderTimeout: handshakeTimeout,
			ErrorLog:          log.New(io.Discard, "", 0),
		}
		if useTLS {
			go s.hs.Serve(tls.NewListener(ln, s.tlsCfg))
		} else {
			go s.hs.Serve(ln)
		}
	}
	return s, nil
}

// Port 返回实际监听端口。
func (s *Server) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

// Close 停止监听并断开全部隧道连接。
func (s *Server) Close() {
	if s.closed.Swap(true) {
		return
	}
	s.ln.Close()
	if s.hs != nil {
		s.hs.Close()
	}
	s.mu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
}

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *Server) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if s.closed.Load() {
				return
			}
			time.Sleep(20 * time.Millisecond)
			continue
		}
		go s.handleRaw(c)
	}
}

func (s *Server) handleRaw(c net.Conn) {
	var conn net.Conn = c
	var ekm []byte
	if s.tlsCfg != nil {
		tc := tls.Server(c, s.tlsCfg)
		ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
		err := tc.HandshakeContext(ctx)
		cancel()
		if err != nil {
			c.Close()
			return
		}
		if ekm, err = exportEKM(tc.ConnectionState()); err != nil {
			c.Close()
			return
		}
		conn = tc
	}
	s.handleConn(conn, ekm)
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  wsBufSize,
	WriteBufferSize: wsBufSize,
	CheckOrigin:     func(*http.Request) bool { return true },
}

func (s *Server) serveWS(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != s.cfg.Path || !websocket.IsWebSocketUpgrade(r) {
		http.NotFound(w, r)
		return
	}
	var ekm []byte
	if r.TLS != nil {
		var err error
		if ekm, err = exportEKM(*r.TLS); err != nil {
			http.NotFound(w, r)
			return
		}
	}
	wc, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	s.handleConn(&wsConn{Conn: wc}, ekm)
}

func (s *Server) warn(remote net.Addr, err error) {
	now := time.Now().Unix()
	if last := s.lastWarn.Load(); now-last >= 5 && s.lastWarn.CompareAndSwap(last, now) {
		log.Printf("[隧道] 拒绝来自 %v 的连接: %v", remote, err)
	}
}

// handleConn 校验前导帧,然后按是否复用分发流。
func (s *Server) handleConn(conn net.Conn, ekm []byte) {
	if !s.track(conn) {
		conn.Close()
		return
	}
	defer s.untrack(conn)
	defer conn.Close()

	var pre [prefaceLen]byte
	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	if _, err := io.ReadFull(conn, pre[:]); err != nil {
		return
	}
	flags, err := verifyPreface(pre[:], s.cfg.Keys, ekm, s.cfg.Now(), &s.rc)
	if err != nil {
		s.warn(conn.RemoteAddr(), err)
		return
	}
	conn.SetReadDeadline(time.Time{})

	if flags&flagMux == 0 {
		s.handleStream(conn)
		return
	}
	sess, err := yamux.Server(conn, yamuxConfig(), nil)
	if err != nil {
		return
	}
	defer sess.Close()
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go s.handleStream(st)
	}
}

func (s *Server) handleStream(st net.Conn) {
	st.SetReadDeadline(time.Now().Add(handshakeTimeout))
	h, err := readStreamHeader(st)
	if err != nil {
		st.Close()
		return
	}
	st.SetReadDeadline(time.Time{})
	s.h(st, h)
}
