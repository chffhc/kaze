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
	"strings"
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
	Path      string           // ws / http 的路径
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
	useTLS := TransportUsesTLS(cfg.Transport)
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
	case TransportTCP, TransportTLS, TransportHTTP:
		go s.acceptLoop()
	default:
		s.hs = &http.Server{
			Handler:           http.HandlerFunc(s.serveWS),
			ReadHeaderTimeout: handshakeTimeout,
			IdleTimeout:       30 * time.Second,
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
	if !s.track(c) {
		c.Close()
		return
	}
	defer s.untrack(c)
	defer c.Close()

	switch {
	case s.cfg.Transport == TransportHTTP:
		conn, flags, err := acceptHTTP(c, s.cfg.Keys, s.cfg.Path, s.cfg.Now(), &s.rc)
		if err != nil {
			if errors.Is(err, errAuth) || errors.Is(err, errClock) || errors.Is(err, errReplay) {
				s.warn(c.RemoteAddr(), err)
			}
			return
		}
		s.serve(conn, flags)
	case s.tlsCfg != nil:
		tc := tls.Server(c, s.tlsCfg)
		ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
		err := tc.HandshakeContext(ctx)
		cancel()
		if err != nil {
			return
		}
		cs := tc.ConnectionState()
		if !safeTLS(cs.Version, cs.CipherSuite) {
			return
		}
		ekm, err := exportEKM(cs.ExportKeyingMaterial)
		if err != nil {
			return
		}
		s.authAndServe(tc, ekm)
	default:
		s.authAndServe(c, nil)
	}
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
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Kaze ") {
		http.Error(w, "unauthorized", 401)
		return
	}
	if _, _, err := verifyHandshakeToken(strings.TrimPrefix(header, "Kaze "), s.cfg.Keys, s.cfg.Now(), &s.rc, "ws-upgrade"); err != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	var ekm []byte
	if r.TLS != nil {
		if !safeTLS(r.TLS.Version, r.TLS.CipherSuite) {
			http.Error(w, "unauthorized", 401)
			return
		}
		var err error
		ekm, err = exportEKM(r.TLS.ExportKeyingMaterial)
		if err != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
	}
	wc, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	// 升级后的连接已被劫持,http.Server.Close 不再管它,需要自己登记
	wc.SetReadLimit(int64(MuxWindow) + 65536)
	conn := &wsConn{Conn: wc}
	if !s.track(conn) {
		conn.Close()
		return
	}
	defer s.untrack(conn)
	defer conn.Close()
	s.authAndServe(conn, ekm)
}

func (s *Server) warn(remote net.Addr, err error) {
	now := time.Now().Unix()
	if last := s.lastWarn.Load(); now-last >= 5 && s.lastWarn.CompareAndSwap(last, now) {
		log.Printf("[隧道] 拒绝来自 %v 的连接: %v", remote, err)
	}
}

// authAndServe 读取并校验连接前导帧,通过后开始分发流。conn 由调用方负责关闭。
func (s *Server) authAndServe(conn net.Conn, ekm []byte) {
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
	s.serve(conn, flags)
}

// serve 在已通过鉴权的连接上分发流:复用连接上跑 yamux,否则整条连接就是一条流。
func (s *Server) serve(conn net.Conn, flags byte) {
	if flags&flagMux == 0 {
		serveStream(conn, s.h)
		return
	}
	sess, err := yamux.Server(conn, yamuxConfig(true), nil)
	if err != nil {
		return
	}
	defer sess.Close()
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go serveStream(st, s.h)
	}
}

// serveStream 读取流头并交给处理函数;正向与反向隧道共用。
func serveStream(st net.Conn, h Handler) {
	st.SetReadDeadline(time.Now().Add(handshakeTimeout))
	hd, err := readStreamHeader(st)
	if err != nil {
		st.Close()
		return
	}
	st.SetReadDeadline(time.Time{})
	h(st, hd)
}
