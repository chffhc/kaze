package relay

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Upstream 是 UDP 会话的上游:直连目标的 UDP 套接字、到出口的原生加密通道,或一条隧道流。
type Upstream interface {
	Send(p []byte) error
	Recv(buf []byte) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

const (
	udpSessBuf   = 16 * 1024 // 每会话回程缓冲
	udpQueueLen  = 128       // 每会话上行队列(满则丢包)
	udpSmallPkt  = 2048
	defaultIdle  = 90 * time.Second
	defaultMaxUS = 8192
)

var udpSmallPool = sync.Pool{New: func() any { b := make([]byte, udpSmallPkt); return &b }}
var udpSessPool = sync.Pool{New: func() any { b := make([]byte, udpSessBuf+64); return &b }}

// UDPRelay 是一个全锥形 NAT 式的 UDP 转发器:按来源地址建立会话,每个会话一个上游。
// 入口规则与出口的原生 UDP 通道共用这套实现,区别只在 Decode / Encode / Open。
type UDPRelay struct {
	workers sync.WaitGroup
	Conn    *net.UDPConn
	// Open 为新会话建立上游;在会话自己的协程里调用,可以阻塞(DNS、隧道握手)。
	Open func(client netip.AddrPort, tag uint32) (Upstream, error)
	// Decode 解析收到的报文(出口用于解密并取出规则号);为 nil 表示原样转发。
	Decode func(pkt []byte) (payload []byte, tag uint32, ok bool)
	// Encode 封装回程报文(出口用于加密);为 nil 表示原样转发。
	Encode func(dst, payload []byte) []byte

	Up, Down             *atomic.Int64 // 可为 nil
	UpLimits, DownLimits [2]*Bucket
	Idle                 time.Duration
	MaxSessions          int

	mu       sync.RWMutex
	sessions map[udpSessionKey]*udpSession
	closed   atomic.Bool
}

// A native exit listener is shared: the same source port is not a rule ID.
type udpSessionKey struct {
	client netip.AddrPort
	tag    uint32
}

type udpSession struct {
	udpSessionKey
	r    *UDPRelay
	q    chan *[]byte // 元素的 len 即报文长度
	last atomic.Int64
	quit chan struct{}
	mu   sync.Mutex
	up   Upstream
}

// Serve 运行收包循环,直到 Conn 被关闭。
func (r *UDPRelay) Serve() {
	if r.Idle <= 0 {
		r.Idle = defaultIdle
	}
	if r.MaxSessions <= 0 {
		r.MaxSessions = defaultMaxUS
	}
	r.mu.Lock()
	r.sessions = make(map[udpSessionKey]*udpSession)
	r.mu.Unlock()

	bp := GetUDPBuf()
	defer PutUDPBuf(bp)
	buf := *bp
	for {
		n, from, err := r.Conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if r.closed.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		payload := buf[:n]
		var tag uint32
		if r.Decode != nil {
			var ok bool
			if payload, tag, ok = r.Decode(payload); !ok {
				continue
			}
		}
		if !r.UpLimits[0].Allow(len(payload)) || !r.UpLimits[1].Allow(len(payload)) {
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		key := udpSessionKey{client: from, tag: tag}
		r.mu.RLock()
		s := r.sessions[key]
		r.mu.RUnlock()
		if s == nil {
			if s = r.newSession(key); s == nil {
				continue
			}
		}
		// 拷贝进会话队列,由会话协程发送;队列满直接丢包,不阻塞收包循环。
		var pb *[]byte
		if len(payload) <= udpSmallPkt {
			pb = udpSmallPool.Get().(*[]byte)
			*pb = (*pb)[:len(payload)]
		} else {
			b := make([]byte, len(payload))
			pb = &b
		}
		copy(*pb, payload)
		select {
		case s.q <- pb:
			if r.Up != nil {
				r.Up.Add(int64(len(payload)))
			}
		default:
			putSmall(pb)
		}
	}
}

func putSmall(pb *[]byte) {
	if cap(*pb) == udpSmallPkt {
		*pb = (*pb)[:udpSmallPkt]
		udpSmallPool.Put(pb)
	}
}

func (r *UDPRelay) newSession(key udpSessionKey) *udpSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed.Load() {
		return nil
	}
	if s := r.sessions[key]; s != nil {
		return s
	}
	if len(r.sessions) >= r.MaxSessions {
		return nil
	}
	s := &udpSession{r: r, udpSessionKey: key, q: make(chan *[]byte, udpQueueLen), quit: make(chan struct{})}
	s.last.Store(time.Now().UnixNano())
	r.sessions[key] = s
	ActiveUDP.Add(1)
	r.workers.Add(1)
	go s.run()
	return s
}

// Closing the upstream also wakes a blocked Send. If Open is still in
// progress, run takes responsibility for closing the late result instead.
func (s *udpSession) stop() {
	s.mu.Lock()
	select {
	case <-s.quit:
		s.mu.Unlock()
		return
	default:
		close(s.quit)
	}
	up := s.up
	s.mu.Unlock()
	if up != nil {
		up.Close()
	}
}

func (s *udpSession) run() {
	r := s.r
	defer r.workers.Done()
	defer func() {
		r.mu.Lock()
		if r.sessions[s.udpSessionKey] == s {
			delete(r.sessions, s.udpSessionKey)
		}
		r.mu.Unlock()
		ActiveUDP.Add(-1)
	}()
	up, err := r.Open(s.client, s.tag)
	if err != nil {
		return
	}
	s.mu.Lock()
	select {
	case <-s.quit:
		s.mu.Unlock()
		up.Close()
		return
	default:
		s.up = up
	}
	s.mu.Unlock()
	recvDone := make(chan struct{})
	go func() { defer close(recvDone); s.recvLoop(up) }()
	defer func() { s.stop(); <-recvDone }()
	for {
		select {
		case pb := <-s.q:
			s.last.Store(time.Now().UnixNano())
			err := up.Send(*pb)
			putSmall(pb)
			if err != nil {
				return
			}
		case <-s.quit:
			return
		}
	}
}

// recvLoop 把上游回包写回客户端,并负责空闲超时。
func (s *udpSession) recvLoop(up Upstream) {
	defer s.stop()
	r := s.r
	bp := udpSessPool.Get().(*[]byte)
	defer udpSessPool.Put(bp)
	buf := (*bp)[:udpSessBuf]
	var scratch []byte
	if r.Encode != nil {
		sp := udpSessPool.Get().(*[]byte)
		defer udpSessPool.Put(sp)
		scratch = *sp
	}
	for {
		up.SetReadDeadline(time.Now().Add(r.Idle))
		n, err := up.Recv(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if time.Now().UnixNano()-s.last.Load() < int64(r.Idle) {
					continue
				}
			}
			return
		}
		select {
		case <-s.quit:
			return
		default:
		}
		if !r.DownLimits[0].Allow(n) || !r.DownLimits[1].Allow(n) {
			continue
		}
		s.last.Store(time.Now().UnixNano())
		out := buf[:n]
		if r.Encode != nil {
			out = r.Encode(scratch[:0], out)
		}
		if _, err := r.Conn.WriteToUDPAddrPort(out, s.client); err != nil {
			return
		}
		if r.Down != nil {
			r.Down.Add(int64(n))
		}
	}
}

// Close 关闭监听与全部会话。
func (r *UDPRelay) Close() {
	if r.closed.Swap(true) {
		return
	}
	r.Conn.Close()
	r.mu.Lock()
	for _, s := range r.sessions {
		s.stop()
	}
	r.mu.Unlock()
}

// Wait waits for all sessions after Close.
func (r *UDPRelay) Wait() { r.workers.Wait() }

// ---- 上游实现 ----

// UDPConnUpstream 是直连目标的 UDP 上游。
type UDPConnUpstream struct{ *net.UDPConn }

// Send 发送一个报文。已 connect 的 UDP 套接字会把 ICMP 不可达反映为写错误,
// 这类瞬时错误不应该拆掉会话。
func (u UDPConnUpstream) Send(p []byte) error {
	if _, err := u.Write(p); err != nil && errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// Recv 接收一个报文,忽略 ICMP 导致的 ECONNREFUSED。
func (u UDPConnUpstream) Recv(b []byte) (int, error) {
	for {
		n, err := u.Read(b)
		if err != nil && errors.Is(err, syscall.ECONNREFUSED) {
			continue
		}
		return n, err
	}
}

// StreamUpstream 把 UDP 报文以 2 字节长度前缀封装在一条可靠流里(UDP over TCP)。
type StreamUpstream struct {
	net.Conn
	wbuf []byte
	hdr  [2]byte
}

// NewStreamUpstream 包装一条隧道流。
func NewStreamUpstream(c net.Conn) *StreamUpstream { return &StreamUpstream{Conn: c} }

func (u *StreamUpstream) Send(p []byte) error {
	if len(p) > 0xffff {
		return nil
	}
	u.wbuf = append(u.wbuf[:0], byte(len(p)>>8), byte(len(p)))
	u.wbuf = append(u.wbuf, p...)
	u.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := u.Conn.Write(u.wbuf)
	return err
}

func (u *StreamUpstream) Recv(b []byte) (int, error) {
	for {
		// 只有在帧边界上的读超时才是"空闲";读到一半超时意味着流已失步,必须当作致命错误。
		if k, err := io.ReadFull(u.Conn, u.hdr[:]); err != nil {
			if k > 0 {
				return 0, io.ErrUnexpectedEOF
			}
			return 0, err
		}
		n := int(binary.BigEndian.Uint16(u.hdr[:]))
		u.Conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		if n > len(b) { // 超长报文:丢弃
			if _, err := io.CopyN(io.Discard, u.Conn, int64(n)); err != nil {
				return 0, io.ErrUnexpectedEOF
			}
			continue
		}
		if _, err := io.ReadFull(u.Conn, b[:n]); err != nil {
			return 0, io.ErrUnexpectedEOF
		}
		return n, nil
	}
}

func (u *StreamUpstream) Close() error {
	Abort(u.Conn)
	return nil
}

// ServeUDPStream 在出口侧把一条 UDP-over-TCP 隧道流与目标 UDP 套接字对接。
func ServeUDPStream(stream net.Conn, target *net.UDPConn, idle time.Duration) {
	if idle <= 0 {
		idle = defaultIdle
	}
	ActiveUDP.Add(1)
	defer ActiveUDP.Add(-1)
	su := NewStreamUpstream(stream)
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	done := make(chan struct{})
	go func() { // 流 -> 目标
		defer close(done)
		defer target.Close() // 唤醒阻塞在 target.Read 上的回程循环
		bp := udpSessPool.Get().(*[]byte)
		defer udpSessPool.Put(bp)
		buf := *bp
		for {
			stream.SetReadDeadline(time.Time{})
			n, err := su.Recv(buf)
			if err != nil {
				return
			}
			last.Store(time.Now().UnixNano())
			if _, err := target.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	bp := udpSessPool.Get().(*[]byte)
	buf := *bp
	for { // 目标 -> 流
		target.SetReadDeadline(time.Now().Add(idle))
		n, err := target.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().UnixNano()-last.Load() < int64(idle) {
				select {
				case <-done:
				default:
					continue
				}
			}
			break
		}
		last.Store(time.Now().UnixNano())
		if su.Send(buf[:n]) != nil {
			break
		}
	}
	udpSessPool.Put(bp)
	Abort(stream)
	target.Close()
	<-done
}
