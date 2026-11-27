package tunnel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-yamux/v5"

	"kaze/internal/proto"
)

// 反向隧道:出口在内网、入口有公网入站时,由出口主动连到入口(-rev-port),
// 并在每条连接上保持一个 yamux 会话;入口需要转发时直接在会话里开流。
//
//	出口(拨号方,TLS 客户端,yamux 服务端)  --->  入口(监听方,TLS 服务端,yamux 客户端)
//
// 双向认证:出口固定校验入口组证书的指纹;入口校验出口发来的前导帧——
// 它用出口组的预共享密钥做 HMAC,并绑定本次 TLS 会话的导出密钥。
//
// 反向前导帧(出口 -> 入口,68 字节):
//
//	magic "KZR1" | 出口组 ID(8) | 时间戳毫秒(8) | nonce(16) | mac(32)
//
// 连接恒为 TLS + 复用,UDP 一律封装进流里(UDP over TCP)。
const (
	revMagic      = "KZR1"
	revPrefaceLen = 4 + 8 + 8 + 16 + 32
	// 少于这个时长就断开的反向会话,多半是被入口拒绝了
	revYoung = 3 * time.Second
)

func revMAC(k *Keys, head, ekm []byte) []byte {
	m := hmac.New(sha256.New, k.rev)
	m.Write(head)
	m.Write(ekm)
	return m.Sum(nil)
}

func appendRevPreface(dst []byte, k *Keys, groupID int64, ekm []byte, now time.Time) []byte {
	start := len(dst)
	dst = append(dst, revMagic...)
	dst = binary.BigEndian.AppendUint64(dst, uint64(groupID))
	dst = binary.BigEndian.AppendUint64(dst, uint64(now.UnixMilli()))
	var nonce [16]byte
	rand.Read(nonce[:])
	dst = append(dst, nonce[:]...)
	return append(dst, revMAC(k, dst[start:], ekm)...)
}

// revPrefaceGroup 取出前导帧声明的出口组 ID(尚未校验)。
func revPrefaceGroup(p []byte) (int64, bool) {
	if len(p) != revPrefaceLen || string(p[:4]) != revMagic {
		return 0, false
	}
	return int64(binary.BigEndian.Uint64(p[4:12])), true
}

func verifyRevPreface(p []byte, k *Keys, ekm []byte) error {
	if len(p) != revPrefaceLen || len(ekm) != ekmSize {
		return errAuth
	}
	head, mac := p[:revPrefaceLen-32], p[revPrefaceLen-32:]
	if !hmac.Equal(mac, revMAC(k, head, ekm)) {
		return errAuth
	}
	return nil
}

// ReverseListener 运行在入口节点上,接受出口拨入的反向连接。
type ReverseListener struct {
	ln     net.Listener
	cert   atomic.Pointer[tls.Certificate]
	tlsCfg *tls.Config

	mu     sync.Mutex
	groups map[int64]*Keys      // 允许拨入的出口组及其密钥
	sess   map[int64][]*revSess // 出口组 -> 已建立的会话
	pend   map[net.Conn]struct{}
	closed bool

	lastWarn atomic.Int64
}

type revSess struct {
	s      *yamux.Session
	keys   *Keys
	remote string

	// yamux 的流号用完后会话就不能再开流。累计开流数到达 limit 时把会话标记为退役:
	// 之后优先使用其它会话,等它空闲(或最多 30 分钟)后断开,出口会立刻补一条新的。
	opened   atomic.Int64
	limit    int64
	retiring atomic.Bool
}

// 各会话的退役阈值带随机量,避免同一出口的几条连接同时退役。
func newRevLimit() int64 { return 1<<29 + mrand.Int64N(1<<28) }

func (rs *revSess) drain() {
	deadline := time.Now().Add(30 * time.Minute)
	for !rs.s.IsClosed() && rs.s.NumStreams() > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)
	}
	rs.s.Close()
}

// NewReverseListener 开始监听。证书与允许的出口组稍后通过 Update 设置,在那之前所有连接都会被拒绝。
func NewReverseListener(bind string, port int) (*ReverseListener, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(bind, fmt.Sprint(port)))
	if err != nil {
		return nil, err
	}
	l := &ReverseListener{
		ln:     ln,
		groups: map[int64]*Keys{}, sess: map[int64][]*revSess{}, pend: map[net.Conn]struct{}{},
	}
	l.tlsCfg = &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c := l.cert.Load(); c != nil {
				return c, nil
			}
			return nil, errors.New("反向隧道尚未配置证书")
		},
	}
	go l.acceptLoop()
	return l, nil
}

// Port 返回实际监听端口。
func (l *ReverseListener) Port() int { return l.ln.Addr().(*net.TCPAddr).Port }

// Update 热更新证书与允许拨入的出口组。被移出名单或密钥已更换的出口组,现有会话会被断开。
func (l *ReverseListener) Update(cert *tls.Certificate, groups map[int64]*Keys) {

	if groups == nil {
		groups = map[int64]*Keys{}
	}
	var drop []*revSess
	l.mu.Lock()
	oldCert := l.cert.Swap(cert)
	certChanged := oldCert == nil || cert == nil || !bytes.Equal(oldCert.Certificate[0], cert.Certificate[0])
	l.groups = groups
	for gid, list := range l.sess {
		k := groups[gid]
		for _, rs := range list {
			if certChanged || k == nil || !k.Equal(rs.keys) {
				drop = append(drop, rs)
			}
		}
	}
	l.mu.Unlock()
	for _, rs := range drop {
		rs.s.Close() // 会话结束后由 handle 里的清理逻辑摘除
	}
}

func (l *ReverseListener) acceptLoop() {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			l.mu.Lock()
			closed := l.closed
			l.mu.Unlock()
			if closed {
				return
			}
			time.Sleep(20 * time.Millisecond)
			continue
		}
		go l.handle(c)
	}
}

func (l *ReverseListener) warn(remote net.Addr, err error) {
	now := time.Now().Unix()
	if last := l.lastWarn.Load(); now-last >= 5 && l.lastWarn.CompareAndSwap(last, now) {
		log.Printf("[反向隧道] 拒绝来自 %v 的连接: %v", remote, err)
	}
}

func (l *ReverseListener) handle(c net.Conn) {
	l.mu.Lock()
	if l.closed || len(l.pend) >= 128 {
		l.mu.Unlock()
		c.Close()
		return
	}
	l.pend[c] = struct{}{}
	l.mu.Unlock()
	pending := true
	unpend := func() {
		if pending {
			pending = false
			l.mu.Lock()
			delete(l.pend, c)
			l.mu.Unlock()
		}
	}
	defer unpend()
	defer c.Close()

	cert := l.cert.Load()
	if cert == nil {
		return
	}
	cfg := l.tlsCfg.Clone()
	cfg.GetCertificate = nil
	cfg.Certificates = []tls.Certificate{*cert}
	tc := tls.Server(c, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	err := tc.HandshakeContext(ctx)
	cancel()
	if err != nil {
		return
	}
	cs := tc.ConnectionState()
	ekm, err := exportEKM(cs.Version, cs.ExportKeyingMaterial)
	if err != nil {
		return
	}

	var pre [revPrefaceLen]byte
	tc.SetReadDeadline(time.Now().Add(handshakeTimeout))
	if _, err := io.ReadFull(tc, pre[:]); err != nil {
		return
	}
	tc.SetReadDeadline(time.Time{})
	gid, ok := revPrefaceGroup(pre[:])
	if !ok {
		l.warn(c.RemoteAddr(), errAuth)
		return
	}
	l.mu.Lock()
	keys := l.groups[gid]
	l.mu.Unlock()
	if keys == nil {
		l.warn(c.RemoteAddr(), fmt.Errorf("出口组 #%d 不在本入口的反向隧道名单里", gid))
		return
	}
	if err := verifyRevPreface(pre[:], keys, ekm); err != nil {
		l.warn(c.RemoteAddr(), err)
		return
	}

	sess, err := yamux.Client(tc, yamuxConfig(false), nil)
	if err != nil {
		return
	}
	defer sess.Close()
	rs := &revSess{s: sess, keys: keys, remote: c.RemoteAddr().String(), limit: newRevLimit()}
	l.mu.Lock()
	// 握手期间名单可能已经变了
	if cur := l.groups[gid]; l.closed || l.cert.Load() == nil || !bytes.Equal(cert.Certificate[0], l.cert.Load().Certificate[0]) || len(l.sess[gid]) >= 64 || cur == nil || !cur.Equal(keys) {
		l.mu.Unlock()
		return
	}
	delete(l.pend, c)
	pending = false
	l.sess[gid] = append(l.sess[gid], rs)
	n := len(l.sess[gid])
	l.mu.Unlock()
	log.Printf("[反向隧道] 出口组 #%d 的节点 %s 已接入(共 %d 条连接)", gid, rs.remote, n)

	<-sess.CloseChan()

	l.mu.Lock()
	list := l.sess[gid]
	for i, x := range list {
		if x == rs {
			list = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(l.sess, gid)
	} else {
		l.sess[gid] = list
	}
	l.mu.Unlock()
}

func (l *ReverseListener) live(groupID int64) []*revSess {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]*revSess, 0, len(l.sess[groupID]))
	for _, rs := range l.sess[groupID] {
		if !rs.s.IsClosed() {
			out = append(out, rs)
		}
	}
	return out
}

// Open 在出口组 groupID 拨入的连接上开一条流,优先选当前流数最少的会话(出口节点间自然均衡)。
func (l *ReverseListener) Open(ctx context.Context, groupID int64) (net.Conn, error) {
	list := l.live(groupID)
	var last error
	for attempt := 0; attempt < 2 && len(list) > 0; attempt++ {
		best := 0
		for i := 1; i < len(list); i++ {
			a, b := list[i], list[best]
			if ar, br := a.retiring.Load(), b.retiring.Load(); ar != br {
				if br {
					best = i
				}
				continue
			}
			if a.s.NumStreams() < b.s.NumStreams() {
				best = i
			}
		}
		rs := list[best]
		st, err := rs.s.OpenStream(ctx)
		if err == nil {
			if rs.opened.Add(1) == rs.limit {
				rs.retiring.Store(true)
				go rs.drain()
			}
			return st, nil
		}
		last = err
		list = append(list[:best], list[best+1:]...)
	}
	if last == nil {
		last = fmt.Errorf("出口组 #%d 还没有节点接入反向隧道", groupID)
	}
	return nil, last
}

// Ping 返回出口组当前的反向连接数,并测量其中一条的往返时延。
func (l *ReverseListener) Ping(groupID int64) (conns int, rtt time.Duration, err error) {
	list := l.live(groupID)
	if len(list) == 0 {
		return 0, 0, fmt.Errorf("出口组 #%d 还没有节点接入反向隧道", groupID)
	}
	type res struct {
		d   time.Duration
		err error
	}
	ch := make(chan res, 1)
	go func() {
		d, err := list[0].s.Ping()
		ch <- res{d, err}
	}()
	select {
	case r := <-ch:
		return len(list), r.d, r.err
	case <-time.After(4 * time.Second):
		return len(list), 0, errors.New("反向隧道探测超时")
	}
}

// Stats 返回允许拨入的出口组数,以及其中当前有连接的组数。
func (l *ReverseListener) Stats() (allowed, connected int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for gid := range l.groups {
		for _, rs := range l.sess[gid] {
			if !rs.s.IsClosed() {
				connected++
				break
			}
		}
	}
	return len(l.groups), connected
}

// Close 停止监听并断开全部反向会话。
func (l *ReverseListener) Close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	var all []*revSess
	for _, list := range l.sess {
		all = append(all, list...)
	}
	for c := range l.pend {
		c.Close()
	}
	l.mu.Unlock()
	l.ln.Close()
	for _, rs := range all {
		rs.s.Close()
	}
}

// ReverseDialer 运行在出口节点上:向一个入口节点保持若干条反向连接,断开后自动重连。
type ReverseDialer struct {
	Spec    proto.ReverseSpec
	groupID int64
	keys    *Keys
	now     func() time.Time
	h       Handler
	tls     *tlsDialer
	nd      net.Dialer

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed chan struct{}
	once   sync.Once

	live     atomic.Int32
	lastWarn atomic.Int64
}

// NewReverseDialer 启动 spec.Conns 条到 spec.Endpoint 的反向连接。h 处理入口在这些连接上开出的流。
func NewReverseDialer(spec proto.ReverseSpec, groupID int64, keys *Keys, now func() time.Time, h Handler) (*ReverseDialer, error) {
	if !ValidFingerprint(spec.Fingerprint) {
		return nil, errors.New("未知的 TLS 指纹: " + spec.Fingerprint)
	}
	if spec.CertPin == "" {
		return nil, errors.New("反向隧道缺少入口证书指纹")
	}
	if now == nil {
		now = time.Now
	}
	n := spec.Conns
	if n <= 0 {
		n = 2
	}
	if n > 16 {
		n = 16
	}
	alpn := []string{"h2", "http/1.1"}
	if spec.Fingerprint != "" {
		alpn = nil
	}
	d := &ReverseDialer{
		Spec: spec, groupID: groupID, keys: keys, now: now, h: h,
		tls:    newTLSDialer(spec.SNI, spec.CertPin, spec.Fingerprint, alpn),
		nd:     net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second},
		conns:  map[net.Conn]struct{}{},
		closed: make(chan struct{}),
	}
	for i := 0; i < n; i++ {
		go d.loop()
	}
	return d, nil
}

// Connected 返回当前已建立的反向连接数。
func (d *ReverseDialer) Connected() int { return int(d.live.Load()) }

// Close 断开全部反向连接并停止重连。
func (d *ReverseDialer) Close() {
	d.once.Do(func() {
		close(d.closed)
		d.mu.Lock()
		for c := range d.conns {
			c.Close()
		}
		d.mu.Unlock()
	})
}

func (d *ReverseDialer) stopped() bool {
	select {
	case <-d.closed:
		return true
	default:
		return false
	}
}

func (d *ReverseDialer) loop() {
	backoff := time.Second
	for !d.stopped() {
		start := time.Now()
		up, err := d.session()
		if d.stopped() {
			return
		}
		el := time.Since(start)
		if el > 30*time.Second {
			backoff = time.Second
		}
		now := time.Now().Unix()
		if last := d.lastWarn.Load(); now-last >= 30 && d.lastWarn.CompareAndSwap(last, now) {
			hint := ""
			if up && el < revYoung {
				hint = "(入口立即断开了连接:可能是密钥不一致,或该入口没有把本出口组列入反向隧道)"
			}
			log.Printf("[反向隧道] 到入口 %s 的连接断开: %v%s,%v 后重连", d.Spec.Endpoint, err, hint, backoff)
		}
		select {
		case <-d.closed:
			return
		case <-time.After(backoff + time.Duration(mrand.Int64N(int64(backoff/2)+1))):
		}
		if backoff < 15*time.Second {
			backoff *= 2
		}
	}
}

// session 建立并维持一条反向连接,直到它断开。up 表示握手与前导帧都已发出(入口是否接受要看之后连接能否保持)。
func (d *ReverseDialer) session() (up bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()
	raw, err := d.nd.DialContext(ctx, "tcp", d.Spec.Endpoint)
	if err != nil {
		return false, err
	}
	defer raw.Close()
	d.mu.Lock()
	if d.stopped() {
		d.mu.Unlock()
		return false, errors.New("已停止")
	}
	d.conns[raw] = struct{}{}
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.conns, raw)
		d.mu.Unlock()
	}()

	tc, ekm, err := d.tls.handshake(ctx, raw, d.Spec.Endpoint)
	if err != nil {
		return false, err
	}
	cancel()
	tc.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = tc.Write(appendRevPreface(nil, d.keys, d.groupID, ekm, d.now()))
	tc.SetWriteDeadline(time.Time{})
	if err != nil {
		return false, err
	}
	sess, err := yamux.Server(tc, yamuxConfig(true), nil)
	if err != nil {
		return false, err
	}
	defer sess.Close()
	d.live.Add(1)
	defer d.live.Add(-1)
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return true, err
		}
		go serveStream(st, d.h)
	}
}
