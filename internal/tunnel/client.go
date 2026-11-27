package tunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-yamux/v5"

	"kaze/internal/proto"
	"kaze/internal/relay"
)

const (
	// 单条复用连接上的并发流达到这个数就再开一条连接(直到 MuxConns),缓解队头阻塞。
	streamsPerConn = 8
	// 单条复用连接累计开流达到这个数后退役(yamux 流号空间有限)。
	sessionMaxOpened = 1 << 29
	// 建立后很快就断开的会话视为握手/鉴权失败。
	youngSession = 3 * time.Second
)

// ClientOpts 是隧道客户端的可选参数。
type ClientOpts struct {
	MaxFail     int
	FailTimeout time.Duration
	Now         func() time.Time // 鉴权时钟(与面板校准后的时间)
	// Reverse 是本节点的反向隧道监听。Spec.Reverse 为 true 的隧道不主动拨号,
	// 而是在出口拨入的连接上开流;为 nil 时这类隧道不可用。
	Reverse *ReverseListener
}

// Client 是入口侧到某个出口组的隧道客户端:
// 在出口节点间按最小连接数均衡、故障转移;复用模式下维护预热的 yamux 会话池。
type Client struct {
	Spec proto.TunnelSpec

	keys     *Keys
	ds       *dialSpec
	bal      *relay.Balancer
	now      func() time.Time
	fallback *Client
	rev      *ReverseListener

	mu      sync.Mutex
	pools   map[*relay.Backend]*muxPool
	retired []*yamux.Session
	closed  chan struct{}
	once    sync.Once
}

// NewClient 根据面板下发的 TunnelSpec 创建客户端,并在后台预热连接。
func NewClient(spec *proto.TunnelSpec, o ClientOpts) (*Client, error) {
	return newClient(spec, o, true)
}

func newClient(spec *proto.TunnelSpec, o ClientOpts, withFallback bool) (*Client, error) {
	keys, err := DeriveKeys(spec.Key)
	if err != nil {
		return nil, err
	}
	if !ValidTransport(spec.Transport) {
		return nil, errors.New("未知的隧道传输层: " + spec.Transport)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	c := &Client{
		Spec:   *spec,
		keys:   keys,
		bal:    relay.NewBalancer(spec.Endpoints, relay.LBLeastConn, o.MaxFail, o.FailTimeout),
		now:    o.Now,
		pools:  make(map[*relay.Backend]*muxPool),
		closed: make(chan struct{}),
	}
	if spec.Transport == TransportWS || spec.Transport == TransportWSS {
		c.Spec.Mux = true // WebSocket 没有半关闭语义,恒走复用层
	}
	if c.Spec.MuxConns <= 0 {
		c.Spec.MuxConns = 4
	}
	if !ValidFingerprint(spec.Fingerprint) {
		return nil, errors.New("未知的 TLS 指纹: " + spec.Fingerprint)
	}
	path := spec.Path
	if path == "" {
		path = "/"
	}
	c.ds = &dialSpec{cdn: spec.CDN, transport: spec.Transport, host: spec.Host, path: path, keys: keys, now: o.Now}
	c.ds.nd = net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	switch spec.Transport {
	case TransportTLS:
		alpn := []string{"h2", "http/1.1"}
		if spec.Fingerprint != "" {
			alpn = nil // 保留指纹预设自带的 ALPN
		}
		c.ds.tls = newTLSDialer(spec.SNI, spec.CertPin, spec.Fingerprint, alpn)
	case TransportWSS:
		// 浏览器发起 WebSocket 时只声明 http/1.1;经 CDN 时声明 h2 还会导致握手后无法升级
		c.ds.tls = newTLSDialer(spec.SNI, spec.CertPin, spec.Fingerprint, []string{"http/1.1"})
	}
	if withFallback && spec.Fallback != nil {
		if fb, err := newClient(spec.Fallback, o, false); err == nil {
			c.fallback = fb
		}
	}
	c.Spec.Fallback = spec.Fallback
	if spec.Reverse {
		c.rev = o.Reverse
		return c, nil // 反向隧道的连接由出口发起并由监听端持有,这里不拨号、不预热
	}
	for _, be := range c.bal.Backends() {
		c.pools[be] = &muxPool{c: c, be: be}
	}
	if c.Spec.Mux {
		go c.janitor()
	}
	return c, nil
}

// janitor 负责预热(每个健康出口至少保持一条复用连接,兼作主动健康检查)与回收退役会话。
func (c *Client) janitor() {
	c.warm()
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-t.C:
			c.warm()
			c.reap(false)
		}
	}
}

func (c *Client) warm() {
	for be, p := range c.pools {
		if be.Down() {
			continue
		}
		go func(p *muxPool) {
			ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
			defer cancel()
			p.get(ctx)
		}(p)
	}
}

func (c *Client) reap(force bool) {
	c.mu.Lock()
	keep := c.retired[:0]
	for _, s := range c.retired {
		if force || s.IsClosed() || s.NumStreams() == 0 {
			s.Close()
		} else {
			keep = append(keep, s)
		}
	}
	c.retired = keep
	c.mu.Unlock()
}

// Open 打开一条隧道流。出口节点全部故障或多次尝试失败时转到故障转移组。
// 返回的 done 必须在流用完后调用一次(归还最小连接数均衡的计数)。
// 返回的连接是原始类型(*net.TCPConn / *tls.Conn / *yamux.Stream),
// 这样明文 tcp 隧道在入口侧也能走 splice 零拷贝。
func (c *Client) Open(ctx context.Context, h StreamHeader) (conn net.Conn, done func(), err error) {
	if c.Spec.Reverse {
		if conn, err = c.openReverse(ctx, h); err == nil {
			return conn, func() {}, nil
		}
		if c.fallback != nil {
			return c.fallback.Open(ctx, h)
		}
		return nil, nil, err
	}
	if c.fallback != nil && c.bal.AllDown() {
		return c.fallback.Open(ctx, h)
	}
	err = errors.New("出口组没有可用节点")
	for i, be := range c.bal.Candidates(0) {
		if i >= 3 || ctx.Err() != nil {
			break
		}
		var e error
		if conn, e = c.openOn(ctx, be, h); e == nil {
			be.Active.Add(1)
			var once sync.Once
			return conn, func() { once.Do(func() { be.Active.Add(-1) }) }, nil
		}
		err = e
	}
	if c.fallback != nil {
		return c.fallback.Open(ctx, h)
	}
	return nil, nil, err
}

// openReverse 在出口拨入的反向连接上开一条流。
func (c *Client) openReverse(ctx context.Context, h StreamHeader) (net.Conn, error) {
	if c.rev == nil {
		return nil, errors.New("本节点没有开启反向隧道监听(启动时未指定 -rev-port)")
	}
	st, err := c.rev.Open(ctx, c.Spec.GroupID)
	if err != nil {
		return nil, err
	}
	var hb [maxStreamHeader]byte
	st.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = st.Write(appendStreamHeader(hb[:0], h))
	st.SetWriteDeadline(time.Time{})
	if err != nil {
		relay.Abort(st)
		return nil, err
	}
	return st, nil
}

func (c *Client) openOn(ctx context.Context, be *relay.Backend, h StreamHeader) (net.Conn, error) {
	var hb [prefaceLen + maxStreamHeader]byte
	if !c.Spec.Mux {
		conn, buf, err := c.ds.dial(ctx, be.Addr, 0, hb[:0])
		c.bal.Report(be, err == nil)
		if err != nil {
			return nil, err
		}
		// 前导帧与流头合在一次写里发出,之后立刻可以转发数据(0-RTT)
		buf = appendStreamHeader(buf, h)
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write(buf)
		conn.SetWriteDeadline(time.Time{})
		if err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
	p := c.pools[be]
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		ms, err := p.get(ctx)
		if err != nil {
			return nil, err
		}
		st, err := ms.s.OpenStream(ctx)
		if err != nil {
			last = err
			continue // 会话刚好断开:换一条再试
		}
		ms.opened.Add(1)
		st.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = st.Write(appendStreamHeader(hb[:0], h))
		st.SetWriteDeadline(time.Time{})
		if err != nil {
			st.Reset()
			last = err
			continue
		}
		return st, nil
	}
	return nil, last
}

// OpenUDP 为一个 UDP 会话建立上游:默认走原生 UDP 加密通道;
// 以下情况改为封装进隧道流(UDP over TCP):出口组如此配置、WebSocket 传输层、反向隧道,
// 或调用方要求(forceStream,链式出口的中间跳只转发流)。
func (c *Client) OpenUDP(ctx context.Context, ruleID uint32, src netip.AddrPort, forceStream bool) (relay.Upstream, error) {
	if forceStream || c.Spec.Reverse || c.Spec.UDPOverTCP || c.Spec.Transport == TransportWS || c.Spec.Transport == TransportWSS {
		conn, done, err := c.Open(ctx, StreamHeader{Cmd: CmdUDP, RuleID: ruleID, Src: src})
		if err != nil {
			return nil, err
		}
		return &streamUDP{StreamUpstream: relay.NewStreamUpstream(conn), done: done}, nil
	}
	if c.fallback != nil && c.bal.AllDown() {
		return c.fallback.OpenUDP(ctx, ruleID, src, false)
	}
	cands := c.bal.Candidates(0)
	if len(cands) == 0 {
		return nil, errors.New("出口组没有可用节点")
	}
	raddr, err := net.ResolveUDPAddr("udp", cands[0].Addr)
	if err != nil {
		return nil, err
	}
	return dialNativeUDP(ctx, raddr, c.keys, ruleID)
}

// Endpoints 返回出口节点地址列表(诊断用);反向隧道没有可拨的地址。
func (c *Client) Endpoints() []string {
	if c.Spec.Reverse {
		return nil
	}
	return c.Spec.Endpoints
}

// ReverseStatus 返回反向隧道当前的连接数与往返时延(诊断用)。
func (c *Client) ReverseStatus() (reverse bool, conns int, rtt time.Duration, err error) {
	if !c.Spec.Reverse {
		return false, 0, 0, nil
	}
	if c.rev == nil {
		return true, 0, 0, errors.New("本节点没有开启反向隧道监听")
	}
	conns, rtt, err = c.rev.Ping(c.Spec.GroupID)
	return true, conns, rtt, err
}

// Retire 让客户端退役:不再预热,已有的流继续跑完,空闲的复用连接被逐步回收。
func (c *Client) Retire() {
	c.once.Do(func() {
		close(c.closed)
		if c.fallback != nil {
			c.fallback.Retire()
		}
		var old []*yamux.Session
		for _, p := range c.pools {
			p.mu.Lock()
			for _, ms := range p.sess {
				old = append(old, ms.s)
			}
			p.sess = nil
			p.mu.Unlock()
		}
		c.mu.Lock()
		c.retired = append(c.retired, old...)
		c.mu.Unlock()
		go func() {
			deadline := time.Now().Add(2 * time.Hour)
			for {
				c.reap(time.Now().After(deadline))
				c.mu.Lock()
				n := len(c.retired)
				c.mu.Unlock()
				if n == 0 {
					return
				}
				time.Sleep(10 * time.Second)
			}
		}()
	})
}

// Close 立即关闭全部连接。
func (c *Client) Close() {
	c.Retire()
	c.reap(true)
	if c.fallback != nil {
		c.fallback.Close()
	}
}

// ---- 复用会话池 ----

type muxSess struct {
	s       *yamux.Session
	created time.Time
	opened  atomic.Int64
}

type muxPool struct {
	c       *Client
	be      *relay.Backend
	mu      sync.Mutex
	sess    []*muxSess
	dialing bool
	wait    chan struct{}
}

// get 返回一条可用的复用会话:挑并发流最少的;全部较忙且未达上限时后台加开一条;
// 一条都没有时同步拨号(并发请求共享同一次拨号)。
func (p *muxPool) get(ctx context.Context) (*muxSess, error) {
	for {
		select {
		case <-p.c.closed:
			return nil, errors.New("隧道已关闭")
		default:
		}
		p.mu.Lock()
		live := p.sess[:0]
		var best *muxSess
		bestN := 0
		for _, ms := range p.sess {
			if ms.s.IsClosed() {
				if time.Since(ms.created) < youngSession {
					p.c.bal.Report(p.be, false)
				}
				continue
			}
			if ms.opened.Load() > sessionMaxOpened {
				p.c.mu.Lock()
				p.c.retired = append(p.c.retired, ms.s)
				p.c.mu.Unlock()
				continue
			}
			live = append(live, ms)
			if n := ms.s.NumStreams(); best == nil || n < bestN {
				best, bestN = ms, n
			}
		}
		for i := len(live); i < len(p.sess); i++ {
			p.sess[i] = nil
		}
		p.sess = live
		if best != nil {
			if bestN >= streamsPerConn && len(live) < p.c.Spec.MuxConns && !p.dialing {
				p.startDial()
			}
			p.mu.Unlock()
			return best, nil
		}
		if !p.dialing {
			p.startDial()
		}
		w := p.wait
		p.mu.Unlock()
		select {
		case <-w:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		p.mu.Lock()
		n := len(p.sess)
		p.mu.Unlock()
		if n == 0 {
			return nil, errors.New("无法连接出口节点 " + p.be.Addr)
		}
	}
}

// startDial 在后台建立一条新的复用连接;调用方需持有 p.mu。
func (p *muxPool) startDial() {
	p.dialing = true
	p.wait = make(chan struct{})
	go func() {
		ms, err := p.dialSession()
		p.mu.Lock()
		if err == nil {
			select {
			case <-p.c.closed:
				ms.s.Close()
			default:
				p.sess = append(p.sess, ms)
			}
		}
		p.dialing = false
		close(p.wait)
		p.mu.Unlock()
	}()
}

func (p *muxPool) dialSession() (*muxSess, error) {
	c := p.c
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()
	conn, preface, err := c.ds.dial(ctx, p.be.Addr, flagMux, nil)
	c.bal.Report(p.be, err == nil)
	if err != nil {
		return nil, err
	}
	if len(preface) > 0 {
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write(preface)
		conn.SetWriteDeadline(time.Time{})
		if err != nil {
			conn.Close()
			return nil, err
		}
	}
	s, err := yamux.Client(conn, yamuxConfig(false), nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &muxSess{s: s, created: time.Now()}, nil
}

// streamUDP 是封装在隧道流里的 UDP 上游,关闭时归还出口节点的连接计数。
type streamUDP struct {
	*relay.StreamUpstream
	done func()
}

func (u *streamUDP) Close() error {
	u.done()
	return u.StreamUpstream.Close()
}
