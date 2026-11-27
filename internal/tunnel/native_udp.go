package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
	"kaze/internal/relay"
)

const datagramChunk = 4096 // Leave headroom below the DTLS library's receive buffer.
const fragmentHeader = 7   // message number, datagram length, fragment index

type assembly struct {
	payload []byte
	mask    uint32
	created time.Time
}

// One reader and one writer use independent state, just like a connected UDP socket.
type datagrams struct {
	net.Conn
	next              uint32
	partial           map[uint32]*assembly
	readBuf, writeBuf [fragmentHeader + datagramChunk]byte
}

func newDatagrams(c net.Conn) *datagrams {
	return &datagrams{Conn: c, partial: make(map[uint32]*assembly)}
}

func (d *datagrams) Write(p []byte) (int, error) {
	if len(p) > 65535 {
		return 0, errors.New("UDP datagram too large")
	}
	d.next++
	buf := d.writeBuf[:]
	binary.BigEndian.PutUint32(buf, d.next)
	binary.BigEndian.PutUint16(buf[4:], uint16(len(p)))
	for i := 0; ; i++ {
		start := i * datagramChunk
		end := min(start+datagramChunk, len(p))
		buf[6] = byte(i)
		copy(buf[7:], p[start:end])
		if _, err := d.Conn.Write(buf[:7+end-start]); err != nil {
			return 0, err
		}
		if end == len(p) {
			return len(p), nil
		}
	}
}

func (d *datagrams) Read(b []byte) (int, error) {
	for {
		buf := d.readBuf[:]
		n, err := d.Conn.Read(buf)
		if err != nil {
			return 0, err
		}
		if n < fragmentHeader {
			continue
		}
		id := binary.BigEndian.Uint32(buf)
		size := int(binary.BigEndian.Uint16(buf[4:]))
		i := int(buf[6])
		start := i * datagramChunk
		count := max(1, (size+datagramChunk-1)/datagramChunk)
		if i >= count || n-fragmentHeader != min(datagramChunk, size-start) || size > len(b) {
			continue
		}
		if count == 1 {
			return copy(b, buf[fragmentHeader:n]), nil
		}
		a := d.partial[id]
		if a == nil {
			now := time.Now()
			for old, v := range d.partial {
				if now.Sub(v.created) > 3*time.Second {
					delete(d.partial, old)
				}
			}
			if len(d.partial) >= 8 {
				continue
			}
			a = &assembly{payload: make([]byte, size), created: now}
			d.partial[id] = a
		}
		if len(a.payload) != size {
			continue
		}
		copy(a.payload[start:], buf[fragmentHeader:n])
		a.mask |= 1 << i
		if a.mask == (1<<count)-1 {
			delete(d.partial, id)
			return copy(b, a.payload), nil
		}
	}
}

func datagramConfig(keys *Keys) *dtls.Config {
	return &dtls.Config{PSK: func([]byte) ([]byte, error) { return keys.udpPSK, nil }, PSKIdentityHint: []byte("kaze-dtls-v2"),
		CipherSuites: []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_GCM_SHA256}, ExtendedMasterSecret: dtls.RequireExtendedMasterSecret, ReplayProtectionWindow: 128}
}

type nativeUDP struct {
	*datagrams
	rule uint32
	wbuf []byte
}

func dialNativeUDP(ctx context.Context, addr *net.UDPAddr, keys *Keys, rule uint32) (relay.Upstream, error) {
	c, err := dtls.Dial("udp", addr, datagramConfig(keys))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	if err := c.HandshakeContext(ctx); err != nil {
		c.Close()
		return nil, err
	}
	return &nativeUDP{datagrams: newDatagrams(c), rule: rule}, nil
}
func (u *nativeUDP) Send(p []byte) error {
	u.wbuf = binary.BigEndian.AppendUint32(u.wbuf[:0], u.rule)
	u.wbuf = append(u.wbuf, p...)
	_, err := u.Write(u.wbuf)
	return err
}
func (u *nativeUDP) Recv(b []byte) (int, error) { return u.Read(b) }

type authenticatedPeer struct {
	*datagrams
	peer netip.AddrPort
}

func (p *authenticatedPeer) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	p.SetReadDeadline(time.Now().Add(2 * time.Minute))
	n, err := p.Read(b)
	if err != nil {
		return 0, p.peer, net.ErrClosed
	}
	return n, p.peer, nil
}
func (p *authenticatedPeer) WriteToUDPAddrPort(b []byte, peer netip.AddrPort) (int, error) {
	if peer != p.peer {
		return 0, net.ErrClosed
	}
	return p.Write(b)
}

type NativeListener struct {
	net.Listener
	mu      sync.Mutex
	closed  bool
	peers   map[net.Conn]bool
	pending int
}

func ListenNativeUDP(addr *net.UDPAddr, keys *Keys, open func(netip.AddrPort, uint32) (relay.Upstream, error)) (*NativeListener, error) {
	ln, err := dtls.Listen("udp", addr, datagramConfig(keys))
	if err != nil {
		return nil, err
	}
	l := &NativeListener{Listener: ln, peers: map[net.Conn]bool{}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			l.mu.Lock()
			if l.closed || l.pending >= 128 || len(l.peers) >= 8192 {
				l.mu.Unlock()
				c.Close()
				continue
			}
			l.pending++
			l.peers[c] = true
			l.mu.Unlock()
			go l.serve(c.(*dtls.Conn), open)
		}
	}()
	return l, nil
}
func (l *NativeListener) serve(c *dtls.Conn, open func(netip.AddrPort, uint32) (relay.Upstream, error)) {
	defer func() { c.Close(); l.mu.Lock(); delete(l.peers, c); l.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	err := c.HandshakeContext(ctx)
	cancel()
	l.mu.Lock()
	l.pending--
	l.mu.Unlock()
	if err != nil {
		return
	}
	peer := c.RemoteAddr().(*net.UDPAddr).AddrPort()
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	p := &authenticatedPeer{newDatagrams(c), peer}
	var bound uint32
	r := relay.UDPRelay{Conn: p, MaxSessions: 1, Open: open, Decode: func(b []byte) ([]byte, uint32, bool) {
		if len(b) < 4 {
			return nil, 0, false
		}
		id := binary.BigEndian.Uint32(b)
		if id == 0 || bound != 0 && id != bound {
			return nil, 0, false
		}
		bound = id
		return b[4:], id, true
	}}
	r.Serve()
	r.Close()
	r.Wait()
}
func (l *NativeListener) Close() error {
	l.mu.Lock()
	l.closed = true
	peers := make([]io.Closer, 0, len(l.peers))
	for c := range l.peers {
		peers = append(peers, c)
	}
	l.mu.Unlock()
	for _, c := range peers {
		c.Close()
	}
	return l.Listener.Close()
}
