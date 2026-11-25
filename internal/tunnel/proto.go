// Package tunnel 实现入口与出口之间的隧道:
//
//	传输层   tcp(明文,专线用) / tls / ws / wss
//	鉴权     连接前导帧 = HMAC-SHA256(预共享密钥, 时间戳 | 随机数 | TLS 导出密钥)
//	复用     yamux(支持半关闭与 RST),一条连接承载多条转发流,新流 0-RTT
//	UDP      原生 UDP + AES-256-GCM,或封装进隧道流(UDP over TCP)
//
// 连接前导帧(入口 -> 出口,61 字节):
//
//	magic "KZ01" | flags(1) | 时间戳毫秒(8) | nonce(16) | mac(32)
//
// 流头(每条流的开头):
//
//	cmd(1) | 规则号(4) | atyp(1: 0/4/6) | 源 IP(0/4/16) | 源端口(2)
//
// 出口不回任何握手响应:入口发完头立刻开始转发(0-RTT),失败由出口直接复位。
package tunnel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"
)

const (
	magic      = "KZ01"
	prefaceLen = 4 + 1 + 8 + 16 + 32

	flagMux = 1 << 0

	// CmdTCP / CmdUDP 是流头里的命令字。
	CmdTCP = 1
	CmdUDP = 2

	// 明文传输层(tcp/ws)下允许的时钟偏差;TLS 下鉴权绑定了会话导出密钥,不依赖时钟。
	authWindow = 120 * time.Second
)

var (
	errAuth   = errors.New("隧道鉴权失败")
	errReplay = errors.New("隧道鉴权重放")
	errClock  = errors.New("隧道鉴权时间戳超出允许范围,请检查系统时间")
)

// Keys 是由预共享密钥派生出的各用途子密钥。
type Keys struct {
	auth   []byte
	udpC2S []byte // 入口 -> 出口
	udpS2C []byte // 出口 -> 入口
}

// DeriveKeys 从 hex 编码的预共享密钥派生子密钥。
func DeriveKeys(keyHex string) (*Keys, error) {
	raw, err := hex.DecodeString(keyHex)
	if err != nil || len(raw) < 16 {
		return nil, errors.New("隧道密钥无效")
	}
	d := func(label string) []byte {
		m := hmac.New(sha256.New, raw)
		m.Write([]byte(label))
		return m.Sum(nil)
	}
	return &Keys{auth: d("kaze auth v1"), udpC2S: d("kaze udp c2s v1"), udpS2C: d("kaze udp s2c v1")}, nil
}

// NewKey 生成一个新的预共享密钥(hex)。
func NewKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func prefaceMAC(key, head, ekm []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(head)
	m.Write(ekm)
	return m.Sum(nil)
}

// appendPreface 追加一个连接前导帧。
func appendPreface(dst []byte, k *Keys, flags byte, ekm []byte, now time.Time) []byte {
	start := len(dst)
	dst = append(dst, magic...)
	dst = append(dst, flags)
	dst = binary.BigEndian.AppendUint64(dst, uint64(now.UnixMilli()))
	var nonce [16]byte
	rand.Read(nonce[:])
	dst = append(dst, nonce[:]...)
	return append(dst, prefaceMAC(k.auth, dst[start:], ekm)...)
}

// replayCache 记住时间窗内见过的 nonce,防止明文传输层上的前导帧重放。
type replayCache struct {
	mu   sync.Mutex
	seen map[[16]byte]int64
	last time.Time
}

func (r *replayCache) check(nonce [16]byte, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = make(map[[16]byte]int64)
	}
	if now.Sub(r.last) > time.Minute {
		r.last = now
		cut := now.Add(-2 * authWindow).UnixMilli()
		for k, t := range r.seen {
			if t < cut {
				delete(r.seen, k)
			}
		}
	}
	if _, dup := r.seen[nonce]; dup {
		return false
	}
	r.seen[nonce] = now.UnixMilli()
	return true
}

// verifyPreface 校验前导帧。ekm 非空(TLS)时不检查时钟。
func verifyPreface(p []byte, k *Keys, ekm []byte, now time.Time, rc *replayCache) (flags byte, err error) {
	if len(p) != prefaceLen || string(p[:4]) != magic {
		return 0, errAuth
	}
	head, mac := p[:prefaceLen-32], p[prefaceLen-32:]
	if !hmac.Equal(mac, prefaceMAC(k.auth, head, ekm)) {
		return 0, errAuth
	}
	if len(ekm) == 0 {
		ts := time.UnixMilli(int64(binary.BigEndian.Uint64(p[5:13])))
		if d := now.Sub(ts); d > authWindow || d < -authWindow {
			return 0, errClock
		}
		var nonce [16]byte
		copy(nonce[:], p[13:29])
		if !rc.check(nonce, now) {
			return 0, errReplay
		}
	}
	return p[4], nil
}

// StreamHeader 是每条隧道流的头部。
type StreamHeader struct {
	Cmd    byte
	RuleID uint32
	Src    netip.AddrPort // 客户端真实地址(可能无效)
}

func appendStreamHeader(dst []byte, h StreamHeader) []byte {
	dst = append(dst, h.Cmd)
	dst = binary.BigEndian.AppendUint32(dst, h.RuleID)
	a := h.Src.Addr().Unmap()
	switch {
	case a.Is4():
		b := a.As4()
		dst = append(dst, 4)
		dst = append(dst, b[:]...)
	case a.Is6():
		b := a.As16()
		dst = append(dst, 6)
		dst = append(dst, b[:]...)
	default:
		dst = append(dst, 0)
	}
	return binary.BigEndian.AppendUint16(dst, h.Src.Port())
}

func readStreamHeader(r io.Reader) (h StreamHeader, err error) {
	var b [24]byte
	if _, err = io.ReadFull(r, b[:6]); err != nil {
		return
	}
	h.Cmd = b[0]
	h.RuleID = binary.BigEndian.Uint32(b[1:5])
	var ipLen int
	switch b[5] {
	case 0:
	case 4:
		ipLen = 4
	case 6:
		ipLen = 16
	default:
		return h, errors.New("隧道流头无效")
	}
	if _, err = io.ReadFull(r, b[:ipLen+2]); err != nil {
		return
	}
	if ipLen > 0 {
		ip, _ := netip.AddrFromSlice(b[:ipLen])
		h.Src = netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[ipLen:]))
	}
	if h.Cmd != CmdTCP && h.Cmd != CmdUDP {
		return h, errors.New("隧道流命令无效")
	}
	return h, nil
}
