// Package tunnel 实现入口与出口之间的隧道:
//
//	传输层   tcp(明文,专线用) / tls / ws / wss / http(伪 HTTP 头 + 加密记录流)
//	鉴权     连接前导帧 = HMAC-SHA256(预共享密钥, 时间戳 | 随机数 | TLS 导出密钥)
//	复用     yamux(支持半关闭与 RST),一条连接承载多条转发流,新流 0-RTT
//	UDP      原生 UDP + DTLS 1.2,或封装进隧道流(UDP over TCP)
//	指纹     tls / wss 可用 utls 模拟浏览器的 ClientHello
//	反向     出口主动拨入入口并保持复用会话,入口在其上开流(出口在内网时使用)
//
// 连接前导帧(入口 -> 出口,61 字节):
//
//	magic "KZ01" | flags(1) | 时间戳毫秒(8) | nonce(16) | mac(32)
//
// 流头(每条流的开头):
//
//	cmd(1) | 规则号(4) | atyp(1: 0/4/6) | 源 IP(0/4/16) | 源端口(2) [| alpn 长度(1) | alpn]
//
// cmd 的最高位置 1 时才带 alpn 字段:入口终结 TLS 后,把与客户端协商出的应用层协议告诉最后一跳,
// 回源 TLS 时声明同一个协议。没有这个字段的流头与 1.0 版本完全相同。
//
// 出口不回任何握手响应:入口发完头立刻开始转发(0-RTT),失败由出口直接复位。
// http 传输层例外:它没有前导帧,鉴权信息放在请求头的 Cookie 里,入口要等到出口的响应头才开始发数据,见 httpconn.go。
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

	cmdHasALPN = 0x80
	maxALPNLen = 32
	// 流头的最大长度
	maxStreamHeader = 1 + 4 + 1 + 16 + 2 + 1 + maxALPNLen

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
	udpPSK []byte
	http   []byte // http 伪装传输层:令牌校验与记录加密
	rev    []byte // 反向隧道:出口向入口证明身份
}

// Equal 报告两组密钥是否来自同一个预共享密钥。
func (k *Keys) Equal(o *Keys) bool {
	return k != nil && o != nil && hmac.Equal(k.auth, o.auth)
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
	return &Keys{
		auth: d("kaze auth v1"), udpPSK: d("kaze native DTLS v2"),
		http: d("kaze http v1"), rev: d("kaze reverse v1"),
	}, nil
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

// verifyPreface 校验前导帧。ekm 非空(绑定了 TLS 会话)时不检查时钟;
// 明文传输层校验时间戳与一次性随机数。
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
	ALPN   string         // TLS 入站时与客户端协商出的应用层协议(可为空;超过 32 字节的不传递)
}

func appendStreamHeader(dst []byte, h StreamHeader) []byte {
	alpn := h.ALPN
	if len(alpn) > maxALPNLen {
		alpn = ""
	}
	cmd := h.Cmd
	if alpn != "" {
		cmd |= cmdHasALPN
	}
	dst = append(dst, cmd)
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
	dst = binary.BigEndian.AppendUint16(dst, h.Src.Port())
	if alpn != "" {
		dst = append(dst, byte(len(alpn)))
		dst = append(dst, alpn...)
	}
	return dst
}

func readStreamHeader(r io.Reader) (h StreamHeader, err error) {
	var b [maxALPNLen]byte
	if _, err = io.ReadFull(r, b[:6]); err != nil {
		return
	}
	hasALPN := b[0]&cmdHasALPN != 0
	h.Cmd = b[0] &^ cmdHasALPN
	h.RuleID = binary.BigEndian.Uint32(b[1:5])
	if h.Cmd != CmdTCP && h.Cmd != CmdUDP {
		return h, errors.New("隧道流命令无效")
	}
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
	if hasALPN {
		if _, err = io.ReadFull(r, b[:1]); err != nil {
			return
		}
		n := int(b[0])
		if n == 0 || n > maxALPNLen {
			return h, errors.New("隧道流头无效")
		}
		if _, err = io.ReadFull(r, b[:n]); err != nil {
			return
		}
		h.ALPN = string(b[:n])
	}
	return h, nil
}
