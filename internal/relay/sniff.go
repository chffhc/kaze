package relay

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"time"
)

// SniffPolicy 是入口的入站审计策略:按首包识别协议并按 SNI / Host 后缀做黑白名单。
type SniffPolicy struct {
	BlockHTTP, BlockTLS, BlockSocks bool
	BlockedHosts, AllowedHosts      []string
}

// NewSniffPolicy 由配置构建策略;未启用任何项时返回 nil。
func NewSniffPolicy(protocols, blockedHosts, allowedHosts []string) *SniffPolicy {
	p := &SniffPolicy{}
	for _, s := range protocols {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "http":
			p.BlockHTTP = true
		case "tls":
			p.BlockTLS = true
		case "socks":
			p.BlockSocks = true
		}
	}
	norm := func(in []string) (out []string) {
		for _, h := range in {
			if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
				out = append(out, h)
			}
		}
		return
	}
	p.BlockedHosts, p.AllowedHosts = norm(blockedHosts), norm(allowedHosts)
	if !p.BlockHTTP && !p.BlockTLS && !p.BlockSocks && len(p.BlockedHosts) == 0 && len(p.AllowedHosts) == 0 {
		return nil
	}
	return p
}

const sniffWait = 300 * time.Millisecond

// Check 读取客户端首包并裁决。返回已读出的数据(放行时需要先转发给目标)。
// 客户端在 300ms 内不发数据(服务端先说话的协议)时:无白名单则放行,有白名单则拒绝。
func (p *SniffPolicy) Check(c net.Conn) (prefix []byte, ok bool) {
	buf := make([]byte, 4096)
	c.SetReadDeadline(time.Now().Add(sniffWait))
	n, err := c.Read(buf)
	if n == 0 {
		c.SetReadDeadline(time.Time{})
		if ne, isNet := err.(net.Error); isNet && ne.Timeout() {
			return nil, len(p.AllowedHosts) == 0
		}
		return nil, false
	}
	// TLS ClientHello 可能跨多个 TCP 段,尽量读完整条记录再解析 SNI。
	if n >= 5 && buf[0] == 0x16 && buf[1] == 0x03 {
		need := 5 + int(binary.BigEndian.Uint16(buf[3:5]))
		if need > len(buf) && need <= 5+16384 {
			nb := make([]byte, need)
			copy(nb, buf[:n])
			buf = nb
		}
		for n < need && n < len(buf) {
			m, err := c.Read(buf[n:])
			n += m
			if err != nil {
				break
			}
		}
	}
	c.SetReadDeadline(time.Time{})
	return buf[:n], p.verdict(buf[:n])
}

func (p *SniffPolicy) verdict(b []byte) bool {
	proto, host := detect(b)
	switch proto {
	case "http":
		if p.BlockHTTP {
			return false
		}
	case "tls":
		if p.BlockTLS {
			return false
		}
	case "socks":
		if p.BlockSocks {
			return false
		}
	}
	return p.HostAllowed(host)
}

// HostAllowed 按域名黑白名单裁决一个主机名(首包里嗅探到的,或 TLS 入站握手中的 SNI)。
// 配置了白名单时,没有主机名的连接一律不放行。
func (p *SniffPolicy) HostAllowed(host string) bool {
	host = strings.ToLower(host)
	if len(p.AllowedHosts) > 0 {
		return host != "" && matchSuffix(host, p.AllowedHosts)
	}
	return host == "" || !matchSuffix(host, p.BlockedHosts)
}

func matchSuffix(host string, list []string) bool {
	for _, s := range list {
		if strings.HasSuffix(host, s) {
			return true
		}
	}
	return false
}

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("DELETE "),
	[]byte("OPTIONS "), []byte("CONNECT "), []byte("PATCH "), []byte("TRACE "),
}

// detect 识别首包协议,并尽力提取 TLS SNI 或 HTTP Host。
func detect(b []byte) (proto, host string) {
	if len(b) >= 3 && b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x04 {
		return "tls", parseSNI(b)
	}
	for _, m := range httpMethods {
		if bytes.HasPrefix(b, m) {
			return "http", parseHTTPHost(b)
		}
	}
	if len(b) >= 3 && b[0] == 0x05 && int(b[1]) > 0 && len(b) == 2+int(b[1]) {
		return "socks", ""
	}
	if len(b) >= 9 && b[0] == 0x04 && (b[1] == 0x01 || b[1] == 0x02) && b[len(b)-1] == 0 {
		return "socks", ""
	}
	return "", ""
}

func parseHTTPHost(b []byte) string {
	lower := bytes.ToLower(b)
	i := bytes.Index(lower, []byte("\r\nhost:"))
	if i < 0 {
		return ""
	}
	rest := b[i+7:]
	if j := bytes.IndexByte(rest, '\r'); j >= 0 {
		rest = rest[:j]
	}
	h := strings.TrimSpace(string(rest))
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return h
}

// parseSNI 从 TLS ClientHello 中提取 server_name。
func parseSNI(b []byte) string {
	if len(b) < 5+4 {
		return ""
	}
	b = b[5:] // record header
	if b[0] != 0x01 {
		return ""
	}
	b = b[4:] // handshake header
	if len(b) < 2+32+1 {
		return ""
	}
	b = b[2+32:]
	skip := func(lenBytes int) bool {
		if len(b) < lenBytes {
			return false
		}
		l := 0
		for i := 0; i < lenBytes; i++ {
			l = l<<8 | int(b[i])
		}
		if len(b) < lenBytes+l {
			return false
		}
		b = b[lenBytes+l:]
		return true
	}
	if !skip(1) || !skip(2) || !skip(1) { // session id, cipher suites, compression
		return ""
	}
	if len(b) < 2 {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if extLen < len(b) {
		b = b[:extLen]
	}
	for len(b) >= 4 {
		typ := binary.BigEndian.Uint16(b)
		l := int(binary.BigEndian.Uint16(b[2:]))
		b = b[4:]
		if l > len(b) {
			return ""
		}
		if typ == 0 { // server_name
			d := b[:l]
			if len(d) < 5 {
				return ""
			}
			nl := int(binary.BigEndian.Uint16(d[3:5]))
			if d[2] != 0 || 5+nl > len(d) {
				return ""
			}
			return string(d[5 : 5+nl])
		}
		b = b[l:]
	}
	return ""
}
