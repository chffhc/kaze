package relay

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
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

const sniffWait = 3 * time.Second
const maxSniff = 64 << 10

// helloReader lets crypto/tls parse a ClientHello across records without sending a handshake.
type helloReader struct {
	net.Conn
	input io.Reader
}

func (c helloReader) Read(b []byte) (int, error)  { return c.input.Read(b) }
func (c helloReader) Write(b []byte) (int, error) { return len(b), nil }

func (p *SniffPolicy) Check(c net.Conn) ([]byte, bool) { return p.CheckInner(c, "") }
func (p *SniffPolicy) CheckInner(c net.Conn, outerHost string) ([]byte, bool) {
	var prefix bytes.Buffer
	c.SetReadDeadline(time.Now().Add(sniffWait))
	defer c.SetReadDeadline(time.Time{})
	r := bufio.NewReader(io.TeeReader(io.LimitReader(c, maxSniff), &prefix))
	first, err := r.Peek(1)
	if err != nil {
		return nil, false
	}
	switch first[0] {
	case ' ', '\t', '\r', '\n':
		return nil, false
	case 0x16:
		if p.BlockTLS {
			return nil, false
		}
		var host string
		parsed := false
		t := tls.Server(helloReader{c, r}, &tls.Config{GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			parsed = true
			host = chi.ServerName
			return nil, errors.New("inspection complete")
		}})
		_ = t.Handshake()
		return prefix.Bytes(), parsed && p.HostAllowed(host) && (host != "" || len(p.BlockedHosts) == 0)
	case 4, 5:
		return prefix.Bytes(), !p.BlockSocks && p.HostAllowed(outerHost)
	}
	// HTTP methods are case-sensitive tokens. Inspect the complete header before forwarding.
	for i := 1; i <= 32; i++ {
		b, err := r.Peek(i)
		if err != nil {
			return nil, false
		}
		ch := b[i-1]
		if ch == ' ' && i > 1 {
			host, valid := readPolicyHTTP(r)
			return prefix.Bytes(), valid && !p.BlockHTTP && p.HostAllowed(host)
		}
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || strings.ContainsRune("!#$%&'*+-.^_\u0060|~", rune(ch))) {
			return prefix.Bytes(), p.HostAllowed(outerHost)
		}
	}
	return nil, false
}

func readPolicyHTTP(r *bufio.Reader) (string, bool) {
	var head bytes.Buffer
	var authority string
	for lineNo := 0; ; lineNo++ {
		line, err := r.ReadString('\n')
		if err != nil || !strings.HasSuffix(line, "\r\n") || strings.ContainsAny(line[:len(line)-2], "\r\n") {
			return "", false
		}
		head.WriteString(line)
		if line == "\r\n" {
			break
		}
		if lineNo > 0 {
			if line[0] == ' ' || line[0] == '\t' {
				return "", false
			}
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				return "", false
			}
			if strings.EqualFold(key, "Host") {
				if authority != "" {
					return "", false
				}
				authority = strings.TrimSpace(value)
				if authority == "" {
					return "", false
				}
			}
		}
	}
	req, err := http.ReadRequest(bufio.NewReader(&head))
	if err != nil {
		return "", false
	}
	if authority == "" || !strings.EqualFold(req.Host, authority) {
		return "", false
	}
	host := authority
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host, true
}

func (p *SniffPolicy) HostAllowed(host string) bool {
	if MatchHostSuffix(host, p.BlockedHosts) {
		return false
	}
	return len(p.AllowedHosts) == 0 || MatchHostSuffix(host, p.AllowedHosts)
}

func MatchHostSuffix(host string, list []string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, entry := range list {
		domain := strings.Trim(strings.ToLower(strings.TrimSpace(entry)), ".")
		if domain != "" && (host == domain || strings.HasSuffix(host, "."+domain)) {
			return true
		}
	}
	return false
}
