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

func isTokenByte(ch byte) bool {
	return ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' ||
		strings.ContainsRune("!#$%&'*+-.^_`|~", rune(ch))
}

func isHTTPMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
		"PRI", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK":
		return true
	}
	return false
}

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
	// Classify text protocols by method / first line before buffering full HTTP headers.
	var token bytes.Buffer
	for {
		ch, err := r.ReadByte()
		if err != nil {
			return nil, false
		}
		if (ch == 0x0b || ch == 0x0c) && isHTTPMethod(token.String()) {
			return nil, false
		}
		if ch == ' ' || ch == '\t' {
			rest, err := r.ReadString('\n')
			if err != nil {
				return nil, false
			}
			firstLine := token.String() + string(ch) + rest
			if firstLine == "PRI * HTTP/2.0\r\n" {
				var tail [8]byte
				if _, err := io.ReadFull(r, tail[:]); err != nil || string(tail[:]) != "\r\nSM\r\n\r\n" {
					return nil, false
				}
				return prefix.Bytes(), !p.BlockHTTP && p.HostAllowed(outerHost) && (outerHost != "" || len(p.BlockedHosts) == 0)
			}
			upperRest := strings.ToUpper(rest)
			if isHTTPMethod(token.String()) || strings.Contains(upperRest, "HTTP/") || strings.Contains(upperRest, "HTTP://") || strings.Contains(upperRest, "HTTPS://") {
				if ch != ' ' {
					return nil, false
				}
				host, valid := readPolicyHTTP(firstLine, r)
				return prefix.Bytes(), valid && !p.BlockHTTP && p.HostAllowed(host)
			}
			return prefix.Bytes(), p.HostAllowed(outerHost)
		}
		if !isTokenByte(ch) {
			return prefix.Bytes(), p.HostAllowed(outerHost)
		}
		token.WriteByte(ch)
	}
}

func readPolicyHTTP(firstLine string, r *bufio.Reader) (string, bool) {
	if !strings.HasSuffix(firstLine, "\r\n") || strings.ContainsAny(firstLine[:len(firstLine)-2], "\r\n\t") {
		return "", false
	}
	var head bytes.Buffer
	head.WriteString(firstLine)
	var authority string
	for {
		line, err := r.ReadString('\n')
		if err != nil || !strings.HasSuffix(line, "\r\n") || strings.ContainsAny(line[:len(line)-2], "\r\n") {
			return "", false
		}
		head.WriteString(line)
		if line == "\r\n" {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			return "", false
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.ContainsAny(key, " \t") {
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
	req, err := http.ReadRequest(bufio.NewReader(&head))
	if err != nil {
		return "", false
	}
	if authority == "" || !strings.EqualFold(req.Host, authority) {
		return "", false
	}
	if req.URL.Host != "" && !strings.EqualFold(req.URL.Host, authority) {
		return "", false
	}
	host := authority
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
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
