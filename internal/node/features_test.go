package node

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"kaze/internal/proto"
	"kaze/internal/tunnel"
)

// ---- 辅助 ----

type outEnv struct {
	a   *Agent
	cfg *proto.OutboundConfig
	gid int64
	pin string
}

// startOut 启动一个出口节点。cfg 里没填的密钥、证书会自动补上。
func startOut(t *testing.T, gid int64, cfg *proto.OutboundConfig) *outEnv {
	t.Helper()
	a := newTestAgent(t)
	if cfg.Key == "" {
		cfg.Key = tunnel.NewKey()
	}
	if cfg.Path == "" {
		cfg.Path = "/t"
	}
	cfg.AllowPrivate = true
	e := &outEnv{a: a, cfg: cfg, gid: gid}
	if tunnel.TransportUsesTLS(cfg.Transport) {
		cfg.CertPEM, cfg.KeyPEM, e.pin, _ = tunnel.GenerateCert("cdn.example.com")
	}
	e.reload(t)
	return e
}

func (e *outEnv) reload(t *testing.T) {
	t.Helper()
	if err := e.a.applyConfig(&proto.NodeConfig{Role: proto.RoleOut, GroupID: e.gid, Outbound: e.cfg}, false); err != nil {
		t.Fatal(err)
	}
}

// spec 返回连接这个出口节点用的隧道配置。
func (e *outEnv) spec(mux bool, fp string) *proto.TunnelSpec {
	return &proto.TunnelSpec{
		GroupID: e.gid, Endpoints: []string{fmt.Sprintf("127.0.0.1:%d", e.a.out.listenPort())},
		Transport: e.cfg.Transport, Mux: mux, Key: e.cfg.Key, Path: e.cfg.Path, CertPin: e.pin, Fingerprint: fp,
	}
}

func startIn(t *testing.T, cfg *proto.InboundConfig) *Agent {
	t.Helper()
	a := newTestAgent(t)
	if err := a.applyConfig(&proto.NodeConfig{Role: proto.RoleIn, GroupID: 100, Inbound: cfg}, false); err != nil {
		t.Fatal(err)
	}
	return a
}

func testCert(t *testing.T, names ...string) (certPEM, keyPEM string, cert tls.Certificate, pool *x509.CertPool) {
	t.Helper()
	cp, kp, _, err := tunnel.GenerateCert(names...)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = tunnel.ParseCert(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	return cp, kp, cert, pool
}

// bannerServer 是一个测试目标:先回一行 "<tag> alpn=<协商的协议> first=<收到的第一行>",之后回显。
// tlsCfg 非 nil 时在 TLS 之上提供服务;proxyFirst 为 true 时在 TLS 握手之前先读一行明文(PROXY 头)。
func bannerServer(t *testing.T, tag string, tlsCfg *tls.Config, proxyFirst bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(10 * time.Second))
				var c net.Conn = raw
				pre := ""
				if proxyFirst {
					var err error
					if pre, err = readProxyHeader(raw); err != nil {
						return
					}
				}
				alpn := "-"
				if tlsCfg != nil {
					tc := tls.Server(raw, tlsCfg)
					if err := tc.Handshake(); err != nil {
						return
					}
					if p := tc.ConnectionState().NegotiatedProtocol; p != "" {
						alpn = p
					}
					c = tc
				}
				br := bufio.NewReader(c)
				first, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if pre == "" {
					pre = strings.TrimSpace(first)
				}
				fmt.Fprintf(c, "%s alpn=%s first=%s\n", tag, alpn, pre)
				io.Copy(c, br)
				if cw, ok := c.(interface{ CloseWrite() error }); ok {
					cw.CloseWrite()
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// readProxyHeader 从连接上精确读出一个 PROXY protocol 头(v1 文本或 v2 二进制),不多读一个字节,
// 并统一成 v1 的文本形式返回。
func readProxyHeader(c net.Conn) (string, error) {
	b := make([]byte, 1)
	if _, err := io.ReadFull(c, b); err != nil {
		return "", err
	}
	if b[0] == 'P' { // v1: "PROXY TCP4 src dst sport dport\r\n"
		line := []byte{'P'}
		for len(line) < 108 {
			if _, err := io.ReadFull(c, b); err != nil {
				return "", err
			}
			if line = append(line, b[0]); b[0] == '\n' {
				return strings.TrimSpace(string(line)), nil
			}
		}
		return "", fmt.Errorf("PROXY v1 头过长")
	}
	hdr := make([]byte, 16)
	hdr[0] = b[0]
	if _, err := io.ReadFull(c, hdr[1:]); err != nil {
		return "", err
	}
	if string(hdr[:12]) != "\r\n\r\n\x00\r\nQUIT\n" || hdr[12] != 0x21 {
		return "", fmt.Errorf("不是 PROXY 头: %q", hdr)
	}
	body := make([]byte, int(hdr[14])<<8|int(hdr[15]))
	if _, err := io.ReadFull(c, body); err != nil {
		return "", err
	}
	if hdr[13] != 0x11 || len(body) != 12 {
		return "", fmt.Errorf("只支持解析 TCP4 的 v2 头: fam=%x len=%d", hdr[13], len(body))
	}
	return fmt.Sprintf("PROXY TCP4 %v %v %d %d", net.IP(body[0:4]), net.IP(body[4:8]),
		int(body[8])<<8|int(body[9]), int(body[10])<<8|int(body[11])), nil
}

// tlsClient 以 TLS 连接入口。roots 为 nil 时不校验证书(入口用的是自动生成的自签名证书)。
func tlsClient(addr, sni string, alpn []string, roots *x509.CertPool) (*tls.Conn, error) {
	raw, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	tc := tls.Client(raw, &tls.Config{ServerName: sni, NextProtos: alpn, InsecureSkipVerify: roots == nil, RootCAs: roots})
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return tc, nil
}

// banner 发送一行 hello 并读回目标的横幅行。
func banner(c net.Conn) (string, error) {
	if _, err := c.Write([]byte("hello\n")); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(line), err
}

// tlsBanner 连接、握手并读取横幅;握手被拒绝时返回错误。
func tlsBanner(addr, sni string, alpn []string, roots *x509.CertPool) (string, error) {
	c, err := tlsClient(addr, sni, alpn, roots)
	if err != nil {
		return "", err
	}
	defer c.Close()
	return banner(c)
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(6 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("等待超时: %s", what)
}

// ---- http 伪装与指纹:经节点端到端 ----

func TestHTTPAndFingerprintForward(t *testing.T) {
	target := echoServer(t)
	cases := []struct {
		transport string
		mux       bool
		fp        string
	}{
		{tunnel.TransportHTTP, false, ""},
		{tunnel.TransportHTTP, true, ""},
		{tunnel.TransportTLS, true, "chrome"},
		{tunnel.TransportTLS, false, "firefox"},
		{tunnel.TransportWSS, true, "safari"},
		{tunnel.TransportTLS, true, "360"}, // 协商到 TLS 1.2:鉴权退回时间戳校验
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s/mux=%v/fp=%s", c.transport, c.mux, c.fp), func(t *testing.T) {
			out := startOut(t, 1, &proto.OutboundConfig{Transport: c.transport, Rules: []proto.OutRule{{ID: 7, Targets: []string{target}}}})
			p := freePort(t)
			in := startIn(t, &proto.InboundConfig{
				Rules:   []proto.Rule{{ID: 7, UserID: 1, ListenPort: p, Proto: "tcp+udp", OutGroup: 1}},
				Tunnels: map[int64]*proto.TunnelSpec{1: out.spec(c.mux, c.fp)},
			})
			addr := fmt.Sprintf("127.0.0.1:%d", p)
			tcpEcho(t, addr, 2<<20)
			tcpEcho(t, addr, 1)
			udpEcho(t, addr)
			if tr := in.in.collect(); len(tr) != 1 || tr[0].Up < 2<<20 || tr[0].Down < 2<<20 {
				t.Fatalf("流量统计不正确: %+v", tr)
			}
		})
	}
}

// ---- 反向隧道 ----

func TestReverseTunnelNodes(t *testing.T) {
	target := echoServer(t)
	revPort := freePort(t)
	certPEM, keyPEM, cert, _ := testCert(t, "edge.example.com")
	pin := tunnel.CertPin(&cert)

	out := startOut(t, 5, &proto.OutboundConfig{
		Transport: tunnel.TransportTLS,
		Rules:     []proto.OutRule{{ID: 7, Targets: []string{target}, ProxyProtocol: 0}},
		Reverse:   []proto.ReverseSpec{{Endpoint: fmt.Sprintf("127.0.0.1:%d", revPort), CertPin: pin, SNI: "edge.example.com", Fingerprint: "chrome"}},
	})

	in := newTestAgent(t)
	in.opt.RevPort = revPort
	p := freePort(t)
	// 入口手里没有出口的任何地址:能通就说明走的是出口拨入的连接
	cfg := &proto.InboundConfig{
		Rules:   []proto.Rule{{ID: 7, UserID: 1, ListenPort: p, Proto: "tcp+udp", OutGroup: 5}},
		Tunnels: map[int64]*proto.TunnelSpec{5: {GroupID: 5, Transport: tunnel.TransportTLS, Key: out.cfg.Key, Reverse: true}},
		Reverse: &proto.ReverseListen{CertPEM: certPEM, KeyPEM: keyPEM, Groups: map[int64]string{5: out.cfg.Key}},
	}
	apply := func() {
		if err := in.applyConfig(&proto.NodeConfig{Role: proto.RoleIn, GroupID: 100, Inbound: cfg}, false); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	waitUntil(t, "出口接入反向隧道", func() bool { _, up := in.in.reverseStatus(); return up == 1 })
	if total, up := out.a.out.reverseStatus(); total != 1 || up != 1 {
		t.Fatalf("出口侧状态: %d/%d", up, total)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", p)
	tcpEcho(t, addr, 3<<20)
	udpEcho(t, addr) // 反向隧道上 UDP 一律走流
	if hops := in.in.diag(7); len(hops) != 1 || hops[0].Error != "" || !strings.Contains(hops[0].To, "反向隧道") {
		t.Fatalf("诊断结果不符合预期: %+v", hops)
	}

	// 无关的配置变更(加一条规则)不应打断反向连接
	long, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer long.Close()
	ping := func() bool {
		long.Write([]byte("p"))
		long.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := io.ReadFull(long, make([]byte, 1))
		return err == nil
	}
	if !ping() {
		t.Fatal("长连接不通")
	}
	p2 := freePort(t)
	cfg.Rules = append(cfg.Rules, proto.Rule{ID: 8, UserID: 1, ListenPort: p2, Proto: "tcp", Targets: []string{target}})
	cfg.AllowPrivate = true
	apply()
	out.reload(t)
	if !ping() {
		t.Fatal("配置热更新不应打断反向隧道上的连接")
	}

	// 入口把出口组移出名单:会话断开,规则不再可用
	cfg.Reverse.Groups = map[int64]string{}
	apply()
	waitUntil(t, "移出名单后反向连接断开", func() bool { _, up := out.a.out.reverseStatus(); return up == 0 })
	if ping() {
		t.Fatal("移出名单后连接应被断开")
	}
	// 重新加入:出口自动重连(重连间隔带退避,多等一会)
	cfg.Reverse.Groups = map[int64]string{5: out.cfg.Key}
	apply()
	waitUntil(t, "重新加入后自动重连", func() bool { _, up := in.in.reverseStatus(); return up == 1 })
	tcpEcho(t, addr, 1000)

	// 面板撤掉反向隧道配置:入口关闭监听
	cfg.Reverse = nil
	apply()
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", revPort), time.Second); err == nil {
		c.Close()
		t.Fatal("撤掉配置后反向端口应停止监听")
	}
}

// ---- 链式出口 ----

func TestChainForward(t *testing.T) {
	// 目标回显它收到的第一行:PROXY 头里应当是访客的真实地址
	target := bannerServer(t, "origin", nil, false)
	echo := echoServer(t)

	// 入口 -> A -(http,不复用)-> B -(wss)-> C -> 目标;三跳各用不同的传输层
	c := startOut(t, 3, &proto.OutboundConfig{Transport: tunnel.TransportWSS, Rules: []proto.OutRule{
		{ID: 7, Targets: []string{target}, ProxyProtocol: 1},
		{ID: 8, Targets: []string{echo}},
	}})
	b := startOut(t, 2, &proto.OutboundConfig{Transport: tunnel.TransportHTTP,
		Rules:   []proto.OutRule{{ID: 7, Next: 31}, {ID: 8, Next: 31}},
		Tunnels: map[int64]*proto.TunnelSpec{31: c.spec(true, "")},
	})
	a := startOut(t, 1, &proto.OutboundConfig{Transport: tunnel.TransportTLS,
		Rules:   []proto.OutRule{{ID: 7, Next: 20}, {ID: 8, Next: 20}},
		Tunnels: map[int64]*proto.TunnelSpec{20: b.spec(false, "")},
	})
	p7, p8 := freePort(t), freePort(t)
	in := startIn(t, &proto.InboundConfig{
		Rules: []proto.Rule{
			{ID: 7, UserID: 1, ListenPort: p7, Proto: "tcp", OutGroup: 1, UDPStream: true},
			{ID: 8, UserID: 1, ListenPort: p8, Proto: "tcp+udp", OutGroup: 1, UDPStream: true},
		},
		Tunnels: map[int64]*proto.TunnelSpec{1: a.spec(true, "chrome")},
	})

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p7))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	line, err := banner(conn)
	want := fmt.Sprintf("origin alpn=- first=PROXY TCP4 127.0.0.1 127.0.0.1 %d ", conn.LocalAddr().(*net.TCPAddr).Port)
	if err != nil || !strings.HasPrefix(line, want) {
		t.Fatalf("三跳之后目标应看到访客的真实地址\n 得到: %q (%v)\n 期望前缀: %q", line, err, want)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", p8)
	tcpEcho(t, addr, 3<<20)
	tcpEcho(t, addr, 0)
	udpEcho(t, addr)
	if tr := in.in.collect(); len(tr) != 2 {
		t.Fatalf("流量应只在入口按规则统计: %+v", tr)
	}

	// 中间跳的诊断指向下一个出口组
	if hops := a.a.out.diag(8); len(hops) != 1 || hops[0].Error != "" || !strings.HasPrefix(hops[0].To, "出口 127.0.0.1:") {
		t.Fatalf("A 的诊断: %+v", hops)
	}
	if hops := c.a.out.diag(8); len(hops) != 1 || hops[0].Error != "" || hops[0].To != "目标 "+echo {
		t.Fatalf("C 的诊断: %+v", hops)
	}

	// 把 B 这一跳的下一跳配置撤掉:连接应被干净地拒绝,而不是挂住
	b.cfg.Tunnels = nil
	b.reload(t)
	x, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	x.Write([]byte("x"))
	x.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := x.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatal("下一跳不可用时连接应被关闭")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("下一跳不可用时连接不应挂住")
	}
}

// ---- TLS 入站 ----

func TestTLSInboundAlone(t *testing.T) {
	target := bannerServer(t, "plain", nil, false)
	p := freePort(t)
	in := startIn(t, &proto.InboundConfig{AllowPrivate: true, Rules: []proto.Rule{{
		ID: 1, UserID: 1, ListenPort: p, Proto: "tcp+udp", Targets: []string{target},
		TLS: &proto.TLSInbound{Mode: proto.TLSModeAlone, SNI: []string{"a.example.com", "b.example.com"}, ALPN: []string{"h2", "http/1.1"}},
	}}})
	addr := fmt.Sprintf("127.0.0.1:%d", p)

	for _, sni := range []string{"a.example.com", "B.Example.Com"} {
		c, err := tlsClient(addr, sni, []string{"http/1.1"}, nil)
		if err != nil {
			t.Fatalf("SNI %s 应当握手成功: %v", sni, err)
		}
		if got := c.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
			t.Fatalf("ALPN = %q", got)
		}
		// 入口终结了 TLS:目标收到的是明文
		if line, err := banner(c); err != nil || line != "plain alpn=- first=hello" {
			t.Fatalf("%q %v", line, err)
		}
		c.Close()
	}
	// 证书是为规则的 SNI 自动签发的
	c, _ := tlsClient(addr, "a.example.com", []string{"h2"}, nil)
	if names := c.ConnectionState().PeerCertificates[0].DNSNames; len(names) != 2 || names[0] != "a.example.com" {
		t.Fatalf("自签名证书的名称: %v", names)
	}
	c.Close()

	for name, try := range map[string]func() (string, error){
		"SNI 不在规则里": func() (string, error) { return tlsBanner(addr, "evil.example.com", []string{"h2"}, nil) },
		"没有 SNI":    func() (string, error) { return tlsBanner(addr, "", []string{"h2"}, nil) },
		"ALPN 没有交集": func() (string, error) { return tlsBanner(addr, "a.example.com", []string{"spdy/3"}, nil) },
		"没有声明 ALPN": func() (string, error) { return tlsBanner(addr, "a.example.com", nil, nil) },
	} {
		if line, err := try(); err == nil {
			t.Errorf("%s: 应当被拒绝,却得到 %q", name, line)
		}
	}
	// 明文客户端连不上 TLS 端口
	raw, _ := net.Dial("tcp", addr)
	raw.Write([]byte("GET / HTTP/1.1\r\nHost: a.example.com\r\n\r\n"))
	raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	if b, _ := io.ReadAll(raw); bytes.Contains(b, []byte("plain")) {
		t.Fatal("明文请求不应到达目标")
	}
	raw.Close()
	// TLS 入站只有 TCP:同端口不应监听 UDP
	if uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p}); err != nil {
		t.Fatalf("TLS 入站规则不应占用 UDP 端口: %v", err)
	} else {
		uc.Close()
	}
	if tr := in.in.collect(); len(tr) != 1 || tr[0].Up == 0 || tr[0].Down == 0 {
		t.Fatalf("流量统计: %+v", tr)
	}
}

// 自带证书;经隧道后由出口回源 TLS,并把协商出的 ALPN 带过去;PROXY 头在回源握手之前发出。
func TestTLSInboundOriginTLS(t *testing.T) {
	_, _, originCert, _ := testCert(t, "origin.internal")
	originCfg := &tls.Config{Certificates: []tls.Certificate{originCert}, NextProtos: []string{"h2", "http/1.1"}}
	origin := bannerServer(t, "tls-origin", originCfg, false)
	originPP := bannerServer(t, "pp-origin", originCfg, true)

	edgeCert, edgeKey, _, edgePool := testCert(t, "www.example.com")
	out := startOut(t, 1, &proto.OutboundConfig{Transport: tunnel.TransportTLS, Rules: []proto.OutRule{
		{ID: 1, Targets: []string{origin}, OriginTLS: &proto.OriginTLS{SNI: "origin.internal"}},
		{ID: 2, Targets: []string{originPP}, ProxyProtocol: 1, OriginTLS: &proto.OriginTLS{}},
		{ID: 3, Targets: []string{origin}, OriginTLS: &proto.OriginTLS{SNI: "wrong.internal", Verify: true}},
	}})
	p1, p2, p3, p4 := freePort(t), freePort(t), freePort(t), freePort(t)
	mk := func(id int64, port int, og int64) proto.Rule {
		r := proto.Rule{ID: id, UserID: 1, ListenPort: port, Proto: "tcp", OutGroup: og,
			TLS: &proto.TLSInbound{Mode: proto.TLSModeAlone, ALPN: []string{"h2", "http/1.1"}, CertPEM: edgeCert, KeyPEM: edgeKey}}
		if og != 0 {
			r.OriginTLS = &proto.OriginTLS{} // 与面板下发的一致:回源由出口执行,入口据此把 ALPN 带过去
		}
		return r
	}
	direct := mk(4, p4, 0) // 直出:回源 TLS 由入口自己做
	direct.Targets, direct.OriginTLS, direct.ProxyProtocol = []string{originPP}, &proto.OriginTLS{}, 2
	startIn(t, &proto.InboundConfig{
		AllowPrivate: true,
		Rules:        []proto.Rule{mk(1, p1, 1), mk(2, p2, 1), mk(3, p3, 1), direct},
		Tunnels:      map[int64]*proto.TunnelSpec{1: out.spec(true, "")},
	})
	at := func(p int) string { return fmt.Sprintf("127.0.0.1:%d", p) }

	// 客户端用规则自带的证书校验入口;h2 一路带到目标
	for _, alpn := range []string{"h2", "http/1.1"} {
		line, err := tlsBanner(at(p1), "www.example.com", []string{alpn}, edgePool)
		if err != nil || line != "tls-origin alpn="+alpn+" first=hello" {
			t.Fatalf("alpn=%s: %q %v", alpn, line, err)
		}
	}
	// 规则没限定 SNI:任何 SNI 都能握手,但证书校验只对证书里的名字成立
	if _, err := tlsBanner(at(p1), "other.example.com", []string{"h2"}, edgePool); err == nil {
		t.Fatal("证书名称不符时客户端校验应失败")
	}
	// PROXY 头先于回源 TLS 握手,以明文到达目标
	c, err := tlsClient(at(p2), "www.example.com", []string{"http/1.1"}, edgePool)
	if err != nil {
		t.Fatal(err)
	}
	line, err := banner(c)
	c.Close()
	if err != nil || !strings.HasPrefix(line, "pp-origin alpn=http/1.1 first=PROXY TCP4 127.0.0.1 ") {
		t.Fatalf("经隧道: %q %v", line, err)
	}
	// 直出 + PROXY v2:回源 TLS 由入口自己做,PROXY 头里的目的地址是访客连接的入口端口
	c, err = tlsClient(at(p4), "www.example.com", []string{"h2"}, edgePool)
	if err != nil {
		t.Fatal(err)
	}
	local := c.LocalAddr().(*net.TCPAddr).Port
	line, err = banner(c)
	c.Close()
	if want := fmt.Sprintf("pp-origin alpn=h2 first=PROXY TCP4 127.0.0.1 127.0.0.1 %d %d", local, p4); err != nil || line != want {
		t.Fatalf("直出: %q %v\n 期望 %q", line, err, want)
	}
	// 开启校验且名称不符:回源握手失败,客户端连接被关闭
	if line, err := tlsBanner(at(p3), "www.example.com", []string{"h2"}, edgePool); err == nil {
		t.Fatalf("回源证书校验失败时不应拿到数据: %q", line)
	}
}

func TestTLSInboundSNISplit(t *testing.T) {
	one := bannerServer(t, "one", nil, false)
	two := bannerServer(t, "two", nil, false)
	three := bannerServer(t, "three", nil, false)
	out := startOut(t, 1, &proto.OutboundConfig{Transport: tunnel.TransportHTTP, Rules: []proto.OutRule{{ID: 12, Targets: []string{two}}}})

	wildCert, wildKey, _, wildPool := testCert(t, "*.cdn.example.com")
	ownCert, ownKey, _, ownPool := testCert(t, "three.other.com")
	p := freePort(t)
	parent := proto.Rule{ID: 10, UserID: 0, ListenPort: p, Proto: "tcp",
		TLS: &proto.TLSInbound{Mode: proto.TLSModeParent, CertPEM: wildCert, KeyPEM: wildKey}}
	child := func(id, uid int64, og int64, target string, tl *proto.TLSInbound) proto.Rule {
		tl.Mode = proto.TLSModeChild
		r := proto.Rule{ID: id, UserID: uid, ListenPort: p, Proto: "tcp", OutGroup: og, TLS: tl}
		if og == 0 {
			r.Targets = []string{target}
		}
		return r
	}
	c1 := child(11, 1, 0, one, &proto.TLSInbound{SNI: []string{"one.cdn.example.com"}})
	c2 := child(12, 2, 1, "", &proto.TLSInbound{SNI: []string{"two.cdn.example.com", "alt.cdn.example.com"}, ALPN: []string{"h2"}})
	c3 := child(13, 2, 0, three, &proto.TLSInbound{SNI: []string{"three.other.com"}, CertPEM: ownCert, KeyPEM: ownKey})
	cfg := &proto.InboundConfig{
		AllowPrivate: true,
		Users:        map[int64]proto.UserLimit{1: {ConnLimit: 1}},
		Rules:        []proto.Rule{parent, c1, c2, c3},
		Tunnels:      map[int64]*proto.TunnelSpec{1: out.spec(false, "")},
	}
	in := newTestAgent(t)
	apply := func() {
		if err := in.applyConfig(&proto.NodeConfig{Role: proto.RoleIn, Inbound: cfg}, false); err != nil {
			t.Fatal(err)
		}
		if errs := in.in.ruleErrors(); len(errs) != 0 {
			t.Fatalf("规则启动失败: %v", errs)
		}
	}
	apply()
	addr := fmt.Sprintf("127.0.0.1:%d", p)

	// 同一个端口,按 SNI 分到三条规则;没有自带证书的子规则沿用母规则的通配符证书
	for _, tc := range []struct {
		sni  string
		alpn []string
		pool *x509.CertPool
		want string
	}{
		{"one.cdn.example.com", nil, wildPool, "one alpn=- first=hello"},
		{"two.cdn.example.com", []string{"h2"}, wildPool, "two alpn=- first=hello"},
		{"ALT.cdn.example.com", []string{"h2", "http/1.1"}, wildPool, "two alpn=- first=hello"},
		{"three.other.com", nil, ownPool, "three alpn=- first=hello"},
	} {
		line, err := tlsBanner(addr, tc.sni, tc.alpn, tc.pool)
		if err != nil || line != tc.want {
			t.Errorf("SNI %s: %q %v (期望 %q)", tc.sni, line, err, tc.want)
		}
	}
	for name, try := range map[string]func() (string, error){
		"未登记的 SNI":       func() (string, error) { return tlsBanner(addr, "nobody.cdn.example.com", nil, nil) },
		"没有 SNI":         func() (string, error) { return tlsBanner(addr, "", nil, nil) },
		"子规则要求的 ALPN 不符": func() (string, error) { return tlsBanner(addr, "two.cdn.example.com", []string{"http/1.1"}, nil) },
	} {
		if line, err := try(); err == nil {
			t.Errorf("%s: 应当被拒绝,却得到 %q", name, line)
		}
	}

	// 限制与统计都落在子规则上:用户 1 限 1 条连接
	hold, err := tlsClient(addr, "one.cdn.example.com", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	if line, err := banner(hold); err != nil || line != "one alpn=- first=hello" {
		t.Fatalf("%q %v", line, err)
	}
	if line, err := tlsBanner(addr, "one.cdn.example.com", nil, nil); err == nil {
		t.Fatalf("超出用户连接数限制的连接应被拒绝: %q", line)
	}
	if line, err := tlsBanner(addr, "three.other.com", nil, nil); err != nil || !strings.HasPrefix(line, "three") {
		t.Fatalf("其他用户不受影响: %q %v", line, err)
	}
	seen := map[int64]bool{}
	for _, tr := range in.in.collect() {
		seen[tr.RuleID] = tr.Up > 0 && tr.Down > 0
	}
	if !seen[11] || !seen[12] || !seen[13] || seen[10] {
		t.Fatalf("流量应记在子规则上,母规则没有流量: %v", seen)
	}

	// 热更新:删掉子规则 12 不影响子规则 11 上已有的连接
	renewedCert, renewedKey, _, renewedPool := testCert(t, "*.cdn.example.com")
	renewedTLS := *parent.TLS
	renewedTLS.CertPEM, renewedTLS.KeyPEM = renewedCert, renewedKey
	parent.TLS = &renewedTLS
	wildPool = renewedPool
	cfg.Rules = []proto.Rule{parent, c1, c3}
	apply()
	hold.Write([]byte("still-here\n"))
	hold.SetReadDeadline(time.Now().Add(2 * time.Second))
	if b := make([]byte, 11); func() error { _, err := io.ReadFull(hold, b); return err }() != nil || string(b) != "still-here\n" {
		t.Fatalf("删除无关子规则不应打断连接: %q", b)
	}
	if line, err := tlsBanner(addr, "two.cdn.example.com", []string{"h2"}, nil); err == nil {
		t.Fatalf("子规则删除后它的 SNI 应被拒绝: %q", line)
	}

	// 入口组的域名白名单、拒绝空 SNI、屏蔽 TLS 协议同样作用于 TLS 入站
	cfg.AllowedHosts = []string{".cdn.example.com"}
	apply()
	if _, err := tlsBanner(addr, "three.other.com", nil, nil); err == nil {
		t.Fatal("不在白名单里的 SNI 应被拒绝")
	}
	hold.Close()
	if line, err := tlsBanner(addr, "one.cdn.example.com", nil, nil); err != nil || !strings.HasPrefix(line, "one") {
		t.Fatalf("白名单内的 SNI 应当可用: %q %v", line, err)
	}
	cfg.AllowedHosts, cfg.BlockedProtocols = nil, []string{"tls"}
	apply()
	if _, err := tlsBanner(addr, "one.cdn.example.com", nil, nil); err == nil {
		t.Fatal("入口组屏蔽 TLS 后握手应失败")
	}

	// 母规则被删除:端口停止监听,子规则留在配置里但无法接入
	cfg.BlockedProtocols = nil
	apply()
	active, err := tlsClient(addr, "three.other.com", nil, ownPool)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if _, err := banner(active); err != nil {
		t.Fatal(err)
	}
	cfg.Rules = []proto.Rule{c1, c3}
	apply()
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c.Close()
		t.Fatal("母规则删除后端口应停止监听")
	}
	active.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := active.Read(make([]byte, 1)); err == nil {
		t.Fatal("母规则撤销后子规则连接仍可用")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("母规则撤销后子规则连接未关闭")
	}
	// 母规则回来:子规则立即恢复
	cfg.Rules = []proto.Rule{parent, c1, c3}
	apply()
	if line, err := tlsBanner(addr, "one.cdn.example.com", nil, wildPool); err != nil || !strings.HasPrefix(line, "one") {
		t.Fatalf("母规则恢复后子规则应当可用: %q %v", line, err)
	}
}

// 独占端口时的入口组策略:拒绝空 SNI、域名黑名单。
func TestTLSInboundGroupPolicy(t *testing.T) {
	target := bannerServer(t, "t", nil, false)
	p := freePort(t)
	cfg := &proto.InboundConfig{AllowPrivate: true, TLSRejectEmptySNI: true, BlockedHosts: []string{".blocked.com"},
		Rules: []proto.Rule{{ID: 1, UserID: 1, ListenPort: p, Proto: "tcp", Targets: []string{target}, TLS: &proto.TLSInbound{Mode: proto.TLSModeAlone}}}}
	in := startIn(t, cfg)
	addr := fmt.Sprintf("127.0.0.1:%d", p)
	if line, err := tlsBanner(addr, "anything.example.org", nil, nil); err != nil || line != "t alpn=- first=hello" {
		t.Fatalf("规则没限定 SNI 时任意 SNI 可用: %q %v", line, err)
	}
	if _, err := tlsBanner(addr, "", nil, nil); err == nil {
		t.Fatal("开启拒绝空 SNI 后,不带 SNI 的握手应失败")
	}
	if _, err := tlsBanner(addr, "x.blocked.com", nil, nil); err == nil {
		t.Fatal("黑名单里的 SNI 应被拒绝")
	}
	cfg.TLSRejectEmptySNI = false
	in.applyConfig(&proto.NodeConfig{Role: proto.RoleIn, Inbound: cfg}, false)
	if line, err := tlsBanner(addr, "", nil, nil); err != nil || !strings.HasPrefix(line, "t ") {
		t.Fatalf("关闭后不带 SNI 应当可用: %q %v", line, err)
	}
	// 大流量:TLS 入站走的是用户态拷贝,确认数据完整
	c, err := tlsClient(addr, "big.example.org", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	data := make([]byte, 4<<20)
	rand.Read(data)
	go func() {
		c.Write([]byte("hello\n"))
		c.Write(data)
		c.CloseWrite()
	}()
	br := bufio.NewReader(c)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(br)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("回显不一致: %d 字节, %v", len(got), err)
	}
}

// 配置不合法的 TLS 规则应当报错而不是悄悄以明文监听。
func TestTLSInboundBadConfig(t *testing.T) {
	target := echoServer(t)
	p1, p2, p3 := freePort(t), freePort(t), freePort(t)
	in := startIn(t, &proto.InboundConfig{AllowPrivate: true, Rules: []proto.Rule{
		{ID: 1, UserID: 1, ListenPort: p1, Proto: "tcp", Targets: []string{target}, TLS: &proto.TLSInbound{Mode: proto.TLSModeAlone, CertPEM: "garbage", KeyPEM: "garbage"}},
		{ID: 2, UserID: 1, ListenPort: p2, Proto: "tcp", Targets: []string{target}, TLS: &proto.TLSInbound{Mode: "mystery"}},
		{ID: 3, UserID: 1, ListenPort: p3, Proto: "tcp", Targets: []string{target}, TLS: &proto.TLSInbound{Mode: proto.TLSModeChild}},
	}})
	errs := in.in.ruleErrors()
	for id := int64(1); id <= 3; id++ {
		if errs[id] == "" {
			t.Errorf("规则 %d 应当启动失败", id)
		}
	}
	for _, p := range []int{p1, p2, p3} {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p), 500*time.Millisecond); err == nil {
			c.Close()
			t.Errorf("端口 %d 不应监听", p)
		}
	}
}

// 流头里的 ALPN 只在规则开了回源 TLS 时才带:否则保持 1.0 的流头格式,还没升级的出口也能处理。
func TestStreamHeaderALPNOnlyForOriginTLS(t *testing.T) {
	key := tunnel.NewKey()
	keys, _ := tunnel.DeriveKeys(key)
	got := make(chan tunnel.StreamHeader, 4)
	srv, err := tunnel.NewServer(tunnel.ServerConfig{Bind: "127.0.0.1", Transport: tunnel.TransportTCP, Keys: keys},
		func(conn net.Conn, h tunnel.StreamHeader) { got <- h; conn.Close() })
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	p1, p2 := freePort(t), freePort(t)
	mk := func(id int64, port int, origin *proto.OriginTLS) proto.Rule {
		return proto.Rule{ID: id, UserID: 1, ListenPort: port, Proto: "tcp", OutGroup: 1, OriginTLS: origin,
			TLS: &proto.TLSInbound{Mode: proto.TLSModeAlone, ALPN: []string{"h2", "http/1.1"}}}
	}
	startIn(t, &proto.InboundConfig{
		Rules: []proto.Rule{mk(1, p1, nil), mk(2, p2, &proto.OriginTLS{})},
		Tunnels: map[int64]*proto.TunnelSpec{1: {GroupID: 1, Endpoints: []string{fmt.Sprintf("127.0.0.1:%d", srv.Port())},
			Transport: tunnel.TransportTCP, Key: key}},
	})
	for port, want := range map[int]string{p1: "", p2: "h2"} {
		c, err := tlsClient(fmt.Sprintf("127.0.0.1:%d", port), "x.test", []string{"h2"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.ConnectionState().NegotiatedProtocol != "h2" {
			t.Fatal("入口应当与客户端协商出 h2")
		}
		select {
		case h := <-got:
			if h.ALPN != want || h.Src.Addr().String() != "127.0.0.1" {
				t.Errorf("端口 %d: 流头里的 ALPN = %q,应为 %q", port, h.ALPN, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("出口没有收到流")
		}
		c.Close()
	}
}
