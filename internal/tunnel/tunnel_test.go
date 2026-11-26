package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-yamux/v5"

	"kaze/internal/proto"
	"kaze/internal/relay"
)

// hashServer 读到 EOF 后回写收到数据的 SHA-256:只有半关闭语义正确才能拿到响应。
func hashServer(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				h := sha256.New()
				io.Copy(h, c)
				c.Write(h.Sum(nil))
			}()
		}
	}()
	return ln
}

var testSrc = netip.MustParseAddrPort("1.2.3.4:1234")

// pipeHandler 是出口侧的流处理:校验流头后连接 target 并转发。
func pipeHandler(target string) Handler {
	d := relay.NewDialer(true)
	var sink atomic.Int64
	return func(conn net.Conn, h StreamHeader) {
		if h.RuleID != 42 || h.Src != testSrc {
			relay.Abort(conn)
			return
		}
		tc, err := d.DialTCP(context.Background(), target)
		if err != nil {
			relay.Abort(conn)
			return
		}
		relay.Pipe(conn, tc, &relay.PipeOpts{Up: &sink, Down: &sink})
	}
}

func startPair(t *testing.T, transport string, mux bool, fp, target string) (*Client, *Server) {
	t.Helper()
	key := NewKey()
	keys, _ := DeriveKeys(key)
	cfg := ServerConfig{Bind: "127.0.0.1", Transport: transport, Keys: keys, Path: "/tun"}
	pin := ""
	if TransportUsesTLS(transport) {
		cp, kp, p, err := GenerateCert("example.com")
		if err != nil {
			t.Fatal(err)
		}
		cert, err := ParseCert(cp, kp)
		if err != nil {
			t.Fatal(err)
		}
		if CertPin(&cert) != p {
			t.Fatal("CertPin 与 GenerateCert 返回的指纹不一致")
		}
		cfg.Cert, pin = &cert, p
	}
	srv, err := NewServer(cfg, pipeHandler(target))
	if err != nil {
		t.Fatal(err)
	}
	cli, err := NewClient(&proto.TunnelSpec{
		Endpoints: []string{fmt.Sprintf("127.0.0.1:%d", srv.Port())},
		Transport: transport, Mux: mux, Key: key, Path: "/tun", CertPin: pin, SNI: "example.com", Fingerprint: fp,
	}, ClientOpts{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return cli, srv
}

// roundTrip 经隧道发送 size 字节并校验目标回写的哈希。
func roundTrip(t *testing.T, cli *Client, size int) error {
	data := make([]byte, size)
	rand.Read(data)
	want := sha256.Sum256(data)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, done, err := cli.Open(ctx, StreamHeader{Cmd: CmdTCP, RuleID: 42, Src: testSrc})
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer done()
	defer conn.Close()
	go func() {
		conn.Write(data)
		relay.CloseWrite(conn)
	}()
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("read: %w (已读 %d 字节)", err, len(got))
	}
	if !bytes.Equal(got, want[:]) {
		return fmt.Errorf("哈希不一致: 收到 %d 字节", len(got))
	}
	return nil
}

func concurrentRoundTrips(t *testing.T, cli *Client, n int) {
	t.Helper()
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := roundTrip(t, cli, 1<<20+i*7919); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
}

func TestTunnelTransports(t *testing.T) {
	target := hashServer(t)
	for _, tr := range []string{TransportTCP, TransportTLS, TransportWS, TransportWSS, TransportHTTP} {
		for _, mux := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/mux=%v", tr, mux), func(t *testing.T) {
				cli, _ := startPair(t, tr, mux, "", target.Addr().String())
				concurrentRoundTrips(t, cli, 8)
				// 空载荷:只有流头和半关闭
				if err := roundTrip(t, cli, 0); err != nil {
					t.Error(err)
				}
			})
		}
	}
}

// 每个指纹在 tls 与 wss 上都要能握手、通过鉴权并正确传输数据。
func TestFingerprints(t *testing.T) {
	target := hashServer(t)
	for _, fp := range Fingerprints() {
		for _, tr := range []string{TransportTLS, TransportWSS} {
			t.Run(fp+"/"+tr, func(t *testing.T) {
				cli, _ := startPair(t, tr, tr == TransportWSS, fp, target.Addr().String())
				for i := 0; i < 3; i++ {
					if err := roundTrip(t, cli, 200_000); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
	if ValidFingerprint("netscape") || !ValidFingerprint("") || !ValidFingerprint("chrome") {
		t.Fatal("ValidFingerprint 判断有误")
	}
}

// 指纹模式下 ClientHello 应当和 Go 标准库的不同,并且带上配置的 SNI。
func TestFingerprintChangesClientHello(t *testing.T) {
	capture := func(fp string) []byte {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		defer ln.Close()
		got := make(chan []byte, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			buf := make([]byte, 8192)
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _ := io.ReadAtLeast(c, buf, 5)
			need := 5 + int(buf[3])<<8 + int(buf[4])
			for n < need && n < len(buf) {
				m, err := c.Read(buf[n:])
				if n += m; err != nil {
					break
				}
			}
			got <- buf[:n]
		}()
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		newTLSDialer("cdn.example.com", strings.Repeat("0", 64), fp, nil).handshake(ctx, raw, ln.Addr().String())
		return <-got
	}
	std, chrome := capture(""), capture("chrome")
	if len(std) < 100 || len(chrome) < 100 {
		t.Fatalf("没有抓到 ClientHello: %d / %d", len(std), len(chrome))
	}
	if !bytes.Contains(chrome, []byte("cdn.example.com")) || !bytes.Contains(std, []byte("cdn.example.com")) {
		t.Fatal("ClientHello 里没有 SNI")
	}
	// Chrome 的握手带有 GREASE、ALPS、证书压缩等扩展,长度明显大于 Go 默认握手
	if len(chrome) <= len(std) || bytes.Equal(std[5:40], chrome[5:40]) && len(chrome) == len(std) {
		t.Fatalf("指纹没有生效: std=%d chrome=%d", len(std), len(chrome))
	}
	// h2 是 Chrome 预设 ALPN 的一部分,而这里没有给标准库配置 ALPN
	if !bytes.Contains(chrome, []byte("\x02h2")) || bytes.Contains(std, []byte("\x02h2")) {
		t.Fatal("ALPN 与预期不符")
	}
}

func TestPinMismatch(t *testing.T) {
	target := hashServer(t)
	for _, fp := range []string{"", "chrome", "firefox", "360"} {
		for _, tr := range []string{TransportTLS, TransportWSS} {
			cli, _ := startPair(t, tr, false, fp, target.Addr().String())
			spec := cli.Spec
			spec.CertPin = strings.Repeat("ab", 32)
			bad, err := NewClient(&spec, ClientOpts{})
			if err != nil {
				t.Fatal(err)
			}
			if err := roundTrip(t, bad, 100); err == nil {
				t.Errorf("fp=%q %s: 证书指纹不匹配时不应连接成功", fp, tr)
			}
			bad.Close()
		}
	}
}

func TestTunnelRejectsBadKey(t *testing.T) {
	target := hashServer(t)
	for _, tr := range []string{TransportTCP, TransportTLS, TransportWS, TransportWSS, TransportHTTP} {
		for _, mux := range []bool{false, true} {
			cli, _ := startPair(t, tr, mux, "", target.Addr().String())
			spec := cli.Spec
			spec.Key = NewKey() // 换一把密钥再连
			bad, _ := NewClient(&spec, ClientOpts{})
			if err := roundTrip(t, bad, 100); err == nil {
				t.Errorf("%s mux=%v: 错误密钥不应得到响应", tr, mux)
			}
			bad.Close()
			if err := roundTrip(t, cli, 100); err != nil {
				t.Errorf("%s mux=%v: 正确密钥应当仍然可用: %v", tr, mux, err)
			}
		}
	}
}

func TestUDPCipher(t *testing.T) {
	keys, _ := DeriveKeys(NewKey())
	in, out := NewUDPCipher(keys, true), NewUDPCipher(keys, false)
	msg := []byte("hello udp")
	pkt := in.Seal(nil, 7, msg)
	if len(pkt) != len(msg)+UDPOverhead {
		t.Fatalf("overhead = %d", len(pkt)-len(msg))
	}
	id, pt, ok := out.Open(append([]byte{}, pkt...))
	if !ok || id != 7 || !bytes.Equal(pt, msg) {
		t.Fatal("c2s 解密失败")
	}
	if _, _, ok := in.Open(append([]byte{}, pkt...)); ok {
		t.Fatal("方向密钥应当不同")
	}
	pkt[len(pkt)-1] ^= 1
	if _, _, ok := out.Open(pkt); ok {
		t.Fatal("篡改后不应通过校验")
	}
}

func TestStreamHeader(t *testing.T) {
	for _, h := range []StreamHeader{
		{Cmd: CmdTCP, RuleID: 1},
		{Cmd: CmdUDP, RuleID: 1 << 31, Src: netip.MustParseAddrPort("10.1.2.3:65535")},
		{Cmd: CmdTCP, RuleID: 99, Src: netip.MustParseAddrPort("[2001:db8::1]:443"), ALPN: "h2"},
		{Cmd: CmdTCP, RuleID: 7, ALPN: strings.Repeat("x", maxALPNLen)},
	} {
		b := appendStreamHeader(nil, h)
		if len(b) > maxStreamHeader {
			t.Fatalf("流头超长: %d", len(b))
		}
		got, err := readStreamHeader(bytes.NewReader(append(b, "payload"...)))
		if err != nil || got != h {
			t.Fatalf("往返不一致: %+v -> %+v (%v)", h, got, err)
		}
	}
	// 不带 ALPN 的流头与 1.0 版本的编码一致
	b := appendStreamHeader(nil, StreamHeader{Cmd: CmdTCP, RuleID: 5, Src: netip.MustParseAddrPort("1.2.3.4:80")})
	if !bytes.Equal(b, []byte{1, 0, 0, 0, 5, 4, 1, 2, 3, 4, 0, 80}) {
		t.Fatalf("编码变了: %v", b)
	}
	// 过长的 ALPN 不传递
	if h, _ := readStreamHeader(bytes.NewReader(appendStreamHeader(nil, StreamHeader{Cmd: CmdTCP, ALPN: strings.Repeat("x", 40)}))); h.ALPN != "" {
		t.Fatal("过长的 ALPN 应被丢弃")
	}
	for _, bad := range [][]byte{{3, 0, 0, 0, 1, 0, 0, 0}, {1, 0, 0, 0, 1, 9, 0, 0}, {0x81, 0, 0, 0, 1, 0, 0, 0, 0}, {0x81, 0, 0, 0, 1, 0, 0, 0, 33}} {
		if _, err := readStreamHeader(bytes.NewReader(append(bad, make([]byte, 64)...))); err == nil {
			t.Fatalf("应当拒绝: %v", bad)
		}
	}
}

func TestPrefaceReplay(t *testing.T) {
	keys, _ := DeriveKeys(NewKey())
	var rc replayCache
	now := time.Now()
	p := appendPreface(nil, keys, flagMux, nil, now)
	if _, err := verifyPreface(p, keys, nil, now, &rc); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPreface(p, keys, nil, now, &rc); err != errReplay {
		t.Fatalf("重放应被拒绝: %v", err)
	}
	old := appendPreface(nil, keys, 0, nil, now.Add(-10*time.Minute))
	if _, err := verifyPreface(old, keys, nil, now, &rc); err != errClock {
		t.Fatalf("过期时间戳应被拒绝: %v", err)
	}
	// TLS 绑定:导出密钥不同则鉴权失败
	q := appendPreface(nil, keys, 0, []byte("ekm-a"), now)
	if _, err := verifyPreface(q, keys, []byte("ekm-b"), now, &rc); err != errAuth {
		t.Fatalf("EKM 不一致应被拒绝: %v", err)
	}
}

// ---- http 伪装传输层 ----

func httpServer(t *testing.T) (*Server, *Keys) {
	keys, _ := DeriveKeys(NewKey())
	srv, err := NewServer(ServerConfig{Bind: "127.0.0.1", Transport: TransportHTTP, Keys: keys, Path: "/api/v2/sync"},
		func(conn net.Conn, h StreamHeader) { io.Copy(conn, conn); conn.Close() })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv, keys
}

func httpExchange(t *testing.T, addr, req string) string {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte(req))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, _ := io.ReadAll(c)
	return string(b)
}

// 探测者(没有密钥)看到的应当是一个普通的 Web 服务器,而且各种错误的响应一致。
func TestHTTPCamouflageProbe(t *testing.T) {
	srv, keys := httpServer(t)
	addr := fmt.Sprintf("127.0.0.1:%d", srv.Port())
	other, _ := DeriveKeys(NewKey())
	badTok, _ := newHTTPToken(other, 0, time.Now())
	oldTok, _ := newHTTPToken(keys, 0, time.Now().Add(-time.Hour))
	strip := func(s string) string { // 去掉 Date 头再比较
		var out []string
		for _, l := range strings.Split(s, "\r\n") {
			if !strings.HasPrefix(l, "Date:") {
				out = append(out, l)
			}
		}
		return strings.Join(out, "\r\n")
	}
	var first string
	for name, req := range map[string]string{
		"浏览器访问":   "GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\n\r\n",
		"路径对但没令牌": "GET /api/v2/sync HTTP/1.1\r\nHost: x\r\n\r\n",
		"令牌格式不对":  "GET /api/v2/sync HTTP/1.1\r\nHost: x\r\nCookie: sid=abc\r\n\r\n",
		"别的密钥":    string(httpRequest("x", "/api/v2/sync", badTok)),
		"过期令牌":    string(httpRequest("x", "/api/v2/sync", oldTok)),
		"POST":    "POST /api/v2/sync HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
	} {
		resp := httpExchange(t, addr, req)
		if !strings.HasPrefix(resp, "HTTP/1.1 404 Not Found\r\nServer: nginx\r\n") || !strings.Contains(resp, "<center>nginx</center>") {
			t.Errorf("%s: 响应不像普通的 404: %q", name, resp)
		}
		if strings.Contains(strings.ToLower(resp), "upgrade") {
			t.Errorf("%s: 响应里不应出现 upgrade", name)
		}
		if first == "" {
			first = strip(resp)
		} else if strip(resp) != first {
			t.Errorf("%s: 不同的失败原因应当得到相同的响应", name)
		}
	}
	if resp := httpExchange(t, addr, "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03 garbage\r\n\r\n"); !strings.HasPrefix(resp, "HTTP/1.1 400 ") {
		t.Errorf("非 HTTP 数据应得到 400: %q", resp)
	}

	// 合法请求:头部里没有 upgrade 字样,同一个请求重放会被拒绝
	tok, _ := newHTTPToken(keys, 0, time.Now())
	req := string(httpRequest("cdn.example.com", "/api/v2/sync", tok))
	if strings.Contains(strings.ToLower(req), "upgrade") || !strings.HasPrefix(req, "GET /api/v2/sync HTTP/1.1\r\nHost: cdn.example.com\r\n") {
		t.Fatalf("请求头不符合预期: %q", req)
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte(req))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, _ := bufio.NewReader(c).ReadString('\n')
	if line != "HTTP/1.1 200 OK\r\n" {
		t.Fatalf("合法令牌应得到 200: %q", line)
	}
	if resp := httpExchange(t, addr, req); !strings.HasPrefix(resp, "HTTP/1.1 404 ") {
		t.Errorf("重放的请求应被拒绝: %q", resp)
	}
}

// 记录流:篡改、截断都必须被发现;读超时不能破坏流的同步。
func TestHTTPRecordIntegrity(t *testing.T) {
	keys, _ := DeriveKeys(NewKey())
	var rc replayCache
	pair := func() (cli net.Conn, srv net.Conn, wire net.Conn) {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		defer ln.Close()
		done := make(chan net.Conn, 1)
		go func() {
			raw, err := ln.Accept()
			if err != nil {
				done <- nil
				return
			}
			conn, _, err := acceptHTTP(raw, keys, "/", time.Now(), &rc)
			if err != nil {
				t.Error(err)
			}
			done <- conn
		}()
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		cli, err = dialHTTP(context.Background(), raw, keys, "h", "/", 0, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		srv = <-done
		if srv == nil {
			t.Fatal("服务端握手失败")
		}
		t.Cleanup(func() { cli.Close(); srv.Close() })
		return cli, srv, raw
	}

	t.Run("往返与半关闭", func(t *testing.T) {
		cli, srv, _ := pair()
		msg := make([]byte, 100_000) // 跨多条记录
		rand.Read(msg)
		go func() { cli.Write(msg); relay.CloseWrite(cli) }()
		got, err := io.ReadAll(srv)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("c2s: err=%v len=%d", err, len(got))
		}
		go func() { srv.Write(msg[:5000]); relay.CloseWrite(srv) }()
		got, err = io.ReadAll(cli)
		if err != nil || !bytes.Equal(got, msg[:5000]) {
			t.Fatalf("s2c: err=%v len=%d", err, len(got))
		}
	})

	t.Run("未发结束记录就断开", func(t *testing.T) {
		cli, srv, _ := pair()
		buf := make([]byte, 16)
		cli.Write([]byte("hello"))
		if n, err := io.ReadFull(srv, buf[:5]); err != nil || string(buf[:n]) != "hello" {
			t.Fatal(err)
		}
		srv.Write([]byte("x"))
		if _, err := io.ReadFull(cli, buf[:1]); err != nil { // 顺带读掉响应头,避免关闭时触发 RST
			t.Fatal(err)
		}
		cli.Close() // 异常中止:没有发结束记录
		if _, err := srv.Read(buf); err != io.ErrUnexpectedEOF {
			t.Fatalf("应当得到 ErrUnexpectedEOF: %v", err)
		}
		if _, err := srv.Read(buf); err != io.ErrUnexpectedEOF {
			t.Fatalf("错误应当保持: %v", err)
		}
	})

	t.Run("篡改密文", func(t *testing.T) {
		cli, srv, wire := pair()
		cli.Write([]byte("ok"))
		buf := make([]byte, 64)
		if _, err := io.ReadFull(srv, buf[:2]); err != nil {
			t.Fatal(err)
		}
		// 绕过加密层,直接往线路上写一条长度合法但内容伪造的记录
		forged := append([]byte{0, 20}, bytes.Repeat([]byte{0x41}, 20)...)
		wire.Write(forged)
		if _, err := srv.Read(buf); err != errHTTPRecord {
			t.Fatalf("伪造的记录应被拒绝: %v", err)
		}
	})

	t.Run("读超时后继续", func(t *testing.T) {
		cli, srv, wire := pair()
		// 先只发出一条记录的前半截
		hc := cli.(*httpConn)
		rec := hc.appendRecord(nil, []byte("split-record-payload"))
		wire.Write(rec[:7])
		buf := make([]byte, 64)
		srv.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := srv.Read(buf); !isTimeout(err) {
			t.Fatalf("应当超时: %v", err)
		}
		wire.Write(rec[7:])
		srv.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := srv.Read(buf)
		if err != nil || string(buf[:n]) != "split-record-payload" {
			t.Fatalf("超时后应能接着读完这条记录: %q %v", buf[:n], err)
		}
	})

	// fake 起一个假出口:收下请求头后回一段固定内容(可以为空),再保持连接一段时间;返回连到它的连接
	fake := func(reply []byte, hold time.Duration) net.Conn {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		t.Cleanup(func() { ln.Close() })
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			readHTTPHead(bufio.NewReader(c))
			c.Write(reply)
			time.Sleep(hold)
		}()
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { raw.Close() })
		return raw
	}

	t.Run("出口迟迟不回响应头", func(t *testing.T) {
		raw := fake(nil, 3*time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		t0 := time.Now()
		if _, err := dialHTTP(ctx, raw, keys, "h", "/", 0, time.Now()); err == nil || time.Since(t0) > 2*time.Second {
			t.Fatalf("握手应当按期限超时: %v (%v)", err, time.Since(t0))
		}
	})

	t.Run("出口回了别的响应", func(t *testing.T) {
		for name, reply := range map[string][]byte{
			"404":     httpReject(404, time.Now()),
			"缺随机数":    []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"),
			"随机数长度不对": []byte("HTTP/1.1 200 OK\r\nETag: \"YWJj\"\r\n\r\n"),
			"不是 HTTP": []byte("SSH-2.0-OpenSSH_9.6\r\n\r\n"),
		} {
			if c, err := dialHTTP(context.Background(), fake(reply, 0), keys, "h", "/", 0, time.Now()); err == nil {
				c.Close()
				t.Errorf("%s: 握手不应成功", name)
			}
		}
	})

	// 被动截获了一条连接的请求头和数据的人,换一台出口(各自记各自见过的令牌)或等出口重启后重放:
	// 令牌还在有效期内,握手会成功,但密钥里有出口这一次新给的随机数,旧数据解不开。
	t.Run("截获的请求和数据不能重放", func(t *testing.T) {
		token, head := newHTTPToken(keys, 0, time.Now())
		req := httpRequest("h", "/", token)
		handshake := func(seen *replayCache) (srv net.Conn, wire net.Conn, snonce []byte) {
			ln, _ := net.Listen("tcp", "127.0.0.1:0")
			defer ln.Close()
			done := make(chan net.Conn, 1)
			go func() {
				raw, err := ln.Accept()
				if err != nil {
					done <- nil
					return
				}
				conn, _, err := acceptHTTP(raw, keys, "/", time.Now(), seen)
				if err != nil {
					raw.Close()
					conn = nil
				}
				done <- conn
			}()
			wire, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { wire.Close() })
			wire.Write(req)
			wire.SetReadDeadline(time.Now().Add(3 * time.Second))
			first, hdr, err := readHTTPHead(bufio.NewReader(wire))
			if srv = <-done; srv == nil {
				return nil, wire, nil
			}
			if err != nil || !strings.HasPrefix(first, "HTTP/1.1 200") {
				t.Fatalf("握手失败: %q %v", first, err)
			}
			t.Cleanup(func() { srv.Close() })
			snonce = []byte(strings.Trim(hdr["etag"], `"`))
			return srv, wire, snonce
		}
		var nodeA, nodeB replayCache
		srvA, wireA, etagA := handshake(&nodeA)
		snA, _ := base64.RawURLEncoding.DecodeString(string(etagA))
		rec := newHTTPConn(wireA, nil, keys, head, snA, true).appendRecord(nil, []byte("transfer 100"))
		wireA.Write(rec)
		buf := make([]byte, 64)
		srvA.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, err := srvA.Read(buf); err != nil || string(buf[:n]) != "transfer 100" {
			t.Fatalf("正常连接应当读到数据: %q %v", buf[:n], err)
		}
		// 同一台出口:令牌只能用一次
		if srv, _, _ := handshake(&nodeA); srv != nil {
			t.Fatal("同一台出口上重放令牌应被拒绝")
		}
		// 另一台出口:握手通过,但重放的数据通不过校验
		srvB, wireB, etagB := handshake(&nodeB)
		if srvB == nil || string(etagA) == string(etagB) {
			t.Fatal("另一台出口应当给出新的随机数")
		}
		wireB.Write(rec)
		srvB.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, err := srvB.Read(buf); err != errHTTPRecord {
			t.Fatalf("重放的数据不应被接受: %q %v", buf[:n], err)
		}
	})
}

// ---- 反向隧道 ----

type revEnv struct {
	ln   *ReverseListener
	cli  *Client
	key  string
	pin  string
	cert string
	ckey string
}

func startReverse(t *testing.T, target string, groups ...int64) *revEnv {
	t.Helper()
	ln, err := NewReverseListener("127.0.0.1", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ln.Close)
	e := &revEnv{ln: ln, key: NewKey()}
	e.cert, e.ckey, e.pin, _ = GenerateCert("edge.example.com")
	cert, _ := ParseCert(e.cert, e.ckey)
	keys, _ := DeriveKeys(e.key)
	allowed := map[int64]*Keys{}
	for _, g := range groups {
		allowed[g] = keys
	}
	ln.Update(&cert, allowed)
	e.cli, err = NewClient(&proto.TunnelSpec{GroupID: 7, Transport: TransportTLS, Key: e.key, Reverse: true}, ClientOpts{Reverse: ln})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *revEnv) dial(t *testing.T, group int64, key, pin, fp string, n int, target string) *ReverseDialer {
	t.Helper()
	keys, _ := DeriveKeys(key)
	d, err := NewReverseDialer(proto.ReverseSpec{
		Endpoint: fmt.Sprintf("127.0.0.1:%d", e.ln.Port()), CertPin: pin, SNI: "edge.example.com", Fingerprint: fp, Conns: n,
	}, group, keys, nil, pipeHandler(target))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("等待超时: %s", what)
}

func TestReverseTunnel(t *testing.T) {
	target := hashServer(t)
	for _, fp := range []string{"", "chrome", "360"} {
		t.Run("fp="+fp, func(t *testing.T) {
			e := startReverse(t, target.Addr().String(), 7)
			if err := roundTrip(t, e.cli, 100); err == nil {
				t.Fatal("出口接入之前不应能开流")
			}
			d := e.dial(t, 7, e.key, e.pin, fp, 2, target.Addr().String())
			waitFor(t, "两条反向连接建立", func() bool { n, _, err := e.ln.Ping(7); return err == nil && n == 2 })
			if d.Connected() != 2 {
				t.Fatalf("Connected = %d", d.Connected())
			}
			concurrentRoundTrips(t, e.cli, 8)
			if rev, n, _, err := e.cli.ReverseStatus(); !rev || n != 2 || err != nil {
				t.Fatalf("ReverseStatus: %v %d %v", rev, n, err)
			}
			if len(e.cli.Endpoints()) != 0 {
				t.Fatal("反向隧道不应有可拨的地址")
			}
			// 出口断开后自动重连
			d.mu.Lock()
			for c := range d.conns {
				c.Close()
			}
			d.mu.Unlock()
			waitFor(t, "连接断开", func() bool { n, _, _ := e.ln.Ping(7); return n < 2 })
			waitFor(t, "自动重连", func() bool { n, _, err := e.ln.Ping(7); return err == nil && n == 2 })
			if err := roundTrip(t, e.cli, 5000); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReverseTunnelAuth(t *testing.T) {
	target := hashServer(t)
	e := startReverse(t, target.Addr().String(), 7)
	addr := target.Addr().String()

	// 密钥不对、组不在名单里、入口证书不对:都不能建立会话
	e.dial(t, 7, NewKey(), e.pin, "", 1, addr)
	e.dial(t, 8, e.key, e.pin, "", 1, addr)
	e.dial(t, 7, e.key, strings.Repeat("cd", 32), "", 1, addr)
	time.Sleep(600 * time.Millisecond)
	if n, _, err := e.ln.Ping(7); err == nil || n != 0 {
		t.Fatalf("不合法的出口不应接入: n=%d err=%v", n, err)
	}
	if n, _, _ := e.ln.Ping(8); n != 0 {
		t.Fatal("名单之外的出口组不应接入")
	}

	// 合法出口接入后,把它移出名单:现有会话应被断开
	e.dial(t, 7, e.key, e.pin, "", 1, addr)
	waitFor(t, "合法出口接入", func() bool { n, _, err := e.ln.Ping(7); return err == nil && n == 1 })
	if err := roundTrip(t, e.cli, 1000); err != nil {
		t.Fatal(err)
	}
	cert, _ := ParseCert(e.cert, e.ckey)
	e.ln.Update(&cert, map[int64]*Keys{})
	waitFor(t, "移出名单后断开", func() bool { n, _, _ := e.ln.Ping(7); return n == 0 })
	if err := roundTrip(t, e.cli, 100); err == nil {
		t.Fatal("移出名单后不应还能开流")
	}

	// 换了密钥:旧密钥的会话断开,新密钥可以接入
	newKey := NewKey()
	nk, _ := DeriveKeys(newKey)
	e.ln.Update(&cert, map[int64]*Keys{7: nk})
	time.Sleep(300 * time.Millisecond)
	if n, _, _ := e.ln.Ping(7); n != 0 {
		t.Fatal("旧密钥的出口不应接入")
	}
}

// 反向隧道不可用时应当转到故障转移组。
func TestReverseFallback(t *testing.T) {
	target := hashServer(t)
	fwd, _ := startPair(t, TransportTLS, true, "", target.Addr().String())
	e := startReverse(t, target.Addr().String(), 7)
	spec := proto.TunnelSpec{GroupID: 7, Transport: TransportTLS, Key: e.key, Reverse: true, Fallback: &fwd.Spec}
	cli, err := NewClient(&spec, ClientOpts{Reverse: e.ln})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if err := roundTrip(t, cli, 3000); err != nil {
		t.Fatalf("应当经故障转移组转发: %v", err)
	}
	// 没有监听对象(节点未指定 -rev-port)时同样如此
	cli2, _ := NewClient(&spec, ClientOpts{})
	defer cli2.Close()
	if err := roundTrip(t, cli2, 3000); err != nil {
		t.Fatal(err)
	}
}

// 复用连接上只有发起转发的一端可以开流。出口(或冒充出口的人)反过来向入口开流时应被立即复位,
// 不会在入口这边堆积占用内存。
func TestMuxRejectsStreamsFromServerSide(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	entry, err := yamux.Client(a, yamuxConfig(false), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Close()
	exit, err := yamux.Server(b, yamuxConfig(true), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer exit.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 正常方向:入口开流,出口接受
	go func() {
		if st, err := exit.AcceptStream(); err == nil {
			io.Copy(st, st)
			st.Close()
		}
	}()
	st, err := entry.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st.Write([]byte("ping"))
	buf := make([]byte, 4)
	st.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(st, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("入口开的流应当可用: %v", err)
	}
	st.Close()

	// 反方向:出口开流,入口复位
	for i := 0; i < 50; i++ {
		rs, err := exit.OpenStream(ctx)
		if err != nil {
			break // 会话也可能因此被对端判为违规而关闭,同样达到目的
		}
		rs.Write([]byte("hello"))
		rs.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, err := rs.Read(buf); err == nil {
			t.Fatalf("入口不应接受出口开的流,却读到 %d 字节", n)
		} else if isTimeout(err) {
			t.Fatal("出口开的流应被立即复位,而不是挂住")
		}
		rs.Close()
	}
	if n := entry.NumStreams(); n != 0 {
		t.Fatalf("入口这边不应留下任何流: %d", n)
	}
}
