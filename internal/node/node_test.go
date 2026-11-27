package node

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"kaze/internal/proto"
	"kaze/internal/tunnel"
)

func newTestAgent(t *testing.T) *Agent {
	a := &Agent{opt: Options{StateDir: t.TempDir(), Bind: "127.0.0.1"}, sendCh: make(chan []byte, 64), hostname: "test"}
	a.loadState()
	a.in, a.out = newInbound(a), newOutbound(a)
	t.Cleanup(func() { a.in.stopAll(); a.out.stopAll() })
	return a
}

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// echoServer 同时提供 TCP 与 UDP 回显。
func echoServer(t *testing.T) string {
	return echoServerWithUDPPeer(t, nil)
}

func echoServerWithUDPPeer(t *testing.T, peers chan<- netip.AddrPort) string {
	var ln net.Listener
	var uc *net.UDPConn
	for attempt := 0; ; attempt++ {
		var err error
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		// A free ephemeral TCP port can already be in use for UDP.
		uc, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: ln.Addr().(*net.TCPAddr).Port})
		if err == nil {
			break
		}
		ln.Close()
		if !errors.Is(err, syscall.EADDRINUSE) || attempt >= 9 {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { ln.Close(); uc.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := uc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if peers != nil {
				peers <- from
			}
			uc.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	return ln.Addr().String()
}

func tcpEcho(t *testing.T, addr string, size int) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	data := make([]byte, size)
	rand.Read(data)
	go func() {
		c.Write(data)
		c.(*net.TCPConn).CloseWrite()
	}()
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read: %v (已读 %d)", err, len(got))
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("回显数据不一致: 发送 %d 收到 %d", len(data), len(got))
	}
}

func udpEcho(t *testing.T, addr string) {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 65535)
	for i := 0; i < 20; i++ {
		size := 100 + i*60
		if i == 19 {
			size = 16384
			if runtime.GOOS == "darwin" {
				// macOS defaults net.inet.udp.maxdgram to 9216; 9000 still exercises 4KB DTLS chunk reassembly.
				size = 9000
			}
		}
		msg := make([]byte, size)
		rand.Read(msg)
		var n int
		for try := 0; try < 5; try++ { // 会话首包可能因异步建会话而稍有延迟
			if _, werr := c.Write(msg); werr != nil {
				t.Fatalf("UDP 发送失败 #%d: %v", i, werr)
			}
			c.SetReadDeadline(time.Now().Add(time.Second))
			if n, err = c.Read(buf); err == nil {
				break
			}
		}
		if err != nil || !bytes.Equal(buf[:n], msg) {
			t.Fatalf("UDP 回显失败 #%d: %v", i, err)
		}
	}
}

// outNode 启动一个出口节点并返回入口使用的 TunnelSpec。
func outNode(t *testing.T, transport string, mux, udpOverTCP bool, rules []proto.OutRule) *proto.TunnelSpec {
	a := newTestAgent(t)
	key := tunnel.NewKey()
	cfg := &proto.OutboundConfig{Transport: transport, Key: key, Path: "/t", Rules: rules, AllowPrivate: true}
	pin := ""
	if transport == tunnel.TransportTLS || transport == tunnel.TransportWSS {
		cfg.CertPEM, cfg.KeyPEM, pin, _ = tunnel.GenerateCert("cdn.example.com")
	}
	if err := a.applyConfig(&proto.NodeConfig{Role: proto.RoleOut, Outbound: cfg}, false); err != nil {
		t.Fatal(err)
	}
	return &proto.TunnelSpec{
		GroupID: 1, Endpoints: []string{fmt.Sprintf("127.0.0.1:%d", a.out.listenPort())},
		Transport: transport, Mux: mux, Key: key, Path: "/t", CertPin: pin, UDPOverTCP: udpOverTCP,
	}
}

func TestDirectForward(t *testing.T) {
	target := echoServer(t)
	in := newTestAgent(t)
	p := freePort(t)
	err := in.applyConfig(&proto.NodeConfig{Role: proto.RoleIn, Inbound: &proto.InboundConfig{
		AllowPrivate: true,
		Rules:        []proto.Rule{{ID: 1, UserID: 1, ListenPort: p, Proto: "tcp+udp", Targets: []string{target}}},
	}}, false)
	if err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", p)
	tcpEcho(t, addr, 3<<20)
	udpEcho(t, addr)
	tr := in.in.collect()
	if len(tr) != 1 || tr[0].Up < 3<<20 || tr[0].Down < 3<<20 {
		t.Fatalf("流量统计不正确: %+v", tr)
	}
}

func TestTunnelForward(t *testing.T) {
	target := echoServer(t)
	cases := []struct {
		transport string
		mux, uot  bool
	}{
		{tunnel.TransportTLS, true, false},
		{tunnel.TransportTLS, false, true},
		{tunnel.TransportTCP, false, false},
		{tunnel.TransportTCP, true, true},
		{tunnel.TransportWS, true, false},
		{tunnel.TransportWSS, true, false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s/mux=%v/uot=%v", c.transport, c.mux, c.uot), func(t *testing.T) {
			spec := outNode(t, c.transport, c.mux, c.uot, []proto.OutRule{{ID: 7, Targets: []string{target}}})
			in := newTestAgent(t)
			p := freePort(t)
			err := in.applyConfig(&proto.NodeConfig{Role: proto.RoleIn, Inbound: &proto.InboundConfig{
				Rules:   []proto.Rule{{ID: 7, UserID: 1, ListenPort: p, Proto: "tcp+udp", OutGroup: 1}},
				Tunnels: map[int64]*proto.TunnelSpec{1: spec},
			}}, false)
			if err != nil {
				t.Fatal(err)
			}
			addr := fmt.Sprintf("127.0.0.1:%d", p)
			tcpEcho(t, addr, 2<<20)
			tcpEcho(t, addr, 100)
			udpEcho(t, addr)
			if tr := in.in.collect(); len(tr) != 1 || tr[0].Up < 2<<20 {
				t.Fatalf("流量统计不正确: %+v", tr)
			}
		})
	}
}

func TestPrivateTargetBlocked(t *testing.T) {
	target := echoServer(t)
	in := newTestAgent(t)
	p := freePort(t)
	in.applyConfig(&proto.NodeConfig{Role: proto.RoleIn, Inbound: &proto.InboundConfig{
		AllowPrivate: false,
		Rules:        []proto.Rule{{ID: 1, UserID: 1, ListenPort: p, Proto: "tcp", Targets: []string{target}}},
	}}, false)
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("x"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := c.Read(make([]byte, 1)); n != 0 {
		t.Fatal("内网目标应当被拦截")
	}
}

func TestSpeedLimitAndConnLimit(t *testing.T) {
	target := echoServer(t)
	in := newTestAgent(t)
	p := freePort(t)
	const rate = 512 * 1024 // 512KB/s
	in.applyConfig(&proto.NodeConfig{Role: proto.RoleIn, Inbound: &proto.InboundConfig{
		AllowPrivate: true,
		Users:        map[int64]proto.UserLimit{1: {SpeedLimit: rate, ConnLimit: 2}},
		Rules:        []proto.Rule{{ID: 1, UserID: 1, ListenPort: p, Proto: "tcp", Targets: []string{target}}},
	}}, false)
	addr := fmt.Sprintf("127.0.0.1:%d", p)
	t0 := time.Now()
	tcpEcho(t, addr, 1<<20) // 1MB @ 512KB/s,扣除突发量后应在 1.5s 以上
	if el := time.Since(t0); el < 1200*time.Millisecond || el > 6*time.Second {
		t.Fatalf("限速不生效: 1MB 用时 %v", el)
	}
	// 连接数限制:第三条并发连接应被拒绝
	c1, _ := net.Dial("tcp", addr)
	c2, _ := net.Dial("tcp", addr)
	defer c1.Close()
	defer c2.Close()
	c1.Write([]byte("a"))
	c2.Write([]byte("b"))
	io.ReadFull(c1, make([]byte, 1))
	io.ReadFull(c2, make([]byte, 1))
	c3, err := net.Dial("tcp", addr)
	if err == nil {
		defer c3.Close()
		c3.Write([]byte("c"))
		c3.SetReadDeadline(time.Now().Add(time.Second))
		if n, _ := c3.Read(make([]byte, 1)); n != 0 {
			t.Fatal("超出连接数限制的连接应被拒绝")
		}
	}
}

func TestProxyProtocolAndSniff(t *testing.T) {
	// 目标:读出首行并回写
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				line, _ := br.ReadString('\n')
				c.Write([]byte(line))
				// 读完剩余数据再关闭:带着未读数据 close 会发 RST,可能冲掉刚写出的响应
				io.Copy(io.Discard, br)
			}()
		}
	}()
	spec := outNode(t, tunnel.TransportTLS, true, false, []proto.OutRule{{ID: 9, Targets: []string{ln.Addr().String()}, ProxyProtocol: 1}})
	in := newTestAgent(t)
	p1, p2 := freePort(t), freePort(t)
	in.applyConfig(&proto.NodeConfig{Role: proto.RoleIn, Inbound: &proto.InboundConfig{
		AllowPrivate:     true,
		BlockedProtocols: []string{"http"},
		BlockedHosts:     []string{".blocked.com"},
		Tunnels:          map[int64]*proto.TunnelSpec{1: spec},
		Rules: []proto.Rule{
			{ID: 9, UserID: 1, ListenPort: p1, Proto: "tcp", OutGroup: 1},
			{ID: 10, UserID: 1, ListenPort: p2, Proto: "tcp", Targets: []string{ln.Addr().String()}, ProxyProtocol: 1},
		},
	}}, false)
	for _, p := range []int{p1, p2} {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("hello\n"))
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		line, _ := bufio.NewReader(c).ReadString('\n')
		c.Close()
		if !strings.HasPrefix(line, "PROXY TCP4 127.0.0.1 ") {
			t.Fatalf("端口 %d 未收到 PROXY 头: %q", p, line)
		}
	}
	// HTTP 被屏蔽
	c, _ := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p2))
	c.Write([]byte("GET / HTTP/1.1\r\nHost: a.com\r\n\r\n"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := c.Read(make([]byte, 16)); n != 0 {
		t.Fatal("HTTP 应被入站策略拦截")
	}
	c.Close()
}

func TestRuleHotReload(t *testing.T) {
	target := echoServer(t)
	in := newTestAgent(t)
	p1, p2 := freePort(t), freePort(t)
	mk := func(rules ...proto.Rule) *proto.NodeConfig {
		return &proto.NodeConfig{Role: proto.RoleIn, Inbound: &proto.InboundConfig{AllowPrivate: true, Rules: rules}}
	}
	r1 := proto.Rule{ID: 1, UserID: 1, ListenPort: p1, Proto: "tcp", Targets: []string{target}}
	r2 := proto.Rule{ID: 2, UserID: 1, ListenPort: p2, Proto: "tcp", Targets: []string{target}}
	in.applyConfig(mk(r1), false)
	// 建一条长连接,之后的无关配置变更不应打断它
	long, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p1))
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
	in.applyConfig(mk(r1, r2), false)
	if !ping() {
		t.Fatal("新增规则不应影响已有连接")
	}
	tcpEcho(t, fmt.Sprintf("127.0.0.1:%d", p2), 1000)
	in.applyConfig(mk(r2), false) // 删除规则 1:连接应被断开,端口应被释放
	if ping() {
		t.Fatal("规则删除后连接应被断开")
	}
	if _, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p1), time.Second); err == nil {
		t.Fatal("规则删除后端口应停止监听")
	}
	// 端口冲突应记录为规则错误
	busy, _ := net.Listen("tcp", "127.0.0.1:0")
	defer busy.Close()
	r3 := proto.Rule{ID: 3, UserID: 1, ListenPort: busy.Addr().(*net.TCPAddr).Port, Proto: "tcp", Targets: []string{target}}
	in.applyConfig(mk(r2, r3), false)
	if e := in.in.ruleErrors(); e[3] == "" {
		t.Fatal("端口被占用应上报规则错误")
	}
}
