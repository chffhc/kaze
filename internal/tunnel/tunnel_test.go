package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kaze/internal/proto"
	"kaze/internal/relay"
)

// hashServer 读到 EOF 后回写收到数据的 SHA-256:只有半关闭语义正确才能拿到响应。
func hashServer(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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

func startPair(t *testing.T, transport string, mux bool, target string) (*Client, *Server) {
	key := NewKey()
	keys, _ := DeriveKeys(key)
	cfg := ServerConfig{Bind: "127.0.0.1", Transport: transport, Keys: keys, Path: "/tun"}
	pin := ""
	if transport == TransportTLS || transport == TransportWSS {
		cp, kp, p, err := GenerateCert("example.com")
		if err != nil {
			t.Fatal(err)
		}
		cert, err := ParseCert(cp, kp)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Cert, pin = &cert, p
	}
	d := relay.NewDialer(true)
	var dummy atomic.Int64
	srv, err := NewServer(cfg, func(conn net.Conn, h StreamHeader) {
		if h.RuleID != 42 || h.Src.Port() != 1234 {
			conn.Close()
			return
		}
		tc, err := d.DialTCP(context.Background(), target)
		if err != nil {
			relay.Abort(conn)
			return
		}
		relay.Pipe(conn, tc, &relay.PipeOpts{Up: &dummy, Down: &dummy})
	})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := NewClient(&proto.TunnelSpec{
		Endpoints: []string{fmt.Sprintf("127.0.0.1:%d", srv.Port())},
		Transport: transport, Mux: mux, Key: key, Path: "/tun", CertPin: pin, SNI: "example.com",
	}, ClientOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return cli, srv
}

func TestTunnelTransports(t *testing.T) {
	target := hashServer(t)
	defer target.Close()
	for _, tr := range []string{TransportTCP, TransportTLS, TransportWS, TransportWSS} {
		for _, mux := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/mux=%v", tr, mux), func(t *testing.T) {
				cli, srv := startPair(t, tr, mux, target.Addr().String())
				defer srv.Close()
				defer cli.Close()
				var wg sync.WaitGroup
				for i := 0; i < 8; i++ {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						data := make([]byte, 1<<20+i*7919)
						rand.Read(data)
						want := sha256.Sum256(data)
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer cancel()
						conn, done, err := cli.Open(ctx, StreamHeader{Cmd: CmdTCP, RuleID: 42,
							Src: netip.MustParseAddrPort("1.2.3.4:1234")})
						if err != nil {
							t.Error(err)
							return
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
							t.Errorf("read: %v", err)
							return
						}
						if !bytes.Equal(got, want[:]) {
							t.Errorf("hash mismatch: got %d bytes", len(got))
						}
					}(i)
				}
				wg.Wait()
			})
		}
	}
}

func TestTunnelRejectsBadKey(t *testing.T) {
	target := hashServer(t)
	defer target.Close()
	for _, tr := range []string{TransportTCP, TransportTLS} {
		cli, srv := startPair(t, tr, false, target.Addr().String())
		// 换一把密钥再连
		spec := cli.Spec
		spec.Key = NewKey()
		bad, _ := NewClient(&spec, ClientOpts{})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, done, err := bad.Open(ctx, StreamHeader{Cmd: CmdTCP, RuleID: 42, Src: netip.MustParseAddrPort("1.2.3.4:1234")})
		if err == nil {
			conn.Write([]byte("hello"))
			relay.CloseWrite(conn)
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			b, _ := io.ReadAll(conn)
			if len(b) != 0 {
				t.Errorf("%s: 错误密钥不应得到响应", tr)
			}
			conn.Close()
			done()
		}
		cancel()
		bad.Close()
		cli.Close()
		srv.Close()
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
