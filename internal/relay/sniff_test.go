package relay

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
)

func runSniffCheck(t *testing.T, p *SniffPolicy, outerHost, payload string) ([]byte, bool) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		_, _ = io.WriteString(a, payload)
		_ = a.Close()
	}()
	return p.CheckInner(b, outerHost)
}

func TestHTTP2PrefacePolicy(t *testing.T) {
	h2Payload := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00"
	p := NewSniffPolicy(nil, []string{"bad.example.org"}, []string{"example.org"})
	prefix, allowed := runSniffCheck(t, p, "app.example.org", h2Payload)
	if !allowed || string(prefix) != h2Payload {
		t.Fatalf("TLS-wrapped h2 with allowed SNI failed: allowed=%v prefix=%q", allowed, prefix)
	}

	blockHTTP := NewSniffPolicy([]string{"http"}, nil, nil)
	if _, allowed := runSniffCheck(t, blockHTTP, "app.example.org", h2Payload); allowed {
		t.Fatal("h2 should be rejected when http is blocked")
	}

	blockHost := NewSniffPolicy(nil, []string{"bad.example.org"}, nil)
	if _, allowed := runSniffCheck(t, blockHost, "", h2Payload); allowed {
		t.Fatal("cleartext h2 without outer host should not bypass BlockedHosts")
	}
	if _, allowed := runSniffCheck(t, p, "", h2Payload); allowed {
		t.Fatal("cleartext h2 without outer host should not bypass AllowedHosts")
	}

	blockSocks := NewSniffPolicy([]string{"socks"}, nil, nil)
	if _, allowed := runSniffCheck(t, blockSocks, "", h2Payload); !allowed {
		t.Fatal("h2 should be allowed when only socks is blocked")
	}
}

func TestNonHTTPTextProtocolsPreserved(t *testing.T) {
	samples := []string{
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n",
		"AUTH default secret\r\n",
		"550e8400-e29b-41d4-a716-446655440000\r\n",
	}
	policies := []*SniffPolicy{
		NewSniffPolicy(nil, []string{"bad.example.org"}, nil),
		NewSniffPolicy([]string{"http", "socks"}, nil, nil),
	}
	for _, p := range policies {
		for _, sample := range samples {
			prefix, allowed := runSniffCheck(t, p, "", sample)
			if !allowed || len(prefix) == 0 {
				t.Fatalf("non-HTTP sample %q unexpectedly rejected: allowed=%v prefix=%q", sample, allowed, prefix)
			}
		}
	}
}

func TestHTTPSmugglingRejected(t *testing.T) {
	p := NewSniffPolicy(nil, []string{"bad.example.org"}, nil)
	cases := []string{
		"GET\t/ HTTP/1.1\r\nHost: bad.example.org\r\n\r\n",
		"GET / HTTP/1.1\r\nHost : www.example.org\r\n\r\n",
		"GET http://bad.example.org/ HTTP/1.1\r\nHost: www.example.org\r\n\r\n",
		"GET /index.html\r\n",
		"SSH-2.0 / HTTP/1.1\r\nHost: bad.example.org\r\n\r\n",
	}
	for _, raw := range cases {
		if _, allowed := runSniffCheck(t, p, "", raw); allowed {
			t.Fatalf("smuggled/blocked request was allowed: %q", raw)
		}
	}
}

func TestHostPolicyUsesDNSLabels(t *testing.T) {
	p := NewSniffPolicy(nil, []string{".private.example.org"}, []string{"example.org"})
	for host, want := range map[string]bool{"EXAMPLE.ORG.": true, "www.example.org": true, "private.example.org.": false, "myexample.org": false, "": false} {
		if got := p.HostAllowed(host); got != want {
			t.Errorf("%q: got %v", host, got)
		}
	}
}
func TestPolicyPreservesFragmentedHTTPRequest(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	parts := []string{"G", "ET / HTTP/1.1\r\n", "Host: www.example.org", "\r\n\r\n"}
	go func() {
		for _, p := range parts {
			if _, err := a.Write([]byte(p)); err != nil {
				return
			}
		}
	}()
	p := NewSniffPolicy(nil, nil, []string{"example.org"})
	data, allowed := p.Check(b)
	if !allowed || string(data) != "GET / HTTP/1.1\r\nHost: www.example.org\r\n\r\n" {
		t.Fatalf("fragmented request: %t %q", allowed, data)
	}
}

func TestTargetGuardRespectsRulePort(t *testing.T) {
	addr := net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:12100"))
	remove := RegisterListener("tcp", addr)
	defer remove()
	dial := NewDialer(true)
	for _, tc := range []struct {
		port     int
		rejected bool
	}{{12100, true}, {12101, false}} {
		ctx := WithExcludedTargets(context.Background(), tc.port, nil)
		err := dial.control(ctx, "tcp4", addr.String(), nil)
		if (err != nil) != tc.rejected {
			t.Fatalf("port %d: %v", tc.port, err)
		}
	}
}
