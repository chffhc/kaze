package relay

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

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
