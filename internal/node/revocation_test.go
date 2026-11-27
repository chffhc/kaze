package node

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"kaze/internal/proto"
	"kaze/internal/tunnel"
)

func dialLocal(t *testing.T, network, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout(network, addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func exchange(t *testing.T, c net.Conn, b byte) {
	t.Helper()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte{b}); err != nil {
		t.Fatal(err)
	}
	var got [1]byte
	if _, err := io.ReadFull(c, got[:]); err != nil || got[0] != b {
		t.Fatalf("expected %x, got %x (%v)", b, got, err)
	}
}

func TestActiveRuleRevocation(t *testing.T) {
	for _, tc := range []struct {
		name                                 string
		exit, tunnelled, streamUDP, fallback bool
		editTarget                           bool
	}{
		{name: "direct"},
		{name: "entry-native", tunnelled: true},
		{name: "exit-native", exit: true, tunnelled: true},
		{name: "exit-target-edit", exit: true, tunnelled: true, editTarget: true},
		{name: "exit-fallback-native", exit: true, tunnelled: true, fallback: true},
		{name: "entry-fallback-stream", tunnelled: true, streamUDP: true, fallback: true},
		{name: "exit-fallback-stream", exit: true, tunnelled: true, streamUDP: true, fallback: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peers := make(chan netip.AddrPort, 8)
			target := echoServerWithUDPPeer(t, peers)
			entry := newTestAgent(t)
			exit := newTestAgent(t)
			ic := proto.InboundConfig{AllowPrivate: true, MaxFail: 1}
			oc := proto.OutboundConfig{Transport: tunnel.TransportTCP, Key: tunnel.NewKey(), AllowPrivate: true}
			for i := int64(1); i <= 2; i++ {
				r := proto.Rule{ID: i, Proto: "tcp+udp", Targets: []string{target}}
				if tc.tunnelled {
					r.OutGroup = 1
				}
				ic.Rules = append(ic.Rules, r)
				oc.Rules = append(oc.Rules, proto.OutRule{ID: i, Targets: []string{target}})
			}
			if tc.tunnelled {
				if err := exit.out.apply(&oc, 1); err != nil {
					t.Fatal(err)
				}
				spec := &proto.TunnelSpec{GroupID: 1, Transport: oc.Transport, Key: oc.Key, Endpoints: []string{fmt.Sprintf("127.0.0.1:%d", exit.out.listenPort())}, Mux: true, MuxConns: 1, UDPOverTCP: tc.streamUDP}
				if tc.fallback {
					primary := *spec
					primary.Endpoints = []string{"127.0.0.1:0"}
					primary.Fallback = spec
					spec = &primary
				}
				ic.Tunnels = map[int64]*proto.TunnelSpec{1: spec}
			}
			entry.in.apply(&ic)
			var tcp, udp [2]net.Conn
			var original [2]netip.AddrPort
			for i := range tcp {
				r := entry.in.rules[int64(i+1)]
				if r == nil {
					t.Fatal(entry.in.ruleErrors())
				}
				tcp[i] = dialLocal(t, "tcp", r.tcpLn.Addr().String())
				udp[i] = dialLocal(t, "udp", r.udp.Conn.LocalAddr().String())
				exchange(t, tcp[i], 'A')
				exchange(t, udp[i], 'B')
				original[i] = <-peers
			}
			var newPeers chan netip.AddrPort
			if tc.editTarget {
				newPeers = make(chan netip.AddrPort, 1)
				oc.Rules[0].Targets = []string{echoServerWithUDPPeer(t, newPeers)}
				if err := exit.out.apply(&oc, 1); err != nil {
					t.Fatal(err)
				}
			} else if tc.exit {
				oc.Rules = oc.Rules[1:]
				if err := exit.out.apply(&oc, 1); err != nil {
					t.Fatal(err)
				}
			} else {
				ic.Rules = ic.Rules[1:]
				entry.in.apply(&ic)
			}
			// An idle stream must actually close, not merely stop returning echo.
			tcp[0].SetReadDeadline(time.Now().Add(time.Second))
			var buf [1]byte
			_, err := tcp[0].Read(buf[:])
			if ne, ok := err.(net.Error); err == nil || ok && ne.Timeout() {
				t.Fatalf("revoked TCP still open: %v", err)
			}
			if tc.editTarget {
				exchange(t, udp[0], 'X')
				select {
				case <-newPeers:
				case <-time.After(time.Second):
					t.Fatal("datagram did not reach the new target")
				}
			} else {
				udp[0].SetDeadline(time.Now().Add(150 * time.Millisecond))
				if _, err := udp[0].Write([]byte{'X'}); err == nil {
					if _, err = udp[0].Read(buf[:]); err == nil {
						t.Fatal("revoked UDP session replied")
					}
				}
			}
			if !tc.exit {
				var retired proto.Traffic
				for _, item := range entry.in.collect() {
					if item.RuleID == 1 {
						retired = item
					}
				}
				if retired.Up < 2 || retired.Down < 2 {
					t.Fatalf("missing TCP or UDP bytes for retired rule: %+v", retired)
				}
			}
			exchange(t, tcp[1], 'C')
			exchange(t, udp[1], 'D')
			if peer := <-peers; peer != original[1] {
				t.Fatalf("surviving UDP session changed target-side peer: %v -> %v", original[1], peer)
			}
			select {
			case <-peers:
				t.Fatal("unexpected datagram reached target")
			default:
			}
		})
	}
}
