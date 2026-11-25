package relay

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// Simulate a blocked stream without relying on kernel socket buffer sizes.
type blockedUpstream struct{ sending, closed chan struct{} }

func (u *blockedUpstream) Send([]byte) error               { close(u.sending); <-u.closed; return net.ErrClosed }
func (u *blockedUpstream) Recv([]byte) (int, error)        { <-u.closed; return 0, net.ErrClosed }
func (u *blockedUpstream) SetReadDeadline(time.Time) error { return nil }
func (u *blockedUpstream) Close() error                    { close(u.closed); return nil }

func TestUDPRelayCloseDuringOpenOrSend(t *testing.T) {
	for _, phase := range []string{"open", "send"} {
		t.Run(phase, func(t *testing.T) {
			addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
			uc, err := net.ListenUDP("udp", addr)
			if err != nil {
				t.Fatal(err)
			}
			u := &blockedUpstream{make(chan struct{}), make(chan struct{})}
			opening, resume := make(chan struct{}), make(chan struct{})
			r := UDPRelay{Conn: uc, Open: func(netip.AddrPort, uint32) (Upstream, error) { close(opening); <-resume; return u, nil }}
			defer r.Close()
			go r.Serve()
			c, err := net.DialUDP("udp", nil, uc.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err := c.Write([]byte{'a'}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-opening:
			case <-time.After(time.Second):
				close(resume)
				t.Fatal("Open not called")
			}
			if phase == "open" {
				r.Close()
				close(resume)
			} else {
				close(resume)
				select {
				case <-u.sending:
				case <-time.After(time.Second):
					t.Fatal("Send not called")
				}
				r.Close()
			}
			select {
			case <-u.closed:
			case <-time.After(time.Second):
				t.Fatal("upstream not closed")
			}
			if phase == "open" {
				select {
				case <-u.sending:
					t.Fatal("sent queued data after Close")
				default:
				}
			}
		})
	}
}
