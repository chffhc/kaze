package relay

import (
	"net/netip"
	"testing"
)

func TestRestrictedAddr(t *testing.T) {
	for _, ip := range []string{"0.7.0.1", "100.127.255.255", "192.0.0.8", "192.0.2.1", "198.19.255.255", "198.51.100.19", "203.0.113.8", "240.0.0.1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "ff02::1", "64:ff9b::808:808", "64:ff9b:1::1", "100::1", "2001:2::1", "2001:db8::1", "2002::1", "3fff:fff::1", "2606:4700::1%zone"} {
		if !RestrictedAddr(netip.MustParseAddr(ip)) {
			t.Errorf("accepted restricted address %s", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "::ffff:8.8.8.8", "192.0.0.9", "192.0.0.10", "2001:3::1", "2001:4860:4860::8888", "2606:4700:4700::1111"} {
		if RestrictedAddr(netip.MustParseAddr(ip)) {
			t.Errorf("rejected public address %s", ip)
		}
	}
}
