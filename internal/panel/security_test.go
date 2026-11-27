package panel

import (
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestProxyAttribution(t *testing.T) {
	s := &Server{opt: Options{TrustProxy: true}, proxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32")}}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("X-Forwarded-For", "203.0.113.1, 198.51.100.4")
	req.Header.Set("X-Real-IP", "203.0.113.2")
	req.RemoteAddr = "192.0.2.10:80"
	if got := s.clientIP(req); got != "198.51.100.4" {
		t.Fatalf("trusted proxy returned %s", got)
	}
	req.RemoteAddr = "192.0.2.20:80"
	if got := s.clientIP(req); got != "192.0.2.20" {
		t.Fatalf("direct request returned %s", got)
	}
}
func TestRegistrationWindowSurvivesCleanup(t *testing.T) {
	l := newIPLimiter()
	l.m["register"] = &window{until: time.Now().Add(7 * time.Minute), n: 5}
	if l.allow("register", 5, 10*time.Minute) {
		t.Fatal("cleanup discarded an active registration limit")
	}
}
func TestAdminUserCreateRollsBackInvalidRole(t *testing.T) {
	s := shopFixture(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/admin/users", strings.NewReader(`{"username":"new-user","password":"fixture-password","role":"invalid"}`))
	s.handleAdminUserCreate(w, r, &User{ID: 1, Role: "admin"})
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	shopAssertInt(t, s, "SELECT COUNT(*) FROM users WHERE username='new-user'", 0)
}

func TestProxyChainWalk(t *testing.T) {
	s := &Server{opt: Options{TrustProxy: true}, proxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	for _, tc := range []struct {
		name  string
		lines []string
		want  string
	}{
		{"no header", nil, "192.0.2.10"},
		{"trusted chain", []string{"203.0.113.1, 192.0.2.11", "::ffff:192.0.2.12"}, "203.0.113.1"},
		{"untrusted hop", []string{"192.0.2.99, 198.51.100.4, 192.0.2.11"}, "198.51.100.4"},
		{"malformed hop", []string{"203.0.113.1, unknown", "192.0.2.11"}, "192.0.2.11"},
		{"empty field", []string{"203.0.113.1,", "192.0.2.11"}, "192.0.2.11"},
		{"zone", []string{"fe80::1%lo"}, "192.0.2.10"},
		{"all trusted", []string{"192.0.2.11, 192.0.2.12"}, "192.0.2.11"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "192.0.2.10:80"
			for _, line := range tc.lines {
				req.Header.Add("X-Forwarded-For", line)
			}
			if got := s.clientIP(req); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
