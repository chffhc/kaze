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
