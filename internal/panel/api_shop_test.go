package panel

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Exercise the handlers against a fresh file-backed database with the normal transaction settings.
func shopFixture(t *testing.T) *Server {
	t.Helper()
	db, err := openDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := &Server{db: db, limiter: newIPLimiter(), settings: map[string]string{"epay_key": "local-test-only", "epay_pid": "fixture-merchant"}}
	s.hub = newHub(s)
	shopExec(t, s, `INSERT INTO users(id,username,password,balance,created_at) VALUES(1,'fixture','',17,0)`)
	return s
}
func shopExec(t *testing.T, s *Server, stmt string, args ...any) {
	t.Helper()
	if _, err := s.db.Exec(stmt, args...); err != nil {
		t.Fatal(err)
	}
}
func shopAssertInt(t *testing.T, s *Server, stmt string, want int) {
	t.Helper()
	var got int
	if err := s.db.QueryRow(stmt).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("%s: got %d want %d", stmt, got, want)
	}
}
func shopFault(t *testing.T, s *Server, event, action string) {
	t.Helper()
	shopExec(t, s, `CREATE TRIGGER fixture_fault BEFORE `+event+` BEGIN SELECT RAISE(`+action+`); END`)
}
func notifyFixture(s *Server) *httptest.ResponseRecorder {
	p := map[string]string{"pid": "fixture-merchant", "out_trade_no": "fixture", "trade_no": "receipt", "trade_status": "TRADE_SUCCESS", "money": "1.25"}
	q := url.Values{}
	for k, v := range p {
		q.Set(k, v)
	}
	q.Set("sign", epaySign(p, "local-test-only"))
	w := httptest.NewRecorder()
	s.handleEpayNotify(w, httptest.NewRequest("GET", "/notify?"+q.Encode(), nil))
	return w
}
func seedRecharge(t *testing.T, s *Server) {
	t.Helper()
	shopExec(t, s, `INSERT INTO orders(order_no,user_id,type,amount,created_at) VALUES('fixture',1,'recharge',125,0)`)
}
func TestRechargeAtomic(t *testing.T) {
	t.Run("cancelled", func(t *testing.T) {
		s := shopFixture(t)
		seedRecharge(t, s)
		shopExec(t, s, "UPDATE orders SET status='cancelled'")
		if w := notifyFixture(s); w.Code != 409 {
			t.Fatalf("cancelled recharge returned status %d", w.Code)
		}
		shopAssertInt(t, s, "SELECT COUNT(*) FROM orders WHERE status='cancelled' AND paid_at=0", 1)
		shopAssertInt(t, s, "SELECT balance FROM users WHERE id=1", 17)
	})
	for _, tc := range []struct{ name, event, action string }{{"order_error", "UPDATE OF status ON orders", "ABORT,'fixture'"}, {"credit_error", "UPDATE OF balance ON users", "ABORT,'fixture'"}, {"credit_zero_rows", "UPDATE OF balance ON users", "IGNORE"}, {"order_zero_rows", "UPDATE OF status ON orders", "IGNORE"}} {
		t.Run(tc.name, func(t *testing.T) {
			s := shopFixture(t)
			seedRecharge(t, s)
			shopFault(t, s, tc.event, tc.action)
			w := notifyFixture(s)
			if w.Code != 500 || strings.TrimSpace(w.Body.String()) != "fail" {
				t.Errorf("expected gateway failure, got status %d", w.Code)
			}
			shopAssertInt(t, s, `SELECT COUNT(*) FROM orders WHERE status='pending' AND paid_at=0 AND trade_no=''`, 1)
			shopAssertInt(t, s, `SELECT balance FROM users WHERE id=1`, 17)
			shopExec(t, s, "DROP TRIGGER fixture_fault")
			w = notifyFixture(s)
			if w.Code != 200 || w.Body.String() != "success" {
				t.Fatal("valid redelivery not confirmed")
			}
			shopAssertInt(t, s, `SELECT balance FROM users WHERE id=1`, 142)
		})
	}
	t.Run("concurrent_duplicates", func(t *testing.T) {
		s := shopFixture(t)
		seedRecharge(t, s)
		start := make(chan struct{})
		result := make(chan *httptest.ResponseRecorder, 4)
		for range 4 {
			go func() { <-start; result <- notifyFixture(s) }()
		}
		close(start)
		for range 4 {
			w := <-result
			if w.Code != 200 || w.Body.String() != "success" {
				t.Errorf("duplicate status %d", w.Code)
			}
		}
		shopAssertInt(t, s, `SELECT balance FROM users WHERE id=1`, 142)
		shopAssertInt(t, s, `SELECT COUNT(*) FROM orders WHERE status='paid' AND trade_no='receipt' AND paid_at>0`, 1)
	})
}
func TestPurchaseRequiresDebitAndOrder(t *testing.T) {
	for _, event := range []string{"UPDATE OF balance ON users", "INSERT ON orders"} {
		t.Run(event, func(t *testing.T) {
			s := shopFixture(t)
			shopExec(t, s, "INSERT INTO plans(id,name,price,created_at) VALUES(3,'fixture',5,0)")
			shopFault(t, s, event, "IGNORE")
			if err := s.purchase(1, 3, "plan"); err == nil {
				t.Fatal("purchase succeeded with a missing ledger write")
			}
			shopAssertInt(t, s, "SELECT COUNT(*) FROM users WHERE balance=17 AND plan_id=0", 1)
			shopAssertInt(t, s, "SELECT COUNT(*) FROM orders", 0)
			shopExec(t, s, "DROP TRIGGER fixture_fault")
			if err := s.purchase(1, 3, "plan"); err != nil {
				t.Fatal(err)
			}
			shopAssertInt(t, s, "SELECT COUNT(*) FROM users WHERE balance=12 AND plan_id=3", 1)
			shopAssertInt(t, s, "SELECT COUNT(*) FROM orders WHERE status='paid' AND amount=5", 1)
		})
	}
}
func redeemFixture(s *Server) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.handleRedeem(w, httptest.NewRequest("POST", "/redeem", strings.NewReader(`{"code":"fixture"}`)), &User{ID: 1})
	return w
}
func TestRedeemAtomic(t *testing.T) {
	for _, typ := range []string{"balance", "plan"} {
		for _, tc := range []struct{ name, event, action string }{{"benefit_zero_rows", "UPDATE ON users", "IGNORE"}, {"code_error", "UPDATE ON redeem_codes", "ABORT,'fixture'"}, {"code_zero_rows", "UPDATE ON redeem_codes", "IGNORE"}, {"order_error", "INSERT ON orders", "ABORT,'fixture'"}, {"order_zero_rows", "INSERT ON orders", "IGNORE"}} {
			t.Run(typ+"/"+tc.name, func(t *testing.T) {
				s := shopFixture(t)
				shopExec(t, s, `INSERT INTO plans(id,name,traffic,created_at) VALUES(3,'fixture',99,0)`)
				pid := 0
				if typ == "plan" {
					pid = 3
				}
				shopExec(t, s, `INSERT INTO redeem_codes(code,type,amount,plan_id,created_at) VALUES('fixture',?,125,?,0)`, typ, pid)
				shopFault(t, s, tc.event, tc.action)
				if w := redeemFixture(s); w.Code != 500 {
					t.Errorf("expected redemption failure, got %d", w.Code)
				}
				shopAssertInt(t, s, `SELECT COUNT(*) FROM redeem_codes WHERE used_by=0 AND used_at=0`, 1)
				shopAssertInt(t, s, `SELECT COUNT(*) FROM orders`, 0)
				shopAssertInt(t, s, `SELECT COUNT(*) FROM users WHERE balance=17 AND plan_id=0 AND traffic_quota=0 AND expire_at=0`, 1)
				shopExec(t, s, "DROP TRIGGER fixture_fault")
				if w := redeemFixture(s); w.Code != 200 {
					t.Fatal("code not reusable after rollback")
				}
				if w := redeemFixture(s); w.Code != 400 {
					t.Fatal("spent code not rejected")
				}
				shopAssertInt(t, s, `SELECT COUNT(*) FROM redeem_codes WHERE used_by=1 AND used_at>0`, 1)
				shopAssertInt(t, s, `SELECT COUNT(*) FROM orders WHERE type='redeem' AND status='paid' AND user_id=1`, 1)
				if typ == "balance" {
					shopAssertInt(t, s, `SELECT balance FROM users WHERE id=1`, 142)
				} else {
					shopAssertInt(t, s, `SELECT COUNT(*) FROM users WHERE plan_id=3 AND traffic_quota=99 AND expire_at>0 AND balance=17`, 1)
				}
			})
		}
	}
}
