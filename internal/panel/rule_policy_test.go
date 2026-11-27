package panel

import (
	"kaze/internal/proto"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestRuleRevocationConfigs(t *testing.T) {
	db, err := openDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{db: db}
	h := newHub(s)
	run := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	run(`INSERT INTO device_groups(id,name,type,token,public,config,created_at) VALUES(1,'in','in','a',1,'{}',0),(2,'primary','out','b',0,'{"failover_group":3}',0),(3,'secondary','out','c',1,'{}',0)`)
	run(`INSERT INTO plans(id,name,groups,created_at) VALUES(1,'a','[2]',0),(2,'b','[2]',0)`)
	run(`INSERT INTO users(id,username,password,plan_id,traffic_quota,created_at) VALUES(1,'a','',1,99,0),(2,'b','',2,99,0)`)
	for i, uid := range []int{1, 2, 1} {
		_, err := s.insertRule(db, &Rule{UserID: int64(uid), InGroup: 1, OutGroup: 2, ListenPort: 20001 + i, Proto: "tcp"})
		if err != nil {
			t.Fatal(err)
		}
	}
	run(`UPDATE rules SET paused=1 WHERE id=3`)
	check := func(want ...int64) {
		t.Helper()
		for _, g := range []int64{1, 2, 3} {
			cfg, err := h.buildConfig(g)
			if err != nil {
				t.Fatal(err)
			}
			var ids []int64
			if cfg.Role == proto.RoleIn {
				for _, v := range cfg.Inbound.Rules {
					ids = append(ids, v.ID)
				}
			} else {
				for _, v := range cfg.Outbound.Rules {
					ids = append(ids, v.ID)
				}
			}
			if !slices.Equal(ids, want) {
				t.Fatalf("group %d rules %v want %v", g, ids, want)
			}
		}
	}
	check(1, 2)
	run(`UPDATE plans SET groups='[]' WHERE id=1`)
	check(2)
	run(`UPDATE plans SET groups='[2]' WHERE id=1`)
	check(1, 2)
	run(`UPDATE device_groups SET config='{"allowed_out":[3]}' WHERE id=1`)
	check()
	run(`UPDATE device_groups SET config='{}' WHERE id=1`)
	check(1, 2)
	run(`DELETE FROM plans WHERE id=1`)
	check(2)
}

func TestRuleOwnerPolicy(t *testing.T) {
	ig := &Group{ID: 1, Type: proto.RoleIn, Public: true}
	p := &rulePolicy{groups: map[int64]*Group{1: ig}}
	u := &User{}
	r := Rule{InGroup: 1, ListenPort: 11000, Proto: "tcp+udp"}
	ig.Config.DisableUDP = true
	if err := p.authorize(u, &r); err != nil || r.Proto != "tcp" {
		t.Fatal("dual protocol was not restricted to TCP")
	}
	r.Proto = "udp"
	if p.authorize(u, &r) == nil {
		t.Fatal("udp unexpectedly allowed")
	}
	ig.Config.DisableUDP = false
	r.Proto = "tcp"
	ig.Config.DirectMode = 1
	if p.authorize(u, &r) == nil {
		t.Fatal("direct mode unexpectedly allowed")
	}
	if err := p.authorize(&User{Role: "admin"}, &r); err != nil {
		t.Fatal(err)
	}
	ig.Config.DirectMode = 0
	ig.Config.PortRange = "12000"
	if p.authorize(u, &r) == nil {
		t.Fatal("port no longer allowed")
	}
}

func TestConcurrentRuleQuota(t *testing.T) {
	db, err := openDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{db: db}
	s.hub = newHub(s)
	for _, q := range []string{`INSERT INTO users(id,username,password,traffic_quota,max_rules,created_at) VALUES(1,'test','',99,1,0)`, `INSERT INTO device_groups(id,name,type,token,created_at) VALUES(1,'test','in','fixture',0)`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	stale := &User{ID: 1, MaxRules: 100, TrafficQuota: 99}
	start := make(chan struct{})
	results := make(chan int, 8)
	for n := range 8 {
		go func() {
			<-start
			w := httptest.NewRecorder()
			if n%2 == 0 {
				s.handleRuleCreate(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"in_group":1,"targets":["127.0.0.1:80"]}`)), stale)
			} else {
				s.handleRuleBatch(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"in_group":1,"text":"r##127.0.0.1#80"}`)), stale)
			}
			results <- w.Code
		}()
	}
	close(start)
	ok := 0
	for range 8 {
		switch status := <-results; status {
		case 200:
			ok++
		case 400:
		default:
			t.Errorf("unexpected status %d", status)
		}
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM rules`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if ok != 1 || count != 1 {
		t.Errorf("successes %d stored %d", ok, count)
	}
}

func TestTLSChildChainPolicy(t *testing.T) {
	in := &Group{ID: 1, Type: proto.RoleIn, Public: true, Config: GroupConfig{TLSInboundPolicy: 2, PortRange: "20000", AllowedHosts: []string{".example.org"}}}
	chain := &Group{ID: 4, Type: proto.RoleChain, Config: GroupConfig{ChainHops: []int64{2, 3}}}
	p := &rulePolicy{groups: groupSet{1: in, 2: {ID: 2, Type: proto.RoleOut}, 3: {ID: 3, Type: proto.RoleOut}, 4: chain}, plans: map[int64][]int64{1: {4}}}
	owner := &User{PlanID: 1}
	r := Rule{InGroup: 1, OutGroup: 4, ListenPort: 443, TLSMode: proto.TLSModeChild, TLS: RuleTLS{SNI: []string{"a.example.org"}}}
	if err := p.authorize(owner, &r); err != nil {
		t.Fatal(err)
	}
	delete(p.plans, 1)
	if p.authorize(owner, &r) == nil {
		t.Fatal("revoked chain still allowed")
	}
	p.plans[1] = []int64{4}
	in.Config.BlockedHosts = []string{".example.org"}
	if p.authorize(owner, &r) == nil {
		t.Fatal("blocked child SNI still allowed")
	}
}
