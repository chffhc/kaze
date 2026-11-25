package panel

import (
	"database/sql"
	"kaze/internal/proto"
	"testing"
)

const fixtureStream = "0123456789abcdef0123456789abcdef"

func trafficDB(t *testing.T) (*Hub, string) {
	t.Helper()
	dir := t.TempDir()
	db, e := openDB(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	s := &Server{db: db}
	h := newHub(s)
	for _, q := range []string{`INSERT INTO users(id,username,password,traffic_quota,created_at) VALUES(1,'fixture','',9999,0)`, `INSERT INTO device_groups(id,name,type,token,ratio,created_at) VALUES(1,'in','in','a',1,0),(2,'out','out','b',2,0)`} {
		if _, e = db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	_, e = s.insertRule(db, &Rule{UserID: 1, InGroup: 1, OutGroup: 2, ListenPort: 23000, Proto: "tcp"})
	if e != nil {
		t.Fatal(e)
	}
	return h, dir
}
func fixtureReport(seq int64) *proto.Report {
	return &proto.Report{Stream: fixtureStream, Seq: seq, Items: []proto.Traffic{{RuleID: 1, Up: 11, Down: 7}}}
}
func assertTraffic(t *testing.T, db *sql.DB, n int) {
	t.Helper()
	for _, tc := range []struct {
		q    string
		want int
	}{{`select traffic_up from rules`, 11 * n}, {`select traffic_down from rules`, 7 * n}, {`select traffic_used from users`, 54 * n}, {`select traffic from device_groups where id=1`, 18 * n}, {`select traffic from device_groups where id=2`, 18 * n}, {`select coalesce(sum(up),0) from traffic_hourly`, 11 * n}, {`select coalesce(sum(down),0) from traffic_hourly`, 7 * n}, {`select coalesce(sum(billed),0) from traffic_hourly`, 54 * n}} {
		var v int
		if e := db.QueryRow(tc.q).Scan(&v); e != nil {
			t.Fatal(e)
		}
		if v != tc.want {
			t.Fatalf("%s = %d want %d", tc.q, v, tc.want)
		}
	}
}
func TestTrafficRestartReplay(t *testing.T) {
	h, dir := trafficDB(t)
	p := fixtureReport(1)
	if e := h.ingest(1, "node", p); e != nil {
		t.Fatal(e)
	}
	assertTraffic(t, h.s.db, 1)
	if e := h.s.db.Close(); e != nil {
		t.Fatal(e)
	}
	db, e := openDB(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	h = newHub(&Server{db: db})
	result := make(chan error, 6)
	for range 6 {
		go func() { result <- h.ingest(1, "node", p) }()
	}
	for range 6 {
		if e = <-result; e != nil {
			t.Fatal(e)
		}
	}
	assertTraffic(t, db, 1)
	bad := fixtureReport(1)
	bad.Items[0].Up++
	if h.ingest(1, "node", bad) == nil || h.ingest(1, "node", fixtureReport(3)) == nil {
		t.Fatal("conflicting replay or skipped batch accepted")
	}
	if e = h.ingest(1, "node", fixtureReport(2)); e != nil {
		t.Fatal(e)
	}
	assertTraffic(t, db, 2)
}
func TestTrafficWriteRollback(t *testing.T) {
	for _, event := range []string{"UPDATE ON rules", "UPDATE ON users", "INSERT ON traffic_hourly", "UPDATE ON device_groups", "INSERT ON traffic_cursors"} {
		for _, fault := range []string{"IGNORE", "ABORT,'fixture'"} {
			t.Run(event+"/"+fault, func(t *testing.T) {
				h, _ := trafficDB(t)
				db := h.s.db
				if _, e := db.Exec(`CREATE TRIGGER fixture BEFORE ` + event + ` BEGIN SELECT RAISE(` + fault + `); END`); e != nil {
					t.Fatal(e)
				}
				p := fixtureReport(1)
				if h.ingest(1, "node", p) == nil {
					t.Fatal("fault returned success")
				}
				assertTraffic(t, db, 0)
				var n int
				if e := db.QueryRow(`select count(*) from traffic_cursors`).Scan(&n); e != nil || n != 0 {
					t.Fatal(n, e)
				}
				if _, e := db.Exec(`DROP TRIGGER fixture`); e != nil {
					t.Fatal(e)
				}
				if e := h.ingest(1, "node", p); e != nil {
					t.Fatal(e)
				}
				assertTraffic(t, db, 1)
			})
		}
	}
}
func TestTrafficLegacyAndMissingRule(t *testing.T) {
	h, _ := trafficDB(t)
	p := fixtureReport(12345)
	p.Stream = ""
	for range 2 {
		if e := h.ingest(1, "old-node", p); e != nil {
			t.Fatal(e)
		}
	}
	assertTraffic(t, h.s.db, 1)
	p = fixtureReport(1)
	p.Items[0].RuleID = 100
	for range 2 {
		if e := h.ingest(1, "new-node", p); e != nil {
			t.Fatal(e)
		}
	}
	assertTraffic(t, h.s.db, 1)
	var sum int
	if e := h.s.db.QueryRow(`SELECT SUM(up+down) FROM traffic_unattributed`).Scan(&sum); e != nil || sum != 18 {
		t.Fatal(sum, e)
	}
}
