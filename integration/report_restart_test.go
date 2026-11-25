//go:build integration

// Run only after both report_v2 implementations have landed, with the local Go
// module cache populated. No installed binaries, credentials or servers used.
package integration_test

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"

	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"kaze/internal/proto"
	_ "modernc.org/sqlite"
)

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func listen(t *testing.T) *net.TCPListener {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	check(t, err)
	t.Cleanup(func() { l.Close() })
	return l.(*net.TCPListener)
}
func secret(t *testing.T) string {
	t.Helper()
	var b [24]byte
	_, err := rand.Read(b[:])
	check(t, err)
	return hex.EncodeToString(b[:])
}

// The relay only observes the two local peers. On pre-crash sessions it drops
// every panel ACK (including retries); on post-crash sessions it forwards all.
// Capture the phase at upgrade, so a dying old connection cannot fake replay.
type wireEvent struct {
	kind string
	data json.RawMessage
}
type phase struct {
	events chan wireEvent
	drop   bool
}

func relay(t *testing.T, panel string, current *atomic.Pointer[phase]) string {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/node/ws" {
			http.NotFound(w, r)
			return
		}
		p := current.Load()
		dial := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
		upstream, _, err := dial.Dial("ws://"+panel+"/api/node/ws", http.Header{"Authorization": {r.Header.Get("Authorization")}})
		if err != nil {
			http.Error(w, "local upstream unavailable", 502)
			return
		}
		defer upstream.Close()
		downstream, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer downstream.Close()
		pump := func(dst, src *websocket.Conn, fromPanel bool) {
			defer dst.Close()
			defer src.Close()
			for {
				mt, b, err := src.ReadMessage()
				if err != nil {
					return
				}
				var m proto.Msg
				if json.Unmarshal(b, &m) != nil {
					return
				}
				ack := fromPanel && m.T == proto.TAck
				if !fromPanel && (m.T == proto.THello || m.T == proto.TReportV2 || m.T == proto.TReport) {
					p.events <- wireEvent{m.T, m.D}
				}
				if !ack || !p.drop {
					dst.SetWriteDeadline(time.Now().Add(3 * time.Second))
					if dst.WriteMessage(mt, b) != nil {
						return
					}
				}
				if ack {
					p.events <- wireEvent{m.T, m.D}
				}
			}
		}
		done := make(chan struct{})
		go func() { defer close(done); pump(upstream, downstream, false) }()
		pump(downstream, upstream, true)
		<-done
	}))
	srv.Listener.Close()
	srv.Listener = listen(t)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.URL
}
func (p *phase) next(t *testing.T, kind string, dst any) {
	t.Helper()
	select {
	case e := <-p.events:
		if e.kind != kind {
			t.Fatalf("wanted %s, received %s", kind, e.kind)
		}
		check(t, json.Unmarshal(e.data, dst))
	case <-time.After(25 * time.Second):
		t.Fatalf("timeout waiting for %s (drop ACK=%v)", kind, p.drop)
	}
}
func (p *phase) batch(t *testing.T, up, down int64) proto.Report {
	t.Helper()
	var r proto.Report
	p.next(t, proto.TReportV2, &r)
	if r.Stream == "" || r.Seq <= 0 || !reflect.DeepEqual(r.Items, []proto.Traffic{{RuleID: 43, Up: up, Down: down}}) {
		t.Fatalf("unexpected report: seq=%d items=%+v", r.Seq, r.Items)
	}
	var a proto.Ack
	p.next(t, proto.TAck, &a)
	if a.Stream != r.Stream || a.Seq != r.Seq {
		t.Fatalf("ACK does not match stream/seq of report %d", r.Seq)
	}
	return r
}

// Dial only until connected. Never retry a write: that would introduce real
// additional billable bytes. Compare both payloads at the actual endpoints.
func transfer(t *testing.T, addr string, target *net.TCPListener, up, down int, marker byte) {
	t.Helper()
	var client net.Conn
	var err error
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		client, err = net.DialTimeout("tcp4", addr, time.Second)
		if err == nil {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	check(t, err)
	defer client.Close()
	check(t, client.SetDeadline(deadline))
	req := bytes.Repeat([]byte{marker}, up)
	res := bytes.Repeat([]byte{marker + 1}, down)
	_, err = client.Write(req)
	check(t, err)
	check(t, client.(*net.TCPConn).CloseWrite())
	check(t, target.SetDeadline(deadline))
	c, err := target.AcceptTCP()
	check(t, err)
	defer c.Close()
	check(t, c.SetDeadline(deadline))
	got, err := io.ReadAll(io.LimitReader(c, int64(up)+1))
	check(t, err)
	if !bytes.Equal(got, req) {
		t.Fatal("target request mismatch")
	}
	_, err = c.Write(res)
	check(t, err)
	check(t, c.CloseWrite())
	got, err = io.ReadAll(io.LimitReader(client, int64(down)+1))
	check(t, err)
	if !bytes.Equal(got, res) {
		t.Fatal("client response mismatch")
	}
}

// A single SELECT gives an atomic read across ledgers. Sum hourly rows so a
// legitimate UTC hour rollover between batches doesn't change the expectation.
func ledger(t *testing.T, dsn, label string, up, down int64) {
	t.Helper()
	db, err := sql.Open("sqlite", dsn+"&mode=ro")
	check(t, err)
	defer db.Close()
	var got [7]int64
	err = db.QueryRow(`SELECT traffic_up,traffic_down,u.traffic_used,g.traffic,
 (SELECT coalesce(sum(up),0) FROM traffic_hourly WHERE user_id=u.id),
 (SELECT coalesce(sum(down),0) FROM traffic_hourly WHERE user_id=u.id),
 (SELECT coalesce(sum(billed),0) FROM traffic_hourly WHERE user_id=u.id)
 FROM rules r JOIN users u ON u.id=r.user_id JOIN device_groups g ON g.id=r.in_group
 WHERE r.id=43 AND u.id=41 AND g.id=42`).Scan(&got[0], &got[1], &got[2], &got[3], &got[4], &got[5], &got[6])
	check(t, err)
	raw := up + down
	billed := 2 * raw
	want := [7]int64{up, down, billed, raw, up, down, billed}
	if got != want {
		t.Fatalf("%s: got %v want %v", label, got, want)
	}
	t.Logf("%s: rule=%d/%d user=%d group=%d hourly=%d/%d/%d", label, got[0], got[1], got[2], got[3], got[4], got[5], got[6])
}

func TestLostACKRestart(t *testing.T) {
	work := t.TempDir()
	bins := filepath.Join(work, "bin")
	check(t, os.Mkdir(bins, 0700))
	build := exec.Command("go", "build", "-mod=readonly", "-o", bins+string(os.PathSeparator), "./cmd/kaze-node", "./cmd/kaze-panel")
	build.Dir = ".."
	build.Env = append(os.Environ(), "GOWORK=off", "GOENV=off", "GOFLAGS=", "GOTOOLCHAIN=local", "GOSUMDB=off", "GOPROXY=off", "GONOPROXY=none", "GOVCS=*:off", "GOTELEMETRY=off")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("offline build: %v\n%s", err, b)
	}
	token, pass := secret(t), secret(t)
	spawn := func(binary, env string, args ...string) func() {
		t.Helper()
		cmd := exec.Command(filepath.Join(bins, binary), args...)
		cmd.Dir = work
		cmd.Env = []string{"HOME=" + work, "TMPDIR=" + work, env}
		check(t, cmd.Start())
		var once sync.Once
		kill := func() { once.Do(func() { check(t, cmd.Process.Kill()); _ = cmd.Wait() }) }
		t.Cleanup(kill)
		return kill
	}
	panelSlot, ruleSlot, target := listen(t), listen(t), listen(t)
	panelAddr, ruleAddr := panelSlot.Addr().String(), ruleSlot.Addr().String()
	check(t, panelSlot.Close())
	startPanel := func() func() {
		t.Helper()
		kill := spawn("kaze-panel", "KAZE_ADMIN_PASS="+pass, "-listen", panelAddr, "-data", "db")
		cl := http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		for end := time.Now().Add(8 * time.Second); time.Now().Before(end); {
			r, err := cl.Get("http://" + panelAddr + "/api/site")
			if err == nil {
				r.Body.Close()
				if r.StatusCode == 200 {
					return kill
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("local panel did not start")
		return nil
	}
	killPanel := startPanel()
	// Seed only the fixture, before the node connects. All counters and report
	// identities subsequently come exclusively from production traffic/ingestion.
	dsn := "file:" + filepath.ToSlash(filepath.Join(work, "db", "kaze.db")) + "?_pragma=busy_timeout(4000)"
	db, err := sql.Open("sqlite", dsn+"&mode=rw")
	check(t, err)
	defer db.Close()
	tx, err := db.Begin()
	check(t, err)
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO users(id,username,password,traffic_quota,created_at) VALUES(41,'fixture','not-a-password-hash',1000000,0)`)
	check(t, err)
	_, err = tx.Exec(`INSERT INTO device_groups(id,name,type,token,ratio,config,created_at) VALUES(42,'fixture','in',?,2,'{"allow_private":true,"port_range":"1024-65535"}',0)`, token)
	check(t, err)
	targets, _ := json.Marshal([]string{target.Addr().String()})
	_, err = tx.Exec(`INSERT INTO rules(id,user_id,in_group,listen_port,proto,targets,created_at,updated_at) VALUES(43,41,42,?,'tcp',?,0,0)`, ruleSlot.Addr().(*net.TCPAddr).Port, string(targets))
	check(t, err)
	check(t, tx.Commit())
	check(t, db.Close())
	ledger(t, dsn, "baseline", 0, 0)
	var active atomic.Pointer[phase]
	before := &phase{make(chan wireEvent, 32), true}
	after := &phase{make(chan wireEvent, 32), false}
	active.Store(before)
	url := relay(t, panelAddr, &active)
	startNode := func() func() {
		return spawn("kaze-node", "KAZE_TOKEN="+token, "-u", url, "-bind", "127.0.0.1", "-state", "node")
	}
	check(t, ruleSlot.Close())
	killNode := startNode()
	var h1, h2 proto.Hello
	before.next(t, proto.THello, &h1)
	const u1, d1, u2, d2 = 4093, 701, 1237, 2053
	transfer(t, ruleAddr, target, u1, d1, 'A')
	first := before.batch(t, u1, d1)
	ledger(t, dsn, "committed, ACK withheld", u1, d1)
	killNode()
	killPanel()
	active.Store(after)
	killPanel = startPanel()
	ledger(t, dsn, "reopened, before node replay", u1, d1)
	killNode = startNode()
	after.next(t, proto.THello, &h2)
	if h2.UID == "" || h1.UID != h2.UID {
		t.Fatal("node identity changed after process restart")
	}
	replay := after.batch(t, u1, d1)
	if !reflect.DeepEqual(first, replay) {
		t.Fatal("unacknowledged report changed on restart")
	}
	ledger(t, dsn, "same report replayed and ACK forwarded", u1, d1)
	transfer(t, ruleAddr, target, u2, d2, 'C')
	fresh := after.batch(t, u2, d2)
	if fresh.Stream != first.Stream || fresh.Seq <= first.Seq {
		t.Fatal("fresh bytes did not advance durable stream")
	}
	killNode()
	killPanel()
	ledger(t, dsn, "fresh report, final on-disk totals", u1+u2, d1+d2)
	t.Logf("report seq: first=%d replay=%d fresh=%d", first.Seq, replay.Seq, fresh.Seq)
}
