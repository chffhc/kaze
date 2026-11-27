package node

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"kaze/internal/proto"
)

func TestPanelDisconnectKeepsLastSnapshot(t *testing.T) {
	a := newTestAgent(t)
	r := proto.Rule{ID: 1, ListenPort: freePort(t), Proto: "tcp+udp", Targets: []string{echoServer(t)}}
	cfg := proto.NodeConfig{Role: proto.RoleIn, Inbound: &proto.InboundConfig{AllowPrivate: true, Rules: []proto.Rule{r}}}
	if err := a.applyConfig(&cfg, true); err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", r.ListenPort)
	tcp, udp := dialLocal(t, "tcp", addr), dialLocal(t, "udp", addr)
	exchange(t, tcp, 'a')
	exchange(t, udp, 'b')
	// Lose the control connection after hello, without sending any snapshot.
	hello := make(chan error, 1)
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err == nil {
			defer ws.Close()
			ws.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, _, err = ws.ReadMessage()
		}
		hello <- err
	}))
	defer panel.Close()
	a.opt.PanelURL, a.opt.Token = panel.URL, "test"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.session(ctx); err == nil {
		t.Fatal("expected panel disconnect")
	}
	select {
	case err := <-hello:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("no control connection")
	}
	panel.Close()
	exchange(t, tcp, 'c')
	exchange(t, udp, 'd')
	a.in.stopAll()
	// Cold start from the same state directory with the panel still down.
	runCtx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(runCtx, a.opt) }()
	defer func() {
		stop()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("node did not stop")
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			defer c.Close()
			exchange(t, c, 'e')
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cached rule not restored: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	exchange(t, dialLocal(t, "udp", addr), 'f')
}

func TestPanelUnauthorizedRevokesSnapshot(t *testing.T) {
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer panel.Close()
	a := newTestAgent(t)
	a.opt.PanelURL, a.opt.Token = panel.URL, "old"
	r := proto.Rule{ID: 1, ListenPort: freePort(t), Proto: "tcp", Targets: []string{echoServer(t)}}
	if err := a.applyConfig(&proto.NodeConfig{Role: proto.RoleIn, Inbound: &proto.InboundConfig{
		AllowPrivate: true, Rules: []proto.Rule{r},
	}}, true); err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", r.ListenPort)
	conn := dialLocal(t, "tcp", addr)
	exchange(t, conn, 'a')
	if err := a.session(t.Context()); err == nil {
		t.Fatal("expected authentication rejection")
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil || os.IsTimeout(err) {
		t.Fatalf("old connection remains open: %v", err)
	}
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c.Close()
		t.Fatal("listener remains open")
	}
	reloaded := &Agent{opt: a.opt}
	if err := reloaded.loadState(); err != nil {
		t.Fatal(err)
	}
	if reloaded.state.LastConfig != nil {
		t.Fatal("revoked configuration still on disk")
	}
}
