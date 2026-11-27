package node

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"kaze/internal/proto"
)

func TestTrafficRestartReplayAndACK(t *testing.T) {
	dir := t.TempDir()
	opt := Options{StateDir: dir, PanelURL: "https://panel.invalid", Token: "test"}
	open := func() *trafficBox {
		b, err := openTraffic(opt, "node")
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	b := open()
	in := newInbound(nil)
	in.orphan[7] = [2]int64{12345, 67890}
	if err := b.checkpoint(in); err != nil {
		t.Fatal(err)
	}
	r := b.report()
	if r == nil || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(r.Stream) || r.Seq != 1 || len(r.Items) != 1 || r.Items[0] != (proto.Traffic{RuleID: 7, Up: 12345, Down: 67890}) {
		t.Fatalf("first report: %+v", r)
	}
	wire := proto.Pack(proto.TReportV2, r)
	for i := 0; i < 2; i++ {
		in.orphan[7] = [2]int64{21, 34}
		if err := b.checkpoint(in); err != nil {
			t.Fatal(err)
		}
	}
	b.close()
	b = open()
	defer func() { b.close() }()
	for _, ack := range []proto.Ack{{Seq: 1}, {Stream: "wrong", Seq: 1}, {Stream: r.Stream, Seq: 2}} {
		if err := b.ack(ack); err != nil {
			t.Fatal(err)
		}
	}
	if got := proto.Pack(proto.TReportV2, b.report()); !bytes.Equal(got, wire) {
		t.Fatalf("changed on replay: %s != %s", got, wire)
	}
	ack := proto.Ack{Stream: r.Stream, Seq: 1}
	if err := b.ack(ack); err != nil {
		t.Fatal(err)
	}
	if err := b.ack(ack); err != nil {
		t.Fatal(err)
	}
	b.close()
	b = open()
	next := b.report()
	if next == nil || next.Stream != r.Stream || next.Seq != 2 || len(next.Items) != 1 || next.Items[0] != (proto.Traffic{RuleID: 7, Up: 42, Down: 68}) {
		t.Fatalf("buffered report: %+v", next)
	}
	if err := b.ack(proto.Ack{Stream: r.Stream, Seq: 2}); err != nil {
		t.Fatal(err)
	}
	b.close()
	b = open()
	if b.report() != nil {
		t.Fatal("resurrected acked report")
	}
	in.orphan[9] = [2]int64{1, 0}
	if err := b.checkpoint(in); err != nil || b.report().Seq != 3 {
		t.Fatal("empty outbox lost its high-water mark", err)
	}
}

func TestTrafficWriteFailure(t *testing.T) {
	b, err := openTraffic(Options{StateDir: t.TempDir(), Token: "test", PanelURL: "local"}, "n")
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	in := newInbound(nil)
	in.orphan[4] = [2]int64{51, 93}
	save := b.write
	b.write = func(string, []byte) error { return errors.New("disk full") }
	if err := b.checkpoint(in); err == nil || b.report() != nil {
		t.Fatal("sent an undurable batch", err)
	}
	in.orphan[4] = [2]int64{12, 7}
	b.write = save
	if err := b.checkpoint(in); err != nil {
		t.Fatal(err)
	}
	r := b.report()
	if r == nil || r.Items[0] != (proto.Traffic{RuleID: 4, Up: 51, Down: 93}) {
		t.Fatalf("failed write lost batch: %+v", r)
	}
	b.write = func(string, []byte) error { return errors.New("read only") }
	if b.ack(proto.Ack{Stream: r.Stream, Seq: r.Seq}) == nil {
		t.Fatal("undurable ACK accepted")
	}
	b.close()
	b, err = openTraffic(Options{StateDir: filepath.Dir(b.path), Token: "test", PanelURL: "local"}, "n")
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	if got := b.report(); got == nil || got.Seq != 1 || got.Items[0] != r.Items[0] {
		t.Fatalf("lost pending on ACK failure: %+v", got)
	}
	if err := b.ack(proto.Ack{Stream: r.Stream, Seq: r.Seq}); err != nil || b.report().Items[0] != (proto.Traffic{RuleID: 4, Up: 12, Down: 7}) {
		t.Fatal("lost concurrent increments", err)
	}
}

func TestTrafficFailClosed(t *testing.T) {
	opt := Options{StateDir: t.TempDir(), Token: "token", PanelURL: "local"}
	b, err := openTraffic(opt, "n")
	if err != nil {
		t.Fatal(err)
	}
	if second, e := openTraffic(opt, "n"); e == nil {
		second.close()
		t.Fatal("concurrent owner")
	}
	b.close()
	check := func(o Options, uid string) {
		t.Helper()
		if got, e := openTraffic(o, uid); e == nil {
			got.close()
			t.Fatal("unexpectedly accepted state")
		}
	}
	raw, err := os.ReadFile(b.path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 1
	if err = os.WriteFile(b.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	check(opt, "n")
	got, _ := os.ReadFile(b.path)
	if !bytes.Equal(got, raw) {
		t.Fatal("overwrote corrupt file")
	}
}

func TestTrafficRebindPreservesOldBatch(t *testing.T) {
	opt := Options{StateDir: t.TempDir(), PanelURL: "https://fixture.invalid", Token: "old"}
	b, err := openTraffic(opt, "node")
	if err != nil {
		t.Fatal(err)
	}
	b.staged = &trafficState{Version: 2, Owner: b.state.Owner, Stream: b.state.Stream, Seq: 1,
		Pending: []proto.Traffic{{RuleID: 1, Up: 10}}}
	if err := b.flush(); err != nil {
		t.Fatal(err)
	}
	stream := b.state.Stream
	raw, err := os.ReadFile(b.path)
	if err != nil {
		t.Fatal(err)
	}
	b.close()
	opt.Token = "new"
	b, err = openTraffic(opt, "node")
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	if b.report() != nil || b.state.Stream == stream {
		t.Fatal("old report was carried over")
	}
	archive, err := os.ReadFile(b.path + "." + stream + ".bak")
	if err != nil || !bytes.Equal(raw, archive) {
		t.Fatalf("old report not preserved: %v", err)
	}
}

func TestTrafficTokenRotationKeepsSameGroupBatch(t *testing.T) {
	opt := Options{StateDir: t.TempDir(), PanelURL: "https://fixture.invalid", Token: "old"}
	b, err := openTraffic(opt, "node")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.bindGroup(opt, "node", 9); err != nil {
		t.Fatal(err)
	}
	next := b.state
	next.Seq = 1
	next.Pending = []proto.Traffic{{RuleID: 1, Up: 10}}
	b.staged = &next
	if err := b.flush(); err != nil {
		t.Fatal(err)
	}
	b.close()
	opt.Token = "fresh"
	b, err = openTraffic(opt, "node")
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	if b.report() != nil {
		t.Fatal("reported before group was authenticated")
	}
	if err := b.bindGroup(opt, "node", 9); err != nil {
		t.Fatal(err)
	}
	report := b.report()
	if report == nil || report.Stream != next.Stream || report.Seq != next.Seq {
		t.Fatal("same group batch was not preserved")
	}
}

func TestEmptyTrafficTokenRotation(t *testing.T) {
	opt := Options{StateDir: t.TempDir(), PanelURL: "https://fixture.invalid", Token: "old"}
	b, err := openTraffic(opt, "node")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.bindGroup(opt, "node", 9); err != nil {
		t.Fatal(err)
	}
	oldStream := b.state.Stream
	oldOwner := b.state.Owner
	b.close()
	opt.Token = "fresh"
	dir, err := openTrafficDir(opt.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = loadTraffic(opt, "node", dir, func() error { return os.ErrPermission })
	dir.Close()
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("rebound with stale cache: %v", err)
	}
	prior := opt
	prior.Token = "old"
	b, err = openTraffic(prior, "node")
	if err != nil {
		t.Fatal(err)
	}
	b.close()
	if b.state.Owner != oldOwner || b.state.Stream != oldStream {
		t.Fatal("failed rebind replaced the outbox")
	}
	for i := 0; i < 2; i++ {
		b, err = openTraffic(opt, "node")
		if err != nil {
			t.Fatal(err)
		}
		b.close()
		if b.awaitingGroup || b.state.Owner != trafficOwner(opt, "node") || b.state.Stream == oldStream || b.state.GroupID != 0 {
			t.Fatal("empty outbox did not persist its new identity")
		}
	}
	if _, err := os.Stat(b.path + "." + oldStream + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("unexpected archive: %v", err)
	}
}
