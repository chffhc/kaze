package node

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"kaze/internal/proto"
)

const (
	trafficName     = "kaze-traffic-v2.outbox"
	trafficRules    = 4096 // per batch; at most one pending and one coalesced successor
	trafficMaxFile  = 1 << 20
	trafficInterval = 5 * time.Second
)

// All slices in a published snapshot are immutable. Seq is the last issued
// sequence even when Pending is empty. A successor has no sequence until promoted.
type trafficState struct {
	Version int             `json:"version"`
	Owner   string          `json:"owner"`
	Stream  string          `json:"stream"`
	Seq     int64           `json:"seq"`
	Pending []proto.Traffic `json:"pending"`
	Buffer  []proto.Traffic `json:"buffer"`
}

type trafficBox struct {
	mu     sync.Mutex
	path   string
	dir    *os.File // exclusive lock on the stable directory inode, NOT the renamed file
	state  trafficState
	staged *trafficState // sole possible next state; retained even after an ambiguous rename
	write  func(string, []byte) error
}

func openTrafficDir(path string) (*os.File, error) {
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	d, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if err = lockTraffic(d); err != nil {
		d.Close()
		return nil, fmt.Errorf("lock traffic state directory: %w", err)
	}
	return d, nil
}

// openTraffic is used when a stable node identity already exists.
func openTraffic(opt Options, uid string) (*trafficBox, error) {
	d, err := openTrafficDir(opt.StateDir)
	if err != nil {
		return nil, err
	}
	b, err := loadTraffic(opt, uid, d)
	if err != nil {
		d.Close()
	}
	return b, err
}

func loadTraffic(opt Options, uid string, d *os.File) (*trafficBox, error) {
	b := &trafficBox{path: filepath.Join(opt.StateDir, trafficName), dir: d, write: writeTrafficAtomic}
	identity, _ := json.Marshal([3]string{strings.TrimRight(opt.PanelURL, "/"), uid, opt.Token})
	owner := fmt.Sprintf("%x", sha256.Sum256(identity))
	info, err := os.Lstat(b.path)
	if errors.Is(err, os.ErrNotExist) {
		var id [16]byte
		rand.Read(id[:])
		b.staged = &trafficState{Version: 2, Owner: owner, Stream: hex.EncodeToString(id[:])}
		if err := b.flush(); err != nil {
			return nil, err
		}
		return b, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > trafficMaxFile {
		return nil, errors.New("unexpected traffic outbox type or size")
	}
	f, err := os.Open(b.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, trafficMaxFile+1))
	if err != nil {
		return nil, err
	}
	checksum, body, ok := bytes.Cut(data, []byte{'\n'})
	if !ok || len(data) > trafficMaxFile || string(checksum) != fmt.Sprintf("%x", sha256.Sum256(body)) {
		return nil, errors.New("traffic outbox checksum mismatch")
	}
	if err = json.Unmarshal(body, &b.state); err != nil {
		return nil, err
	}
	s := b.state
	if s.Owner != owner {
		return nil, errors.New("traffic outbox belongs to another panel, node UID or token")
	}
	id, err := hex.DecodeString(s.Stream)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != s.Stream || s.Version != 2 || s.Seq < 0 || (len(s.Pending) > 0 && s.Seq == 0) || (len(s.Pending) == 0 && len(s.Buffer) > 0) {
		return nil, errors.New("invalid traffic stream state")
	}
	for _, items := range [][]proto.Traffic{s.Pending, s.Buffer} {
		if len(items) > trafficRules {
			return nil, errors.New("oversize traffic batch")
		}
		var prev int64
		for _, v := range items {
			if v.RuleID <= prev || !validTraffic(v) {
				return nil, errors.New("invalid traffic batch")
			}
			prev = v.RuleID
		}
	}
	// A previous process might have exited after rename but before directory fsync.
	if err = d.Sync(); err != nil {
		return nil, err
	}
	return b, nil
}

func validTraffic(v proto.Traffic) bool {
	return v.RuleID > 0 && v.Up >= 0 && v.Down >= 0 && (v.Up != 0 || v.Down != 0) && v.Up <= math.MaxInt64-v.Down
}
func (b *trafficBox) close() { b.dir.Close() }

// Fixed staging name bounds crash debris. The directory lock excludes other writers.
func writeTrafficAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	cerr := f.Close()
	if err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// flush only publishes after all durability barriers, never substituting a
// different candidate on retry (not even an ACK after a directory-sync failure).
func (b *trafficBox) flush() error {
	if b.staged == nil {
		return nil
	}
	body, err := json.Marshal(b.staged)
	if err != nil {
		return err
	}
	data := append([]byte(fmt.Sprintf("%x\n", sha256.Sum256(body))), body...)
	if len(data) > trafficMaxFile {
		return errors.New("oversize traffic checkpoint")
	}
	if err = b.write(b.path, data); err != nil {
		return err
	}
	b.state = *b.staged
	b.staged = nil
	return nil
}

func (b *trafficBox) checkpoint(in *inbound) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.flush(); err != nil {
		return err
	}
	s := b.state
	if s.Seq == math.MaxInt64 {
		return errors.New("traffic sequence exhausted")
	}
	var rows map[int64]proto.Traffic
	var blocked error
	changed := false
	in.collectIf(func(v proto.Traffic) bool {
		if rows == nil {
			rows = make(map[int64]proto.Traffic, len(s.Buffer))
			for _, old := range s.Buffer {
				rows[old.RuleID] = old
			}
		}
		old, ok := rows[v.RuleID]
		if !ok && len(rows) >= trafficRules {
			blocked = errors.New("traffic buffer full; remaining rules stay in live counters")
			return false
		}
		if !validTraffic(v) || old.Up+old.Down > math.MaxInt64-v.Up-v.Down {
			blocked = errors.New("invalid or overflowing traffic; retaining live counters")
			return false
		}
		v.Up += old.Up
		v.Down += old.Down
		rows[v.RuleID] = v
		changed = true
		return true
	})
	if !changed {
		return blocked
	}
	items := make([]proto.Traffic, 0, len(rows))
	for _, v := range rows {
		items = append(items, v)
	}
	slices.SortFunc(items, func(a, b proto.Traffic) int { return cmp.Compare(a.RuleID, b.RuleID) })
	if len(s.Pending) == 0 {
		s.Seq++
		s.Pending = items
	} else {
		s.Buffer = items
	}
	b.staged = &s
	if err := b.flush(); err != nil {
		return err
	}
	return blocked
}

func (b *trafficBox) report() *proto.Report {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.staged != nil || len(b.state.Pending) == 0 {
		return nil
	}
	return &proto.Report{Stream: b.state.Stream, Seq: b.state.Seq, Items: b.state.Pending}
}

func (b *trafficBox) ack(a proto.Ack) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.flush(); err != nil {
		return err
	}
	s := b.state
	if len(s.Pending) == 0 || a.Stream != s.Stream || a.Seq != s.Seq {
		return nil
	}
	s.Pending, s.Buffer = s.Buffer, nil
	if len(s.Pending) > 0 {
		if s.Seq == math.MaxInt64 {
			return errors.New("traffic sequence exhausted")
		}
		s.Seq++
	}
	b.staged = &s
	return b.flush()
}
