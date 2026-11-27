package node

import (
	"context"
	"net"
	"sync"

	"kaze/internal/relay"
)

// ruleConns owns the streams and target sockets for one rule, never the shared
// tunnel carrier. A dial completing concurrently with stop cannot escape it.
type ruleConns struct {
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	workers sync.WaitGroup
}

func newRuleConns() *ruleConns {
	ctx, cancel := context.WithCancel(context.Background())
	return &ruleConns{ctx: ctx, cancel: cancel, conns: make(map[net.Conn]struct{})}
}

func (r *ruleConns) track(c net.Conn) bool {
	return r.add(c, false)
}

func (r *ruleConns) start(c net.Conn) bool {
	return r.add(c, true)
}

func (r *ruleConns) add(c net.Conn, worker bool) bool {
	r.mu.Lock()
	if r.conns == nil {
		r.mu.Unlock()
		relay.Abort(c)
		return false
	}
	r.conns[c] = struct{}{}
	if worker {
		r.workers.Add(1)
	}
	r.mu.Unlock()
	return true
}

func (r *ruleConns) finish(c net.Conn) {
	r.forget(c)
	r.workers.Done()
}

func (r *ruleConns) forget(c net.Conn) {
	r.mu.Lock()
	delete(r.conns, c)
	r.mu.Unlock()
}

func (r *ruleConns) stop() {
	r.mu.Lock()
	conns := r.conns
	r.conns = nil
	r.cancel()
	r.mu.Unlock()
	for c := range conns {
		relay.Abort(c)
	}
}
