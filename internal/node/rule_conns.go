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
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
}

func newRuleConns() *ruleConns {
	ctx, cancel := context.WithCancel(context.Background())
	return &ruleConns{ctx: ctx, cancel: cancel, conns: make(map[net.Conn]struct{})}
}

func (r *ruleConns) track(c net.Conn) bool {
	r.mu.Lock()
	if r.conns == nil {
		r.mu.Unlock()
		relay.Abort(c)
		return false
	}
	r.conns[c] = struct{}{}
	r.mu.Unlock()
	return true
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
