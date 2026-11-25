package relay

import (
	"math/rand/v2"
	"sync/atomic"
	"time"
)

// 负载均衡策略
const (
	LBRoundRobin = "round_robin"
	LBRandom     = "random"
	LBLeastConn  = "least_conn"
	LBIPHash     = "ip_hash"
	LBFailover   = "failover"
)

// Backend 是一个后端地址及其健康状态。
type Backend struct {
	Addr      string
	Active    atomic.Int64 // 当前连接数(最小连接数策略使用)
	fails     atomic.Int32
	downUntil atomic.Int64 // UnixNano;在此之前视为故障
}

// Down 报告后端当前是否处于故障摘除期。
func (b *Backend) Down() bool {
	u := b.downUntil.Load()
	return u != 0 && time.Now().UnixNano() < u
}

// Balancer 在一组后端间做负载均衡与被动故障转移:
// 连续失败 maxFail 次后摘除 failTimeout,期间只在没有其他可用后端时才兜底尝试。
type Balancer struct {
	strategy    string
	backends    []*Backend
	rr          atomic.Uint32
	maxFail     int32
	failTimeout time.Duration
}

// NewBalancer 创建均衡器。
func NewBalancer(addrs []string, strategy string, maxFail int, failTimeout time.Duration) *Balancer {
	if maxFail <= 0 {
		maxFail = 3
	}
	if failTimeout <= 0 {
		failTimeout = 30 * time.Second
	}
	b := &Balancer{strategy: strategy, maxFail: int32(maxFail), failTimeout: failTimeout}
	for _, a := range addrs {
		b.backends = append(b.backends, &Backend{Addr: a})
	}
	return b
}

// Backends 返回全部后端。
func (b *Balancer) Backends() []*Backend { return b.backends }

// AllDown 报告是否所有后端都处于故障期。
func (b *Balancer) AllDown() bool {
	for _, be := range b.backends {
		if !be.Down() {
			return false
		}
	}
	return len(b.backends) > 0
}

// Report 记录一次连接结果。
func (b *Balancer) Report(be *Backend, ok bool) {
	if ok {
		if be.fails.Load() != 0 {
			be.fails.Store(0)
		}
		if be.downUntil.Load() != 0 {
			be.downUntil.Store(0)
		}
		return
	}
	if be.fails.Add(1) >= b.maxFail {
		be.downUntil.Store(time.Now().Add(b.failTimeout).UnixNano())
	}
}

// Candidates 按策略返回尝试顺序:健康后端在前,故障后端垫后兜底。
// hash 用于 ip_hash 策略(来源 IP 的哈希)。
func (b *Balancer) Candidates(hash uint64) []*Backend {
	n := len(b.backends)
	if n <= 1 {
		return b.backends
	}
	out := make([]*Backend, 0, n)
	var down []*Backend
	start := 0
	switch b.strategy {
	case LBFailover:
		start = 0
	case LBRandom:
		start = rand.IntN(n)
	case LBIPHash:
		start = int(hash % uint64(n))
	default: // round_robin / least_conn 的同值打散
		start = int(b.rr.Add(1) % uint32(n))
	}
	for i := 0; i < n; i++ {
		be := b.backends[(start+i)%n]
		if be.Down() {
			down = append(down, be)
		} else {
			out = append(out, be)
		}
	}
	if b.strategy == LBLeastConn && len(out) > 1 {
		// 把连接数最少的换到首位
		mi := 0
		for i := 1; i < len(out); i++ {
			if out[i].Active.Load() < out[mi].Active.Load() {
				mi = i
			}
		}
		out[0], out[mi] = out[mi], out[0]
	}
	return append(out, down...)
}
