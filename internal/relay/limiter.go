package relay

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// 缓冲池:用户态拷贝路径使用 32KB 缓冲,UDP 使用 64KB。
const (
	tcpBufSize = 32 * 1024
	udpBufSize = 64 * 1024
)

var tcpBufPool = sync.Pool{New: func() any { b := make([]byte, tcpBufSize); return &b }}
var udpBufPool = sync.Pool{New: func() any { b := make([]byte, udpBufSize); return &b }}

// GetUDPBuf 取一个 64KB 缓冲。
func GetUDPBuf() *[]byte { return udpBufPool.Get().(*[]byte) }

// PutUDPBuf 归还缓冲。
func PutUDPBuf(b *[]byte) { udpBufPool.Put(b) }

// 全局计量(探针用)
var (
	ActiveTCP atomic.Int64
	ActiveUDP atomic.Int64
)

// Bucket 是一个字节令牌桶。Wait 采用"欠账"模型:先扣令牌,不足则按欠账时长睡眠,
// 多个连接共享同一个桶时自然形成公平排队。
type Bucket struct {
	mu     sync.Mutex
	rate   float64 // 字节/秒
	burst  float64
	tokens float64
	last   time.Time
}

// NewBucket 创建限速桶;rate<=0 返回 nil(不限速)。
func NewBucket(rate int64) *Bucket {
	if rate <= 0 {
		return nil
	}
	burst := float64(rate) / 5 // 200ms 的突发量
	if burst < 16*1024 {
		burst = 16 * 1024
	}
	return &Bucket{rate: float64(rate), burst: burst, tokens: burst, last: time.Now()}
}

func (b *Bucket) refill(now time.Time) {
	el := now.Sub(b.last).Seconds()
	if el > 0 {
		b.tokens += el * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
}

// Wait 消耗 n 字节令牌,必要时阻塞。
func (b *Bucket) Wait(n int) {
	if b == nil || n <= 0 {
		return
	}
	b.mu.Lock()
	b.refill(time.Now())
	b.tokens -= float64(n)
	var d time.Duration
	if b.tokens < 0 {
		d = time.Duration(-b.tokens / b.rate * float64(time.Second))
	}
	b.mu.Unlock()
	if d > 0 {
		time.Sleep(d)
	}
}

// Allow 非阻塞地尝试消耗 n 字节令牌(UDP 超速直接丢包)。
func (b *Bucket) Allow(n int) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill(time.Now())
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}

// Chunk 返回限速时单次读取的建议上限,让小带宽下的流量更平滑。
func (b *Bucket) Chunk() int {
	if b == nil {
		return tcpBufSize
	}
	c := int(b.rate / 20)
	if c < 2048 {
		c = 2048
	}
	if c > tcpBufSize {
		c = tcpBufSize
	}
	return c
}

// Limits 是一组资源限制(规则级或用户级):上下行限速、并发连接数、并发来源 IP 数。
type Limits struct {
	Up, Down *Bucket
	maxConns int64
	maxIPs   int
	conns    atomic.Int64
	mu       sync.Mutex
	ips      map[netip.Addr]int
}

// NewLimits 创建限制;全部为 0 时返回 nil。
func NewLimits(speed int64, conns, ips int) *Limits {
	if speed <= 0 && conns <= 0 && ips <= 0 {
		return nil
	}
	l := &Limits{Up: NewBucket(speed), Down: NewBucket(speed), maxConns: int64(conns), maxIPs: ips}
	if ips > 0 {
		l.ips = make(map[netip.Addr]int)
	}
	return l
}

// Acquire 为来源 ip 申请一个连接名额。
func (l *Limits) Acquire(ip netip.Addr) bool {
	if l == nil {
		return true
	}
	if l.maxConns > 0 {
		if l.conns.Add(1) > l.maxConns {
			l.conns.Add(-1)
			return false
		}
	}
	if l.maxIPs > 0 {
		l.mu.Lock()
		n, ok := l.ips[ip]
		if !ok && len(l.ips) >= l.maxIPs {
			l.mu.Unlock()
			if l.maxConns > 0 {
				l.conns.Add(-1)
			}
			return false
		}
		l.ips[ip] = n + 1
		l.mu.Unlock()
	}
	return true
}

// Release 归还名额。
func (l *Limits) Release(ip netip.Addr) {
	if l == nil {
		return
	}
	if l.maxConns > 0 {
		l.conns.Add(-1)
	}
	if l.maxIPs > 0 {
		l.mu.Lock()
		if n := l.ips[ip]; n <= 1 {
			delete(l.ips, ip)
		} else {
			l.ips[ip] = n - 1
		}
		l.mu.Unlock()
	}
}

// AcquireAll 依次申请多组限制,任一失败则回滚。
func AcquireAll(ip netip.Addr, ls ...*Limits) bool {
	for i, l := range ls {
		if !l.Acquire(ip) {
			for j := 0; j < i; j++ {
				ls[j].Release(ip)
			}
			return false
		}
	}
	return true
}

// ReleaseAll 归还多组限制。
func ReleaseAll(ip netip.Addr, ls ...*Limits) {
	for _, l := range ls {
		l.Release(ip)
	}
}
