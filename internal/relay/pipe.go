package relay

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"time"
)

const (
	// 一个方向正常结束(半关闭)后,另一方向允许的最长空闲时间。
	halfCloseIdle = 5 * time.Minute
	// 对端不支持半关闭时的收尾时间。
	noHalfCloseLinger = 10 * time.Second
	// splice 零拷贝路径每次计量的块大小:块越小流量统计越实时,开销越大。
	spliceChunk = 512 * 1024
)

// PipeOpts 是一次 TCP 双向转发的参数。
// 约定:Up = 客户端 -> 目标,Down = 目标 -> 客户端。
type PipeOpts struct {
	Context              context.Context
	Up, Down             *atomic.Int64 // 流量计数器(不可为 nil)
	UpLimits, DownLimits [2]*Bucket    // 规则级、用户级限速桶,nil 表示不限
	Prefix               []byte        // 已从客户端读出(嗅探)、需要先写给目标的数据
}

type pipe struct {
	half atomic.Bool // 已有一个方向正常结束
}

// Pipe 在 client 与 target 之间双向转发,直到两个方向都结束,然后关闭两端。
//
// 性能路径:两端都是 *net.TCPConn 且不限速时走 splice(2) 零拷贝(Linux);
// 否则走带缓冲池的用户态拷贝。支持 TCP 半关闭语义(CloseWrite),
// 出错时对两端执行 abort(yamux 流发送 RST),避免对端继续空发数据。
func Pipe(client, target net.Conn, o *PipeOpts) {
	ActiveTCP.Add(1)
	defer ActiveTCP.Add(-1)
	p := &pipe{}
	ctx := o.Context
	if ctx == nil {
		ctx = context.Background()
	}
	done := make(chan struct{})
	go func() {
		p.oneWay(target, client, o.Up, o.UpLimits, o.Prefix, ctx)
		close(done)
	}()
	p.oneWay(client, target, o.Down, o.DownLimits, nil, ctx)
	<-done
	client.Close()
	target.Close()
}

func (p *pipe) oneWay(dst, src net.Conn, ctr *atomic.Int64, lim [2]*Bucket, prefix []byte, ctx context.Context) {
	if err := p.copy(dst, src, ctr, lim, prefix, ctx); err != nil {
		Abort(src)
		Abort(dst)
		return
	}
	// src 正常 EOF:把半关闭传递给 dst,并给反方向设置空闲上限,防止连接永久悬挂。
	linger := halfCloseIdle
	if !CloseWrite(dst) {
		linger = noHalfCloseLinger
	}
	if !p.half.Swap(true) {
		dst.SetReadDeadline(time.Now().Add(linger))
	}
}

func (p *pipe) copy(dst, src net.Conn, ctr *atomic.Int64, lim [2]*Bucket, prefix []byte, ctx context.Context) error {
	if len(prefix) > 0 {
		if err := waitPipeLimits(ctx, lim, len(prefix)); err != nil {
			return err
		}
		written, err := dst.Write(prefix)
		ctr.Add(int64(written))
		if err != nil {
			return err
		}
	}
	if canSplice && lim[0] == nil && lim[1] == nil {
		if d, ok := dst.(*net.TCPConn); ok {
			if s, ok := src.(*net.TCPConn); ok {
				return p.spliceLoop(d, s, ctr)
			}
		}
	}
	bp := tcpBufPool.Get().(*[]byte)
	defer tcpBufPool.Put(bp)
	buf := *bp
	if c := lim[0].Chunk(); c < len(buf) {
		buf = buf[:c]
	}
	if c := lim[1].Chunk(); c < len(buf) {
		buf = buf[:c]
	}
	for {
		if p.half.Load() {
			src.SetReadDeadline(time.Now().Add(halfCloseIdle))
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if err := waitPipeLimits(ctx, lim, n); err != nil {
				return err
			}
			written, werr := dst.Write(buf[:n])
			ctr.Add(int64(written))
			if werr != nil {
				return werr
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return nil
			}
			return rerr
		}
	}
}

func waitPipeLimits(ctx context.Context, lim [2]*Bucket, n int) error {
	for _, bucket := range lim {
		if err := bucket.wait(ctx, n); err != nil {
			return err
		}
	}
	return nil
}

// spliceLoop 利用 io.CopyN -> (*TCPConn).ReadFrom -> splice(2) 实现内核态零拷贝,
// 同时按块统计流量。
func (p *pipe) spliceLoop(dst, src *net.TCPConn, ctr *atomic.Int64) error {
	for {
		if p.half.Load() {
			src.SetReadDeadline(time.Now().Add(halfCloseIdle))
		}
		n, err := io.CopyN(dst, src, spliceChunk)
		if n > 0 {
			ctr.Add(n)
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// CloseWrite 关闭写方向(半关闭)。连接不支持半关闭时返回 false。
func CloseWrite(c net.Conn) bool {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return true
	}
	return false
}

// Abort 立即终止连接:多路复用流发送 RST,其余直接关闭。
func Abort(c net.Conn) {
	if tlsConn, ok := c.(interface{ NetConn() net.Conn }); ok {
		Abort(tlsConn.NetConn())
		return
	}
	if r, ok := c.(interface{ Reset() error }); ok {
		r.Reset()
		return
	}
	c.Close()
}
