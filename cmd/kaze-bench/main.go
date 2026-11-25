// kaze-bench 是配套的压测工具:自带目标服务端(下载/上传/回显)与三种压测客户端。
//
//	kaze-bench server -l :9000                     启动目标服务端(TCP + UDP 回显)
//	kaze-bench tcp  -a host:port -c 8 -d 10s -m down   TCP 吞吐(down/up)
//	kaze-bench conn -a host:port -c 64 -d 10s          新建连接速率与首字节延迟
//	kaze-bench udp  -a host:port -c 4 -d 5s -s 1200    UDP 回显吞吐与丢包
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: kaze-bench server|tcp|conn|udp [参数]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	listen := fs.String("l", ":9000", "服务端监听地址")
	addr := fs.String("a", "127.0.0.1:9000", "压测目标地址")
	conc := fs.Int("c", 8, "并发数")
	dur := fs.Duration("d", 10*time.Second, "持续时间")
	mode := fs.String("m", "down", "tcp 模式: down / up")
	size := fs.Int("s", 1200, "udp 报文大小")
	fs.Parse(os.Args[2:])
	switch os.Args[1] {
	case "server":
		server(*listen)
	case "tcp":
		benchTCP(*addr, *conc, *dur, *mode)
	case "conn":
		benchConn(*addr, *conc, *dur)
	case "udp":
		benchUDP(*addr, *conc, *dur, *size)
	default:
		fmt.Println("未知子命令:", os.Args[1])
		os.Exit(2)
	}
}

// 服务端协议:客户端先发 1 字节。'D' = 服务端持续发送;'U' = 服务端只收;'E' = 回显。
func server(listen string) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if ua, err := net.ResolveUDPAddr("udp", listen); err == nil {
		if uc, err := net.ListenUDP("udp", ua); err == nil {
			uc.SetReadBuffer(8 << 20)
			uc.SetWriteBuffer(8 << 20)
			go func() {
				buf := make([]byte, 65536)
				for {
					n, from, err := uc.ReadFromUDPAddrPort(buf)
					if err != nil {
						return
					}
					uc.WriteToUDPAddrPort(buf[:n], from)
				}
			}()
		}
	}
	fmt.Println("kaze-bench 服务端监听", listen)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer c.Close()
			var m [1]byte
			if _, err := io.ReadFull(c, m[:]); err != nil {
				return
			}
			switch m[0] {
			case 'D':
				buf := make([]byte, 256*1024)
				for {
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			case 'U':
				io.Copy(io.Discard, c)
			default:
				c.Write(m[:])
				io.Copy(c, c)
			}
		}()
	}
}

func benchTCP(addr string, conc int, dur time.Duration, mode string) {
	var total atomic.Int64
	var wg sync.WaitGroup
	deadline := time.Now().Add(dur)
	start := time.Now()
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				fmt.Println("连接失败:", err)
				return
			}
			defer c.Close()
			c.SetDeadline(deadline)
			buf := make([]byte, 256*1024)
			if mode == "up" {
				c.Write([]byte{'U'})
				for {
					n, err := c.Write(buf)
					total.Add(int64(n))
					if err != nil {
						return
					}
				}
			}
			c.Write([]byte{'D'})
			for {
				n, err := c.Read(buf)
				total.Add(int64(n))
				if err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()
	el := time.Since(start).Seconds()
	b := float64(total.Load())
	fmt.Printf("TCP %s  并发 %d  时长 %.1fs  总量 %.2f GB  吞吐 %.2f Gbps (%.0f MB/s)\n",
		mode, conc, el, b/1e9, b*8/el/1e9, b/el/1e6)
}

func benchConn(addr string, conc int, dur time.Duration) {
	var ok, fail atomic.Int64
	var mu sync.Mutex
	var lats []time.Duration
	var wg sync.WaitGroup
	deadline := time.Now().Add(dur)
	start := time.Now()
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var local []time.Duration
			var b [1]byte
			for time.Now().Before(deadline) {
				t0 := time.Now()
				c, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil {
					fail.Add(1)
					continue
				}
				c.SetDeadline(time.Now().Add(5 * time.Second))
				c.Write([]byte{'E'})
				_, err = io.ReadFull(c, b[:])
				if tc, isTCP := c.(*net.TCPConn); isTCP {
					tc.SetLinger(0) // 避免压测机本地端口耗尽在 TIME_WAIT 上
				}
				c.Close()
				if err != nil {
					fail.Add(1)
					continue
				}
				ok.Add(1)
				local = append(local, time.Since(t0))
			}
			mu.Lock()
			lats = append(lats, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	el := time.Since(start).Seconds()
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	pct := func(p float64) time.Duration {
		if len(lats) == 0 {
			return 0
		}
		return lats[int(float64(len(lats)-1)*p)]
	}
	fmt.Printf("CONN 并发 %d  时长 %.1fs  成功 %d  失败 %d  速率 %.0f 连接/秒  首字节延迟 p50 %v  p99 %v\n",
		conc, el, ok.Load(), fail.Load(), float64(ok.Load())/el,
		pct(0.5).Round(time.Microsecond), pct(0.99).Round(time.Microsecond))
}

func benchUDP(addr string, conc int, dur time.Duration, size int) {
	var sent, recv atomic.Int64
	var wg sync.WaitGroup
	deadline := time.Now().Add(dur)
	start := time.Now()
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("udp", addr)
			if err != nil {
				fmt.Println("连接失败:", err)
				return
			}
			defer c.Close()
			done := make(chan struct{})
			go func() { // 收
				defer close(done)
				buf := make([]byte, 65536)
				for {
					c.SetReadDeadline(time.Now().Add(time.Second))
					if _, err := c.Read(buf); err != nil {
						if time.Now().After(deadline) {
							return
						}
						continue
					}
					recv.Add(1)
				}
			}()
			buf := make([]byte, size)
			// 以窗口方式发送:在途报文不超过 64 个,测的是无丢包前提下的最大回显速率
			for time.Now().Before(deadline) {
				if sent.Load()-recv.Load() > int64(64*conc) {
					time.Sleep(50 * time.Microsecond)
					continue
				}
				if _, err := c.Write(buf); err == nil {
					sent.Add(1)
				}
			}
			<-done
		}()
	}
	wg.Wait()
	el := time.Since(start).Seconds()
	s, r := sent.Load(), recv.Load()
	loss := 0.0
	if s > 0 {
		loss = 100 * float64(s-r) / float64(s)
	}
	fmt.Printf("UDP 并发 %d  报文 %dB  时长 %.1fs  发送 %d  收到 %d  丢包 %.2f%%  回显 %.0f pps (%.1f Mbps)\n",
		conc, size, el, s, r, loss, float64(r)/el, float64(r)*float64(size)*8/el/1e6)
}
