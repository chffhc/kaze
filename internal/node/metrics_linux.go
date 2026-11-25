//go:build linux

package node

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"kaze/internal/proto"
)

// metricsCollector 从 /proc 采集探针数据。
type metricsCollector struct {
	ifaces             map[string]bool // 指定统计的网卡;为空则自动选择
	lastTotal, lastIdl uint64
	lastRx, lastTx     uint64
	lastT              time.Time
}

func newMetricsCollector(iface string) *metricsCollector {
	m := &metricsCollector{}
	for _, s := range strings.Split(iface, ",") {
		if s = strings.TrimSpace(s); s != "" {
			if m.ifaces == nil {
				m.ifaces = make(map[string]bool)
			}
			m.ifaces[s] = true
		}
	}
	m.sample()
	return m
}

// 自动选择网卡时跳过回环与常见的虚拟网卡,避免流量被重复统计。
var virtualPrefixes = []string{"lo", "docker", "veth", "br-", "virbr", "cni", "flannel", "kube", "dummy", "tun", "tap", "wg", "tailscale", "ifb", "sit", "ip6tnl", "gre"}

func (m *metricsCollector) countIface(name string) bool {
	if m.ifaces != nil {
		return m.ifaces[name]
	}
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	return true
}

func (m *metricsCollector) sample() proto.Metrics {
	var out proto.Metrics
	now := time.Now()

	if b, err := os.ReadFile("/proc/stat"); err == nil {
		line, _, _ := strings.Cut(string(b), "\n")
		f := strings.Fields(line)
		var total, idle uint64
		for i := 1; i < len(f); i++ {
			v, _ := strconv.ParseUint(f[i], 10, 64)
			total += v
			if i == 4 || i == 5 { // idle + iowait
				idle += v
			}
		}
		if dt := total - m.lastTotal; m.lastTotal != 0 && dt > 0 {
			out.CPU = 100 * (1 - float64(idle-m.lastIdl)/float64(dt))
			if out.CPU < 0 {
				out.CPU = 0
			}
		}
		m.lastTotal, m.lastIdl = total, idle
	}

	if f, err := os.Open("/proc/meminfo"); err == nil {
		sc := bufio.NewScanner(f)
		var avail uint64
		for sc.Scan() {
			k, v, _ := strings.Cut(sc.Text(), ":")
			n, _ := strconv.ParseUint(strings.Fields(v + " 0")[0], 10, 64)
			switch k {
			case "MemTotal":
				out.MemTotal = n * 1024
			case "MemAvailable":
				avail = n * 1024
			}
		}
		f.Close()
		if out.MemTotal > avail {
			out.MemUsed = out.MemTotal - avail
		}
	}

	if f, err := os.Open("/proc/net/dev"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			name, rest, ok := strings.Cut(sc.Text(), ":")
			if !ok {
				continue
			}
			name = strings.TrimSpace(name)
			fs := strings.Fields(rest)
			if len(fs) < 9 || !m.countIface(name) {
				continue
			}
			rx, _ := strconv.ParseUint(fs[0], 10, 64)
			tx, _ := strconv.ParseUint(fs[8], 10, 64)
			out.NetRx += rx
			out.NetTx += tx
		}
		f.Close()
		if el := now.Sub(m.lastT).Seconds(); !m.lastT.IsZero() && el > 0 {
			if out.NetRx >= m.lastRx {
				out.RxRate = uint64(float64(out.NetRx-m.lastRx) / el)
			}
			if out.NetTx >= m.lastTx {
				out.TxRate = uint64(float64(out.NetTx-m.lastTx) / el)
			}
		}
		m.lastRx, m.lastTx = out.NetRx, out.NetTx
	}

	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			out.Load1, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			up, _ := strconv.ParseFloat(f[0], 64)
			out.Uptime = uint64(up)
		}
	}
	var st syscall.Statfs_t
	if syscall.Statfs("/", &st) == nil {
		out.DiskTotal = st.Blocks * uint64(st.Bsize)
		out.DiskUsed = (st.Blocks - st.Bfree) * uint64(st.Bsize)
	}
	m.lastT = now
	return out
}
