//go:build linux

package relay

// Linux 上 *net.TCPConn 之间的 io.Copy 会使用 splice(2)。
const canSplice = true
