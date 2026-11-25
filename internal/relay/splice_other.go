//go:build !linux

package relay

// 非 Linux 平台没有 splice,统一走带缓冲池的用户态拷贝。
const canSplice = false
