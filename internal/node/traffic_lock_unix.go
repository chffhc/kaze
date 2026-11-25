//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package node

import (
	"os"
	"syscall"
)

func lockTraffic(d *os.File) error {
	return syscall.Flock(int(d.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
