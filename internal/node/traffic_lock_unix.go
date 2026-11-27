//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package node

import (
	"os"
	"syscall"
)

func lockTraffic(d *os.File) error {
	return syscall.Flock(int(d.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func openTrafficLock(path string) (*os.File, error) { return os.Open(path) }
func replaceTrafficFile(src, dst string) error      { return os.Rename(src, dst) }
func syncTrafficDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
