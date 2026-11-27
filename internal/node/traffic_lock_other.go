//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package node

import (
	"errors"
	"os"
)

func lockTraffic(d *os.File) error {
	return errors.New("durable metering requires filesystem directory locking on a supported OS")
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
