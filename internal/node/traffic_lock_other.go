//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package node

import (
	"errors"
	"os"
)

func lockTraffic(d *os.File) error {
	return errors.New("durable metering requires filesystem directory locking on a supported OS")
}
