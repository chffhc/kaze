package node

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func openTrafficLock(path string) (*os.File, error) {
	return os.OpenFile(filepath.Join(path, ".kaze-traffic.lock"), os.O_CREATE|os.O_RDWR, 0600)
}

func lockTraffic(f *os.File) error {
	var offset windows.Overlapped
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &offset)
}

func replaceTrafficFile(src, dst string) error {
	from, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// MoveFileEx requests write-through for the replacement on Windows.
func syncTrafficDir(string) error { return nil }
