//go:build linux

// ---
// relationships:
//   implements: linux-user-service
// ---

package userservice

import (
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const (
	operationLockName    = ".wyrwood.service.lock"
	operationLockTimeout = 30 * time.Second
)

type operationLocker interface {
	lock(string, uint32) (io.Closer, error)
}

type fileOperationLocker struct{}

func (fileOperationLocker) lock(path string, uid uint32) (io.Closer, error) {
	directory, err := openUnitDirectory(path, uid, true)
	if err != nil {
		return nil, err
	}
	defer unix.Close(directory)
	descriptor, err := unix.Openat(
		directory, operationLockName,
		unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		unitMode,
	)
	if err != nil {
		return nil, errors.New("open user service operation lock")
	}
	file := os.NewFile(uintptr(descriptor), operationLockName)
	var status unix.Stat_t
	if err := unix.Fstat(descriptor, &status); err != nil || status.Uid != uid ||
		status.Mode&unix.S_IFMT != unix.S_IFREG || status.Mode&0o7777 != unitMode {
		_ = file.Close()
		return nil, errors.New("user service operation lock must be an owner-only regular file")
	}
	deadline := time.Now().Add(operationLockTimeout)
	for {
		err := unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return file, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = file.Close()
			return nil, errors.New("lock user service operation")
		}
		if time.Now().After(deadline) {
			_ = file.Close()
			return nil, errors.New("user service operation lock timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
