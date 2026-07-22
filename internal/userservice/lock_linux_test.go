//go:build linux

// ---
// relationships:
//   verifies: linux-user-service
// ---

package userservice

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileOperationLockerSerializesServiceMutations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "systemd", "user", UnitName)
	locker := fileOperationLocker{}
	first, err := locker.lock(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })

	acquired := make(chan error, 1)
	go func() {
		second, lockErr := locker.lock(path, uint32(os.Geteuid()))
		if lockErr == nil {
			lockErr = second.Close()
		}
		acquired <- lockErr
	}()
	select {
	case err := <-acquired:
		t.Fatalf("second lock did not wait: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := first.Close(); err != nil {
		t.Fatalf("release first lock: %v", err)
	}
	select {
	case err := <-acquired:
		if err != nil {
			t.Fatalf("second lock: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second lock did not acquire after release")
	}
}

func TestFileOperationLockerRejectsSymlinkEntry(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "systemd", "user")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatalf("MkdirAll(): %v", err)
	}
	if err := os.Symlink("target", filepath.Join(directory, operationLockName)); err != nil {
		t.Fatalf("Symlink(): %v", err)
	}
	if lock, err := (fileOperationLocker{}).lock(filepath.Join(directory, UnitName), uint32(os.Geteuid())); err == nil {
		_ = lock.Close()
		t.Fatal("lock followed a symlink entry")
	}
}
