// ---
// relationships:
//   implements: operational-events
// ---

package events

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const replacementPrefix = ".events-"

func validateStorageInputs(path string, retention int) error {
	if strings.IndexByte(path, 0) >= 0 {
		return errors.New("event store path must not contain a NUL byte")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("event store path must be canonical and absolute")
	}
	root := string(filepath.Separator)
	directory := filepath.Dir(path)
	if path == root || directory == root || filepath.Dir(directory) == root {
		return errors.New("event store path must use a dedicated directory below the filesystem root")
	}
	if retention <= 0 || retention > maximumRetention {
		return fmt.Errorf("retention must be between 1 and %d", maximumRetention)
	}
	return nil
}

func cleanupStaleReplacements(directory string, remove func(string) error) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), replacementPrefix) {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if err := requireCurrentOwner(info); err != nil {
			continue
		}
		if err := remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		removed = true
	}
	if removed {
		return syncDirectory(directory)
	}
	return nil
}

func ensureOwnerOnlyDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create event store directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect event store directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("event store directory must be a real directory")
	}
	if err := requireCurrentOwner(info); err != nil {
		return fmt.Errorf("event store directory: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("secure event store directory: %w", err)
	}
	return nil
}

func openOwnerOnlyFile(path string, flags int) (*os.File, error) {
	fileDescriptor, err := unix.Open(path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fileDescriptor), path)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("event store file must be regular")
	}
	if err := requireCurrentOwner(info); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func requireCurrentOwner(info os.FileInfo) error {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("ownership metadata is unavailable")
	}
	if status.Uid != uint32(os.Geteuid()) {
		return errors.New("path is not owned by the daemon user")
	}
	return nil
}

func syncDirectory(path string) error {
	fileDescriptor, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("open directory without following symlinks: %w", err)
	}
	syncErr := unix.Fsync(fileDescriptor)
	closeErr := unix.Close(fileDescriptor)
	if syncErr != nil || closeErr != nil {
		return errors.Join(syncErr, closeErr)
	}
	return nil
}
