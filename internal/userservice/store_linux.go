//go:build linux

// ---
// relationships:
//   implements: linux-user-service
// ---

package userservice

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const maximumUnitBytes = 64 * 1024
const pendingRestartName = ".wyrwood.service.pending-restart"

var errUnitDirectoryAbsent = errors.New("user unit directory does not exist")

type unitStore interface {
	inspect(string, uint32) (bool, error)
	install(string, []byte, uint32) (bool, error)
	remove(string, uint32) (bool, error)
	pending(string, uint32) (bool, error)
	clearPending(string, uint32) error
}

type fileUnitStore struct{ beforeReplace func() error }

func (fileUnitStore) inspect(path string, uid uint32) (bool, error) {
	directory, err := openUnitDirectory(path, uid, false)
	if errors.Is(err, errUnitDirectoryAbsent) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer unix.Close(directory)
	file, err := openUnitFile(directory, uid)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, file.Close()
}

func (store fileUnitStore) install(path string, contents []byte, uid uint32) (bool, error) {
	if len(contents) == 0 || len(contents) > maximumUnitBytes {
		return false, errors.New("rendered user unit has an invalid size")
	}
	directory, err := openUnitDirectory(path, uid, true)
	if err != nil {
		return false, err
	}
	defer unix.Close(directory)

	current, err := readUnit(directory, uid)
	if err == nil && bytes.Equal(current, contents) {
		if err := discardMismatchedPending(directory, uid, contents); err != nil {
			return false, err
		}
		return false, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := writePendingRestart(directory, uid, contents); err != nil {
		return false, err
	}
	if store.beforeReplace != nil {
		if err := store.beforeReplace(); err != nil {
			return false, err
		}
	}

	temporaryName, temporary, err := createTemporaryFile(directory, ".wyrwood.service-")
	if err != nil {
		return false, err
	}
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = unix.Unlinkat(directory, temporaryName, 0)
		}
	}()
	if _, err := io.Copy(temporary, bytes.NewReader(contents)); err != nil {
		return false, errors.New("write replacement user unit")
	}
	if err := temporary.Sync(); err != nil {
		return false, errors.New("sync replacement user unit")
	}
	if err := temporary.Close(); err != nil {
		return false, errors.New("close replacement user unit")
	}
	if err := unix.Renameat(directory, temporaryName, directory, UnitName); err != nil {
		return false, errors.New("replace user unit")
	}
	committed = true
	if err := unix.Fsync(directory); err != nil {
		return true, &DurabilityError{Err: errors.New("sync user unit directory")}
	}
	return true, nil
}

func (fileUnitStore) remove(path string, uid uint32) (bool, error) {
	directory, err := openUnitDirectory(path, uid, false)
	if errors.Is(err, errUnitDirectoryAbsent) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer unix.Close(directory)
	removed := false
	file, err := openUnitFile(directory, uid)
	if err == nil {
		if err := file.Close(); err != nil {
			return false, errors.New("close user unit")
		}
		if err := unix.Unlinkat(directory, UnitName, 0); err != nil {
			return false, errors.New("remove user unit")
		}
		removed = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	pending, err := openPendingRestart(directory, uid)
	if err == nil {
		if err := pending.Close(); err != nil {
			return false, errors.New("close pending restart marker")
		}
		if err := unix.Unlinkat(directory, pendingRestartName, 0); err != nil {
			return false, errors.New("remove pending restart marker")
		}
		removed = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if !removed {
		return false, nil
	}
	if err := unix.Fsync(directory); err != nil {
		return true, &DurabilityError{Err: errors.New("sync user unit directory")}
	}
	return true, nil
}

func (fileUnitStore) pending(path string, uid uint32) (bool, error) {
	directory, err := openUnitDirectory(path, uid, false)
	if errors.Is(err, errUnitDirectoryAbsent) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer unix.Close(directory)
	marker, err := readPendingRestart(directory, uid)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	unit, err := readUnit(directory, uid)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256(unit)
	return bytes.Equal(marker, digest[:]), nil
}

func (fileUnitStore) clearPending(path string, uid uint32) error {
	directory, err := openUnitDirectory(path, uid, false)
	if errors.Is(err, errUnitDirectoryAbsent) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(directory)
	marker, err := openPendingRestart(directory, uid)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := marker.Close(); err != nil {
		return errors.New("close pending restart marker")
	}
	if err := unix.Unlinkat(directory, pendingRestartName, 0); err != nil {
		return errors.New("remove pending restart marker")
	}
	if err := unix.Fsync(directory); err != nil {
		return &DurabilityError{Err: errors.New("sync user unit directory")}
	}
	return nil
}

func openUnitDirectory(path string, uid uint32, create bool) (int, error) {
	if err := validateUnitPath(path); err != nil {
		return -1, err
	}
	directoryPath := filepath.Dir(path)
	current, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, errors.New("open filesystem root")
	}
	for _, component := range strings.Split(strings.TrimPrefix(directoryPath, string(filepath.Separator)), string(filepath.Separator)) {
		if create {
			if err := unix.Mkdirat(current, component, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
				unix.Close(current)
				return -1, errors.New("create user unit directory")
			}
		}
		next, openErr := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(current)
		if errors.Is(openErr, unix.ENOENT) && !create {
			return -1, errUnitDirectoryAbsent
		}
		if openErr != nil {
			return -1, errors.New("open user unit directory without following links")
		}
		current = next
	}
	var status unix.Stat_t
	if err := unix.Fstat(current, &status); err != nil || status.Uid != uid ||
		status.Mode&unix.S_IFMT != unix.S_IFDIR || status.Mode&0o022 != 0 {
		unix.Close(current)
		return -1, errors.New("user unit directory must be owned and not writable by other users")
	}
	return current, nil
}

func openUnitFile(directory int, uid uint32) (*os.File, error) {
	descriptor, err := unix.Openat(directory, UnitName, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, errors.New("open user unit without following links")
	}
	var status unix.Stat_t
	if err := unix.Fstat(descriptor, &status); err != nil || status.Uid != uid ||
		status.Mode&unix.S_IFMT != unix.S_IFREG || status.Mode&0o7777 != unitMode ||
		status.Size < 0 || status.Size > maximumUnitBytes {
		unix.Close(descriptor)
		return nil, errors.New("user unit must be a bounded owner-only regular file")
	}
	return os.NewFile(uintptr(descriptor), UnitName), nil
}

func writePendingRestart(directory int, uid uint32, contents []byte) error {
	digest := sha256.Sum256(contents)
	existing, err := readPendingRestart(directory, uid)
	if err == nil && bytes.Equal(existing, digest[:]) {
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	name, marker, err := createTemporaryFile(directory, ".wyrwood.pending-restart-")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = marker.Close()
		if !committed {
			_ = unix.Unlinkat(directory, name, 0)
		}
	}()
	if _, err := marker.Write(digest[:]); err != nil {
		return errors.New("write pending restart marker")
	}
	if err := marker.Sync(); err != nil {
		return errors.New("sync pending restart marker")
	}
	if err := marker.Close(); err != nil {
		return errors.New("close pending restart marker")
	}
	if err := unix.Renameat(directory, name, directory, pendingRestartName); err != nil {
		return errors.New("replace pending restart marker")
	}
	committed = true
	if err := unix.Fsync(directory); err != nil {
		return &DurabilityError{Err: errors.New("sync pending restart marker")}
	}
	return nil
}

func openPendingRestart(directory int, uid uint32) (*os.File, error) {
	descriptor, err := unix.Openat(directory, pendingRestartName, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, errors.New("open pending restart marker without following links")
	}
	var status unix.Stat_t
	if err := unix.Fstat(descriptor, &status); err != nil || status.Uid != uid ||
		status.Mode&unix.S_IFMT != unix.S_IFREG || status.Mode&0o7777 != unitMode || status.Size != sha256.Size {
		unix.Close(descriptor)
		return nil, errors.New("pending restart marker must be a bounded owner-only regular file")
	}
	return os.NewFile(uintptr(descriptor), pendingRestartName), nil
}

func readPendingRestart(directory int, uid uint32) ([]byte, error) {
	marker, err := openPendingRestart(directory, uid)
	if err != nil {
		return nil, err
	}
	defer marker.Close()
	contents, err := io.ReadAll(io.LimitReader(marker, sha256.Size+1))
	if err != nil || len(contents) != sha256.Size {
		return nil, errors.New("read pending restart marker")
	}
	return contents, nil
}

func discardMismatchedPending(directory int, uid uint32, contents []byte) error {
	marker, err := readPendingRestart(directory, uid)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	digest := sha256.Sum256(contents)
	if bytes.Equal(marker, digest[:]) {
		return nil
	}
	if err := unix.Unlinkat(directory, pendingRestartName, 0); err != nil {
		return errors.New("discard obsolete pending restart marker")
	}
	if err := unix.Fsync(directory); err != nil {
		return &DurabilityError{Err: errors.New("sync user unit directory")}
	}
	return nil
}

func readUnit(directory int, uid uint32) ([]byte, error) {
	file, err := openUnitFile(directory, uid)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maximumUnitBytes+1))
	if err != nil || len(contents) > maximumUnitBytes {
		return nil, errors.New("read bounded user unit")
	}
	return contents, nil
}

func createTemporaryFile(directory int, prefix string) (string, *os.File, error) {
	for attempt := 0; attempt < 16; attempt++ {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", nil, errors.New("name replacement user unit")
		}
		name := fmt.Sprintf("%s%x", prefix, random)
		descriptor, err := unix.Openat(directory, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, unitMode)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", nil, errors.New("create replacement user unit")
		}
		return name, os.NewFile(uintptr(descriptor), name), nil
	}
	return "", nil, errors.New("allocate replacement user unit")
}

func validateUnitPath(path string) error {
	if err := validatePath(path); err != nil || filepath.Base(path) != UnitName || filepath.Dir(path) == string(filepath.Separator) {
		return errors.New("user unit path is unsafe")
	}
	return nil
}

func ownerUID(info os.FileInfo) uint32 {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ^uint32(0)
	}
	return status.Uid
}
