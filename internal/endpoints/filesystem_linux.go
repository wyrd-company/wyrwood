//go:build linux

// ---
// relationships:
//   implements: linux-per-user-agent-proxy
// ---

package endpoints

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/wyrd-company/wyrwood/internal/runtime"
	"golang.org/x/sys/unix"
)

// Linux sockaddr_un.sun_path is 108 bytes including its terminating NUL.
const maximumUnixSocketPathBytes = 107

type fileIdentity struct {
	device uint64
	inode  uint64
}

// parentHandle pins the exact dedicated directory inode visible to a mounted
// consumer. Ownership moves from staged listener to active endpoint to pending
// cleanup and ends only after the socket inode is gone.
type parentHandle struct {
	fd       int
	identity fileIdentity
}

type endpointFile struct {
	parent   *parentHandle
	name     string
	identity fileIdentity
}

type stagedSocket struct {
	path         string
	consumer     runtime.Consumer
	listener     *net.UnixListener
	file         *endpointFile
	parentChange *metadataChange
}

func prepareSocket(consumer runtime.Consumer) (*stagedSocket, error) {
	if err := validateConsumerFilesystemInputs(consumer); err != nil {
		return nil, err
	}
	directoryMode, socketMode, group := desiredPermissions(consumer)
	directory := filepath.Dir(consumer.Socket())
	parent, original, created, err := openConsumerDirectory(directory)
	if err != nil {
		return nil, err
	}
	change := &metadataChange{
		path:          consumer.Socket(),
		file:          &endpointFile{parent: parent, name: filepath.Base(consumer.Socket())},
		parentBefore:  original,
		directoryMode: directoryMode,
		socketMode:    socketMode,
		group:         cloneGroup(group),
	}
	if created {
		change = nil
	}
	closeOnError := func(cause error) (*stagedSocket, error) {
		if change != nil {
			cause = errors.Join(cause, change.rollback())
		} else {
			_ = unix.Fchmod(parent.fd, 0o700)
		}
		return nil, errors.Join(cause, parent.close())
	}

	if err := applyDirectoryPermissions(parent.fd, directoryMode, group); err != nil {
		return closeOnError(err)
	}
	name := filepath.Base(consumer.Socket())
	if err := removeStaleOwnedSocket(parent, name, consumer.Socket()); err != nil {
		return closeOnError(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: consumer.Socket(), Net: "unix"})
	if err != nil {
		return closeOnError(fmt.Errorf("bind consumer listener: %w", err))
	}
	listener.SetUnlinkOnClose(false)

	identity, err := secureSocket(parent.fd, name, socketMode, group)
	file := &endpointFile{parent: parent, name: name, identity: identity}
	candidate := &stagedSocket{
		path:         consumer.Socket(),
		consumer:     consumer,
		listener:     listener,
		file:         file,
		parentChange: change,
	}
	if err != nil {
		if identity != (fileIdentity{}) {
			return candidate, err
		}
		closeErr := listener.Close()
		unlinkErr := unix.Unlinkat(parent.fd, name, 0)
		if change != nil {
			unlinkErr = errors.Join(unlinkErr, change.rollback())
		}
		return nil, errors.Join(err, closeErr, unlinkErr, parent.close())
	}
	return candidate, nil
}

func openConsumerDirectory(path string) (*parentHandle, fileMetadata, bool, error) {
	ancestor := filepath.Dir(path)
	name := filepath.Base(path)
	ancestorFD, err := unix.Open(ancestor, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fileMetadata{}, false, fmt.Errorf("open consumer parent ancestor: %w", err)
	}
	defer unix.Close(ancestorFD)

	created := false
	if err := unix.Mkdirat(ancestorFD, name, 0o700); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return nil, fileMetadata{}, false, fmt.Errorf("create consumer parent: %w", err)
		}
	} else {
		created = true
	}
	directoryFD, err := unix.Openat(ancestorFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fileMetadata{}, created, fmt.Errorf("open consumer parent: %w", err)
	}
	metadata, err := statFD(directoryFD)
	if err != nil {
		unix.Close(directoryFD)
		return nil, fileMetadata{}, created, fmt.Errorf("inspect consumer parent: %w", err)
	}
	if metadata.mode&unix.S_IFMT != unix.S_IFDIR || metadata.owner != uint32(os.Geteuid()) {
		unix.Close(directoryFD)
		return nil, fileMetadata{}, created, errors.New("consumer parent is not an owned real directory")
	}
	return &parentHandle{fd: directoryFD, identity: metadata.identity}, metadata, created, nil
}

func secureSocket(directoryFD int, name string, mode uint32, group *uint32) (fileIdentity, error) {
	metadata, err := statAt(directoryFD, name)
	if err != nil {
		return fileIdentity{}, fmt.Errorf("inspect bound consumer socket: %w", err)
	}
	if metadata.mode&unix.S_IFMT != unix.S_IFSOCK || metadata.owner != uint32(os.Geteuid()) {
		return metadata.identity, errors.New("bound consumer endpoint is not an owned socket")
	}
	if err := applyAtPermissions(directoryFD, name, mode, group); err != nil {
		return metadata.identity, err
	}
	verified, err := statAt(directoryFD, name)
	if err != nil {
		return metadata.identity, fmt.Errorf("verify bound consumer socket: %w", err)
	}
	if verified.identity != metadata.identity || verified.mode&unix.S_IFMT != unix.S_IFSOCK {
		return metadata.identity, errors.New("bound consumer socket identity changed")
	}
	return verified.identity, nil
}

func removeStaleOwnedSocket(parent *parentHandle, name, path string) error {
	metadata, err := statAt(parent.fd, name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing consumer socket path: %w", err)
	}
	if metadata.mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("consumer socket path contains a non-socket entry")
	}
	if metadata.owner != uint32(os.Geteuid()) {
		return errors.New("consumer socket path contains a foreign socket")
	}
	connection, probeErr := net.DialTimeout("unix", path, 25*time.Millisecond)
	if probeErr == nil {
		_ = connection.Close()
		return errors.New("consumer socket path is already served by a live listener")
	}
	if !errors.Is(probeErr, unix.ECONNREFUSED) {
		return fmt.Errorf("verify stale consumer socket: %w", probeErr)
	}
	if err := unix.Unlinkat(parent.fd, name, 0); err != nil {
		return fmt.Errorf("remove stale consumer socket: %w", err)
	}
	return nil
}

func removeSocket(file *endpointFile) error {
	if file == nil || file.parent == nil {
		return errors.New("consumer socket cleanup handle is absent")
	}
	parent, err := statFD(file.parent.fd)
	if err != nil {
		return fmt.Errorf("inspect pinned consumer parent for cleanup: %w", err)
	}
	if parent.identity != file.parent.identity || parent.mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("pinned consumer parent identity changed before cleanup")
	}
	metadata, err := statAt(file.parent.fd, file.name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect consumer socket for cleanup: %w", err)
	}
	if metadata.identity != file.identity {
		return nil
	}
	if metadata.mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("owned consumer socket was replaced by a non-socket entry")
	}
	if err := unix.Unlinkat(file.parent.fd, file.name, 0); err != nil {
		return fmt.Errorf("remove consumer socket: %w", err)
	}
	return nil
}

func (parent *parentHandle) close() error {
	if parent == nil || parent.fd < 0 {
		return nil
	}
	fd := parent.fd
	parent.fd = -1
	return unix.Close(fd)
}
