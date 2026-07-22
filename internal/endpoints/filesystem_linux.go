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

type fileMetadata struct {
	identity fileIdentity
	mode     uint32
	owner    uint32
	group    uint32
}

type metadataChange struct {
	parentPath string
	parent     fileMetadata
	socketPath string
	socket     *fileMetadata
}

type stagedSocket struct {
	path         string
	consumer     runtime.Consumer
	listener     *net.UnixListener
	identity     fileIdentity
	parentChange *metadataChange
}

func prepareSocket(consumer runtime.Consumer) (*stagedSocket, error) {
	if len(consumer.Socket()) > maximumUnixSocketPathBytes {
		return nil, fmt.Errorf("consumer socket path exceeds Linux AF_UNIX pathname limit")
	}
	directoryMode, socketMode, group := desiredPermissions(consumer)
	if err := validateAccessGroup(group); err != nil {
		return nil, err
	}
	directory := filepath.Dir(consumer.Socket())
	directoryFD, original, created, err := openConsumerDirectory(directory)
	if err != nil {
		return nil, err
	}
	defer unix.Close(directoryFD)

	change := &metadataChange{parentPath: directory, parent: original}
	if created {
		change = nil
	}
	if err := applyDirectoryPermissions(directoryFD, directoryMode, group); err != nil {
		if change != nil {
			return nil, errors.Join(err, change.rollback())
		}
		_ = unix.Fchmod(directoryFD, 0o700)
		return nil, err
	}

	name := filepath.Base(consumer.Socket())
	if err := removeStaleOwnedSocket(directoryFD, name, consumer.Socket()); err != nil {
		if change != nil {
			err = errors.Join(err, change.rollback())
		}
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: consumer.Socket(), Net: "unix"})
	if err != nil {
		if change != nil {
			err = errors.Join(err, change.rollback())
		}
		return nil, fmt.Errorf("bind consumer listener: %w", err)
	}
	listener.SetUnlinkOnClose(false)

	identity, err := secureSocket(directoryFD, name, socketMode, group)
	if err != nil {
		candidate := &stagedSocket{
			path:         consumer.Socket(),
			consumer:     consumer,
			listener:     listener,
			identity:     identity,
			parentChange: change,
		}
		if identity == (fileIdentity{}) {
			closeErr := listener.Close()
			unlinkErr := unix.Unlinkat(directoryFD, name, 0)
			if change != nil {
				unlinkErr = errors.Join(unlinkErr, change.rollback())
			}
			return nil, errors.Join(err, closeErr, unlinkErr)
		}
		return candidate, err
	}
	return &stagedSocket{
		path:         consumer.Socket(),
		consumer:     consumer,
		listener:     listener,
		identity:     identity,
		parentChange: change,
	}, nil
}

func prepareActiveSocket(consumer runtime.Consumer, expected fileIdentity) (*metadataChange, error) {
	if len(consumer.Socket()) > maximumUnixSocketPathBytes {
		return nil, fmt.Errorf("consumer socket path exceeds Linux AF_UNIX pathname limit")
	}
	directoryMode, socketMode, group := desiredPermissions(consumer)
	if err := validateAccessGroup(group); err != nil {
		return nil, err
	}
	directory := filepath.Dir(consumer.Socket())
	directoryFD, parent, created, err := openConsumerDirectory(directory)
	if err != nil {
		return nil, err
	}
	defer unix.Close(directoryFD)
	if created {
		return nil, errors.New("active consumer parent directory was absent")
	}

	name := filepath.Base(consumer.Socket())
	socket, err := statAt(directoryFD, name)
	if err != nil {
		return nil, fmt.Errorf("inspect active consumer socket: %w", err)
	}
	if socket.mode&unix.S_IFMT != unix.S_IFSOCK || socket.identity != expected || metadataOwner(socket) != uint32(os.Geteuid()) {
		return nil, errors.New("active consumer socket identity or ownership changed")
	}

	change := &metadataChange{
		parentPath: directory,
		parent:     parent,
		socketPath: consumer.Socket(),
		socket:     &socket,
	}
	if err := applyDirectoryPermissions(directoryFD, directoryMode, group); err != nil {
		return nil, errors.Join(err, change.rollback())
	}
	if err := applyAtPermissions(directoryFD, name, socketMode, group); err != nil {
		return nil, errors.Join(err, change.rollback())
	}
	return change, nil
}

func desiredPermissions(consumer runtime.Consumer) (directoryMode uint32, socketMode uint32, group *uint32) {
	if accessGroup, exists := consumer.AccessGroup(); exists {
		return 0o710, 0o660, &accessGroup
	}
	return 0o700, 0o600, nil
}

func validateAccessGroup(group *uint32) error {
	if group == nil || *group == uint32(os.Getegid()) {
		return nil
	}
	groups, err := os.Getgroups()
	if err != nil {
		return fmt.Errorf("inspect daemon access groups: %w", err)
	}
	for _, candidate := range groups {
		if candidate >= 0 && uint32(candidate) == *group {
			return nil
		}
	}
	return errors.New("daemon user is not a member of the configured access group")
}

func openConsumerDirectory(path string) (int, fileMetadata, bool, error) {
	parent := filepath.Dir(path)
	name := filepath.Base(path)
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fileMetadata{}, false, fmt.Errorf("open consumer parent ancestor: %w", err)
	}
	defer unix.Close(parentFD)

	created := false
	if err := unix.Mkdirat(parentFD, name, 0o700); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return -1, fileMetadata{}, false, fmt.Errorf("create consumer parent: %w", err)
		}
	} else {
		created = true
	}
	directoryFD, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fileMetadata{}, created, fmt.Errorf("open consumer parent: %w", err)
	}
	metadata, err := statFD(directoryFD)
	if err != nil {
		unix.Close(directoryFD)
		return -1, fileMetadata{}, created, fmt.Errorf("inspect consumer parent: %w", err)
	}
	if metadata.mode&unix.S_IFMT != unix.S_IFDIR {
		unix.Close(directoryFD)
		return -1, fileMetadata{}, created, errors.New("consumer parent is not a directory")
	}
	if metadataOwner(metadata) != uint32(os.Geteuid()) {
		unix.Close(directoryFD)
		return -1, fileMetadata{}, created, errors.New("consumer parent is not owned by the daemon user")
	}
	return directoryFD, metadata, created, nil
}

func applyDirectoryPermissions(directoryFD int, mode uint32, group *uint32) error {
	if group != nil {
		if err := unix.Fchown(directoryFD, -1, int(*group)); err != nil {
			return fmt.Errorf("assign consumer parent group: %w", err)
		}
	}
	if err := unix.Fchmod(directoryFD, mode); err != nil {
		return fmt.Errorf("set consumer parent mode: %w", err)
	}
	metadata, err := statFD(directoryFD)
	if err != nil {
		return fmt.Errorf("verify consumer parent permissions: %w", err)
	}
	if metadata.mode&0o7777 != mode {
		return errors.New("consumer parent mode did not apply exactly")
	}
	if group != nil && metadata.group != *group {
		return errors.New("consumer parent group did not apply exactly")
	}
	return nil
}

func secureSocket(directoryFD int, name string, mode uint32, group *uint32) (fileIdentity, error) {
	metadata, err := statAt(directoryFD, name)
	if err != nil {
		return fileIdentity{}, fmt.Errorf("inspect bound consumer socket: %w", err)
	}
	if metadata.mode&unix.S_IFMT != unix.S_IFSOCK || metadataOwner(metadata) != uint32(os.Geteuid()) {
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

func applyAtPermissions(directoryFD int, name string, mode uint32, group *uint32) error {
	groupID := -1
	if group != nil {
		groupID = int(*group)
	}
	if group != nil {
		if err := unix.Fchownat(directoryFD, name, -1, groupID, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("assign consumer socket group: %w", err)
		}
	}
	if err := unix.Fchmodat(directoryFD, name, mode, 0); err != nil {
		return fmt.Errorf("set consumer socket mode: %w", err)
	}
	metadata, err := statAt(directoryFD, name)
	if err != nil {
		return fmt.Errorf("verify consumer socket permissions: %w", err)
	}
	if metadata.mode&0o7777 != mode {
		return errors.New("consumer socket mode did not apply exactly")
	}
	if group != nil && metadata.group != *group {
		return errors.New("consumer socket group did not apply exactly")
	}
	return nil
}

func removeStaleOwnedSocket(directoryFD int, name, path string) error {
	metadata, err := statAt(directoryFD, name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing consumer socket path: %w", err)
	}
	if metadata.mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("consumer socket path contains a non-socket entry")
	}
	if metadataOwner(metadata) != uint32(os.Geteuid()) {
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
	if err := unix.Unlinkat(directoryFD, name, 0); err != nil {
		return fmt.Errorf("remove stale consumer socket: %w", err)
	}
	return nil
}

func removeSocket(path string, expected fileIdentity) error {
	directoryFD, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open consumer parent for cleanup: %w", err)
	}
	defer unix.Close(directoryFD)
	name := filepath.Base(path)
	metadata, err := statAt(directoryFD, name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect consumer socket for cleanup: %w", err)
	}
	if metadata.identity != expected {
		return nil
	}
	if metadata.mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("owned consumer socket was replaced by a non-socket entry")
	}
	if err := unix.Unlinkat(directoryFD, name, 0); err != nil {
		return fmt.Errorf("remove consumer socket: %w", err)
	}
	return nil
}

func (change *metadataChange) rollback() error {
	if change == nil {
		return nil
	}
	directoryFD, err := unix.Open(change.parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open consumer parent for metadata rollback: %w", err)
	}
	defer unix.Close(directoryFD)
	currentParent, err := statFD(directoryFD)
	if err != nil {
		return fmt.Errorf("inspect consumer parent for metadata rollback: %w", err)
	}
	if currentParent.identity != change.parent.identity {
		return errors.New("consumer parent identity changed before metadata rollback")
	}
	var result error
	if change.socket != nil {
		name := filepath.Base(change.socketPath)
		current, statErr := statAt(directoryFD, name)
		if statErr != nil {
			result = errors.Join(result, fmt.Errorf("inspect consumer socket for metadata rollback: %w", statErr))
		} else if current.identity != change.socket.identity {
			result = errors.Join(result, errors.New("consumer socket identity changed before metadata rollback"))
		} else {
			if current.group != change.socket.group {
				if err := unix.Fchownat(directoryFD, name, -1, int(change.socket.group), unix.AT_SYMLINK_NOFOLLOW); err != nil {
					result = errors.Join(result, fmt.Errorf("restore consumer socket group: %w", err))
				}
			}
			if current.mode&0o7777 != change.socket.mode&0o7777 {
				if err := unix.Fchmodat(directoryFD, name, change.socket.mode&0o7777, 0); err != nil {
					result = errors.Join(result, fmt.Errorf("restore consumer socket mode: %w", err))
				}
			}
		}
	}
	if currentParent.group != change.parent.group {
		if err := unix.Fchown(directoryFD, -1, int(change.parent.group)); err != nil {
			result = errors.Join(result, fmt.Errorf("restore consumer parent group: %w", err))
		}
	}
	if currentParent.mode&0o7777 != change.parent.mode&0o7777 {
		if err := unix.Fchmod(directoryFD, change.parent.mode&0o7777); err != nil {
			result = errors.Join(result, fmt.Errorf("restore consumer parent mode: %w", err))
		}
	}
	return result
}

func statFD(fd int) (fileMetadata, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fileMetadata{}, err
	}
	return metadataFromStat(stat), nil
}

func statAt(directoryFD int, name string) (fileMetadata, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fileMetadata{}, err
	}
	return metadataFromStat(stat), nil
}

func metadataFromStat(stat unix.Stat_t) fileMetadata {
	return fileMetadata{
		identity: fileIdentity{device: uint64(stat.Dev), inode: stat.Ino},
		mode:     stat.Mode,
		owner:    stat.Uid,
		group:    stat.Gid,
	}
}

func metadataOwner(metadata fileMetadata) uint32 {
	return metadata.owner
}
