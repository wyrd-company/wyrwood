// ---
// relationships:
//   implements: agent
//   mitigates: agent-compromise-exposes-host-container-secrets
// ---

// Package consumer owns per-container consumer directories. A directory is
// the security principal for a bound container: it is created with
// access-group modes, its sockets are replaced in place through a pinned
// directory handle, and it is never itself replaced while mounted.
package consumer

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// Socket names inside a consumer directory.
const (
	VaultSocket    = "vault.sock"
	SSHAgentSocket = "ssh-agent.sock"
)

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)

// ValidName reports whether a container name is usable as a directory name.
func ValidName(name string) bool { return namePattern.MatchString(name) && name != "." && name != ".." }

// Root is the consumer root directory.
type Root struct {
	path string
}

// OpenRoot creates the consumer root when absent. It must be a real
// directory owned by the agent user.
func OpenRoot(path string) (*Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("consumer root must be canonical and absolute")
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, fmt.Errorf("create consumer root: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("consumer root must be a real directory")
	}
	if err := requireOwner(info); err != nil {
		return nil, err
	}
	return &Root{path: path}, nil
}

// Path returns the root path.
func (root *Root) Path() string { return root.path }

// DirectoryPath returns the consumer directory path for a container name.
func (root *Root) DirectoryPath(name string) string { return filepath.Join(root.path, name) }

// Directory is one open consumer directory.
type Directory struct {
	name   string
	path   string
	group  *uint32
	mu     sync.Mutex
	fd     int
	closed bool
}

// Open creates or adopts the consumer directory for name with modes for the
// access group: 0750 with the group, or 0700 without one. The directory is
// pinned by a handle for every later socket operation.
func (root *Root) Open(name string, group *uint32) (*Directory, error) {
	if !ValidName(name) {
		return nil, errors.New("container name is not a valid directory name")
	}
	rootFD, err := unix.Open(root.path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open consumer root: %w", err)
	}
	defer unix.Close(rootFD)
	if err := unix.Mkdirat(rootFD, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("create consumer directory: %w", err)
	}
	fd, err := unix.Openat(rootFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open consumer directory: %w", err)
	}
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil || status.Uid != uint32(os.Geteuid()) {
		_ = unix.Close(fd)
		return nil, errors.New("consumer directory is not owned by the agent user")
	}
	directory := &Directory{name: name, path: root.DirectoryPath(name), fd: fd}
	if err := directory.SetGroup(group); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return directory, nil
}

// Name returns the container name the directory belongs to.
func (directory *Directory) Name() string { return directory.name }

// Path returns the directory path, used as the mount source.
func (directory *Directory) Path() string { return directory.path }

// SetGroup applies directory and socket modes for an access group.
func (directory *Directory) SetGroup(group *uint32) error {
	directory.mu.Lock()
	defer directory.mu.Unlock()
	if directory.closed {
		return errors.New("consumer directory is closed")
	}
	gid, mode, socketMode := -1, uint32(0o700), uint32(0o600)
	if group != nil {
		gid, mode, socketMode = int(*group), 0o750, 0o660
	} else {
		gid = os.Getegid()
	}
	if err := unix.Fchown(directory.fd, -1, gid); err != nil {
		return fmt.Errorf("assign consumer directory group: %w", err)
	}
	if err := unix.Fchmod(directory.fd, mode); err != nil {
		return fmt.Errorf("set consumer directory mode: %w", err)
	}
	for _, name := range []string{VaultSocket, SSHAgentSocket} {
		if err := unix.Fchownat(directory.fd, name, -1, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("assign socket group: %w", err)
		}
		if err := fchmodSocket(directory.fd, name, socketMode); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("set socket mode: %w", err)
		}
	}
	directory.group = group
	return nil
}

func fchmodSocket(directoryFD int, name string, mode uint32) error {
	var status unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &status, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if status.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("not a socket")
	}
	return unix.Fchmodat(directoryFD, name, mode, 0)
}

// Listen replaces the named socket inside the directory and returns its
// listener. Binding goes through the pinned handle, so a rename of the
// directory path cannot redirect it.
func (directory *Directory) Listen(name string) (*net.UnixListener, error) {
	if name != VaultSocket && name != SSHAgentSocket {
		return nil, errors.New("unknown socket name")
	}
	directory.mu.Lock()
	defer directory.mu.Unlock()
	if directory.closed {
		return nil, errors.New("consumer directory is closed")
	}
	if err := unlinkSocket(directory.fd, name); err != nil {
		return nil, err
	}
	address := "/proc/self/fd/" + strconv.Itoa(directory.fd) + "/" + name
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: address, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("bind socket: %w", err)
	}
	listener.SetUnlinkOnClose(false)
	gid, mode := os.Getegid(), uint32(0o600)
	if directory.group != nil {
		gid, mode = int(*directory.group), 0o660
	}
	if err := unix.Fchownat(directory.fd, name, -1, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("assign socket group: %w", err)
	}
	if err := fchmodSocket(directory.fd, name, mode); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("set socket mode: %w", err)
	}
	return listener, nil
}

func unlinkSocket(directoryFD int, name string) error {
	var status unix.Stat_t
	err := unix.Fstatat(directoryFD, name, &status, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if status.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("a non-socket occupies the socket path")
	}
	if err := unix.Unlinkat(directoryFD, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

// Remove unlinks the sockets through the pinned handle, then removes the
// directory from the root if it is still that same directory and empty.
func (directory *Directory) Remove(root *Root) error {
	directory.mu.Lock()
	defer directory.mu.Unlock()
	if directory.closed {
		return nil
	}
	var result error
	for _, name := range []string{VaultSocket, SSHAgentSocket} {
		result = errors.Join(result, unlinkSocket(directory.fd, name))
	}
	var pinned unix.Stat_t
	if err := unix.Fstat(directory.fd, &pinned); err == nil {
		rootFD, err := unix.Open(root.path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == nil {
			var current unix.Stat_t
			if unix.Fstatat(rootFD, directory.name, &current, unix.AT_SYMLINK_NOFOLLOW) == nil &&
				current.Ino == pinned.Ino && current.Dev == pinned.Dev {
				if err := unix.Unlinkat(rootFD, directory.name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
					result = errors.Join(result, err)
				}
			}
			_ = unix.Close(rootFD)
		}
	}
	directory.closed = true
	result = errors.Join(result, unix.Close(directory.fd))
	return result
}

// Close releases the pinned handle and leaves the directory in place.
func (directory *Directory) Close() error {
	directory.mu.Lock()
	defer directory.mu.Unlock()
	if directory.closed {
		return nil
	}
	directory.closed = true
	return unix.Close(directory.fd)
}

// CanAssign reports whether the agent user can assign gid to its files.
func CanAssign(gid uint32) bool {
	if os.Geteuid() == 0 || uint32(os.Getegid()) == gid {
		return true
	}
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	for _, group := range groups {
		if uint32(group) == gid {
			return true
		}
	}
	return false
}

func requireOwner(info os.FileInfo) error {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status.Uid != uint32(os.Geteuid()) {
		return errors.New("consumer root is not owned by the agent user")
	}
	return nil
}
