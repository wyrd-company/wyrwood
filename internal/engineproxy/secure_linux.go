// ---
// relationships:
//   implements: engine-proxy
// ---

package engineproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/wyrd-company/wyrwood/internal/config"
	"golang.org/x/sys/unix"
)

// ErrBoundary is categorical: paths, account data, and OS errors stay private.
var ErrBoundary = errors.New("engine proxy security boundary unavailable")

// openTrusted traverses only root-controlled directories through pinned handles.
// Root-owned symlinks are resolved with the same checks on their target chain.
func openTrusted(path string, directory bool, depth int) (*os.File, error) {
	if !filepath.IsAbs(path) || depth > 40 {
		return nil, ErrBoundary
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrBoundary
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if path == "/" {
		parts = nil
	}
	parent := "/"
	for index, part := range parts {
		if part == "" || part == "." {
			continue
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 {
			return nil, ErrBoundary
		}
		var entry unix.Stat_t
		if unix.Fstatat(fd, part, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil {
			return nil, ErrBoundary
		}
		if entry.Mode&unix.S_IFMT == unix.S_IFLNK {
			if entry.Uid != 0 {
				return nil, ErrBoundary
			}
			target := make([]byte, 4096)
			count, err := unix.Readlinkat(fd, part, target)
			if err != nil || count == len(target) {
				return nil, ErrBoundary
			}
			resolved := string(target[:count])
			if !filepath.IsAbs(resolved) {
				resolved = parent + "/" + resolved
			}
			return openTrusted(strings.Join(append([]string{resolved}, parts[index+1:]...), "/"), directory, depth+1)
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if index < len(parts)-1 || directory {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, part, flags, 0)
		if err != nil {
			return nil, ErrBoundary
		}
		_ = unix.Close(fd)
		fd = next
		parent += "/" + part
	}
	var final unix.Stat_t
	if unix.Fstat(fd, &final) != nil || final.Uid != 0 || final.Mode&0022 != 0 {
		return nil, ErrBoundary
	}
	file := os.NewFile(uintptr(fd), path)
	fd = -1
	return file, nil
}

// LoadConfiguration reads the same verified file handle whose owner is checked.
func LoadConfiguration(path string) (config.Agent, error) {
	file, err := openTrusted(path, false, 0)
	if err != nil {
		return config.Agent{}, ErrBoundary
	}
	defer file.Close()
	var st unix.Stat_t
	if unix.Fstat(int(file.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return config.Agent{}, ErrBoundary
	}
	data, err := io.ReadAll(io.LimitReader(file, config.MaximumDocumentBytes+1))
	if err != nil {
		return config.Agent{}, ErrBoundary
	}
	result, err := config.ParseAgent(data)
	if err != nil {
		return config.Agent{}, ErrBoundary
	}
	return result, nil
}

// CheckAgentAccess rejects inherited raw Engine authority for the service UID.
// Root remains able to run diagnostic daemons; it is outside the boundary.
func CheckAgentAccess(socket string) error {
	if os.Geteuid() == 0 {
		return nil
	}
	account, err := user.Lookup("wyrwood")
	if err != nil || account.Uid != strconv.Itoa(os.Geteuid()) {
		return ErrBoundary
	}
	groups, err := os.Getgroups()
	if err != nil {
		return ErrBoundary
	}
	dockerGID := -1
	docker, err := user.LookupGroup("docker")
	if err == nil {
		dockerGID, err = strconv.Atoi(docker.Gid)
		if err != nil {
			return ErrBoundary
		}
	} else {
		if _, missing := err.(user.UnknownGroupError); !missing {
			return ErrBoundary
		}
	}
	return checkRawAccess(socket, append(groups, os.Getegid()), dockerGID)
}

func checkRawAccess(socket string, groups []int, dockerGID int) error {
	for _, group := range groups {
		if dockerGID >= 0 && group == dockerGID {
			return ErrBoundary
		}
	}
	// Effective credentials include POSIX ACLs; no daemon connection is needed.
	err := unix.Faccessat(unix.AT_FDCWD, socket, unix.W_OK, unix.AT_EACCESS)
	if err == nil {
		return ErrBoundary
	}
	if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.ENOENT) {
		return ErrBoundary
	}
	return nil
}

// Listen creates the filtered socket only in a directory the agent cannot edit.
func Listen(path string, agentUID int) (net.Listener, error) {
	directory, err := openTrusted(filepath.Dir(filepath.Dir(path)), true, 0)
	if err != nil {
		return nil, ErrBoundary
	}
	defer directory.Close()
	fd, err := unix.Openat(int(directory.Fd()), filepath.Base(filepath.Dir(path)), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrBoundary
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || int(st.Uid) != os.Geteuid() || int(st.Gid) != os.Getegid() || st.Mode&0777 != 0750 || os.Geteuid() == agentUID {
		return nil, ErrBoundary
	}
	// Pin the directory for binding and unlinking, even across root renames.
	pinned := "/proc/self/fd/" + strconv.Itoa(fd) + "/" + filepath.Base(path)
	var previous unix.Stat_t
	err = unix.Fstatat(fd, filepath.Base(path), &previous, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		if previous.Mode&unix.S_IFMT != unix.S_IFSOCK || int(previous.Uid) != os.Geteuid() {
			return nil, ErrBoundary
		}
		if unix.Unlinkat(fd, filepath.Base(path), 0) != nil {
			return nil, ErrBoundary
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return nil, ErrBoundary
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: pinned, Net: "unix"})
	if err != nil {
		return nil, ErrBoundary
	}
	listener.SetUnlinkOnClose(false)
	if unix.Fchmodat(fd, filepath.Base(path), 0660, 0) != nil {
		_ = listener.Close()
		_ = unix.Unlinkat(fd, filepath.Base(path), 0)
		return nil, ErrBoundary
	}
	// Hold a pinned handle for cleanup after the original traversal closes.
	held, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		_ = listener.Close()
		_ = unix.Unlinkat(fd, filepath.Base(path), 0)
		return nil, ErrBoundary
	}
	return &peerListener{UnixListener: listener, uid: uint32(agentUID), directory: held, name: filepath.Base(path)}, nil
}

type peerListener struct {
	*net.UnixListener
	uid       uint32
	directory int
	name      string
}

func (listener *peerListener) Accept() (net.Conn, error) {
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			return nil, err
		}
		raw, err := conn.SyscallConn()
		allowed := false
		if err == nil {
			err = raw.Control(func(fd uintptr) {
				credentials, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
				allowed = e == nil && (credentials.Uid == 0 || credentials.Uid == listener.uid)
			})
		}
		if err == nil && allowed {
			return conn, nil
		}
		_ = conn.Close()
	}
}
func (listener *peerListener) Close() error {
	err := listener.UnixListener.Close()
	if err == nil {
		_ = unix.Unlinkat(listener.directory, listener.name, 0)
		_ = unix.Close(listener.directory)
	}
	return err
}

// Run loads host-controlled permissions and runs the separate service process.
func Run(ctx context.Context, path string, output io.Writer) error {
	cfg, err := LoadConfiguration(path)
	if err != nil {
		return err
	}
	// Root-only diagnostic sessions can run before service enrollment. Normal
	// service operation requires the named agent account created by installation.
	uid := -1
	agent, err := user.Lookup("wyrwood")
	if err != nil {
		if os.Geteuid() != 0 {
			return ErrBoundary
		}
	} else {
		uid, err = strconv.Atoi(agent.Uid)
		if err != nil {
			return ErrBoundary
		}
	}
	upstream, err := filepath.EvalSymlinks(cfg.EngineSocket)
	if err != nil {
		upstream = cfg.EngineSocket
	}
	filtered, err := filepath.EvalSymlinks(cfg.EngineProxySocket)
	if err != nil {
		filtered = cfg.EngineProxySocket
	}
	if upstream == filtered {
		return ErrBoundary
	}
	listener, err := Listen(cfg.EngineProxySocket, uid)
	if err != nil {
		return err
	}
	return New(cfg.EngineSocket, cfg.AllowRecreate, output).Serve(ctx, listener)
}
