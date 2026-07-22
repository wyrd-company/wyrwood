//go:build linux

// ---
// relationships:
//   implements: control-interface
// ---

package control

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	controlIOTimeout     = 5 * time.Second
	initialAcceptBackoff = 5 * time.Millisecond
	maximumAcceptBackoff = 100 * time.Millisecond
)

var ErrAlreadyRunning = errors.New("control listener is already active")

type peerCredential func(*net.UnixConn) (uint32, error)

// Server owns the only local control listener and all accepted peers.
type Server struct {
	listener *net.UnixListener
	path     string
	device   uint64
	inode    uint64
	uid      uint32
	handler  Handler
	peerUID  peerCredential

	mu          sync.Mutex
	connections map[*net.UnixConn]struct{}
	closed      bool
	wg          sync.WaitGroup
}

// Listen binds an owner-only Unix control socket and authenticates every peer
// with kernel credentials against uid. It never creates a network listener.
func Listen(path string, uid uint32, handler Handler) (*Server, error) {
	return listenWithPeerCredential(path, uid, handler, kernelPeerUID)
}

func listenWithPeerCredential(path string, uid uint32, handler Handler, peerUID peerCredential) (*Server, error) {
	if handler == nil || peerUID == nil {
		return nil, errors.New("control server dependencies are incomplete")
	}
	if strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) == string(filepath.Separator) {
		return nil, errors.New("control socket path must be canonical, absolute, and use a dedicated directory")
	}
	if err := ensureControlDirectory(filepath.Dir(path), uid); err != nil {
		return nil, err
	}
	if err := removeStaleControlSocket(path, uid); err != nil {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, errors.New("bind control listener")
	}
	listener.SetUnlinkOnClose(false)
	cleanup := func() {
		_ = listener.Close()
		_ = os.Remove(path)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		cleanup()
		return nil, errors.New("secure control listener")
	}
	info, err := os.Lstat(path)
	if err != nil {
		cleanup()
		return nil, errors.New("inspect control listener")
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status.Uid != uid || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSocket == 0 {
		cleanup()
		return nil, errors.New("control listener ownership or mode verification failed")
	}
	server := &Server{
		listener: listener, path: path, device: uint64(status.Dev), inode: status.Ino,
		uid: uid, handler: handler, peerUID: peerUID, connections: make(map[*net.UnixConn]struct{}),
	}
	server.wg.Add(1)
	go server.accept()
	return server, nil
}

func (server *Server) accept() {
	defer server.wg.Done()
	backoff := time.Duration(0)
	for {
		connection, err := server.listener.AcceptUnix()
		if err != nil {
			server.mu.Lock()
			closed := server.closed
			server.mu.Unlock()
			if closed {
				return
			}
			if backoff == 0 {
				backoff = initialAcceptBackoff
			} else {
				backoff = min(backoff*2, maximumAcceptBackoff)
			}
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		uid, err := server.peerUID(connection)
		if err != nil || uid != server.uid || !server.track(connection) {
			_ = connection.Close()
			continue
		}
		server.wg.Add(1)
		go server.serve(connection)
	}
}

func (server *Server) track(connection *net.UnixConn) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.closed || len(server.connections) >= MaximumConcurrentPeers {
		return false
	}
	server.connections[connection] = struct{}{}
	return true
}

func (server *Server) serve(connection *net.UnixConn) {
	defer server.wg.Done()
	defer func() {
		server.mu.Lock()
		delete(server.connections, connection)
		server.mu.Unlock()
		_ = connection.Close()
	}()
	_ = connection.SetReadDeadline(time.Now().Add(controlIOTimeout))
	var request Request
	if err := readJSONFrame(connection, MaximumRequestBytes, &request); err != nil {
		_ = connection.SetWriteDeadline(time.Now().Add(controlIOTimeout))
		_ = writeResponse(connection, Response{Version: Version, Error: ErrorBadRequest})
		return
	}
	_ = connection.SetReadDeadline(time.Time{})
	response := dispatch(server.handler, request)
	_ = connection.SetWriteDeadline(time.Now().Add(controlIOTimeout))
	_ = writeResponse(connection, response)
}

func writeResponse(writer io.Writer, response Response) error {
	frame, err := encodeJSONFrame(MaximumResponseBytes, response)
	if err != nil {
		code := ErrorInternal
		if errors.Is(err, errEncodedFrameTooLarge) {
			code = ErrorResourceLimit
		}
		frame, err = encodeJSONFrame(MaximumResponseBytes, Response{Version: Version, Error: code})
		if err != nil {
			return err
		}
	}
	return writeEncodedFrame(writer, frame)
}

// Close stops accepting, closes every connected client, removes only the
// socket inode created by this server, and waits for all server goroutines.
func (server *Server) Close() error {
	server.mu.Lock()
	if server.closed {
		server.mu.Unlock()
		return nil
	}
	server.closed = true
	_ = server.listener.Close()
	for connection := range server.connections {
		_ = connection.Close()
	}
	server.mu.Unlock()
	server.wg.Wait()

	info, err := os.Lstat(server.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("inspect control listener during shutdown")
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(status.Dev) != server.device || status.Ino != server.inode || info.Mode()&os.ModeSocket == 0 {
		return errors.New("control listener path no longer identifies the owned socket")
	}
	if err := os.Remove(server.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("remove control listener")
	}
	return syncControlDirectory(filepath.Dir(server.path))
}

func kernelPeerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if socketErr != nil || credential == nil {
		return 0, errors.New("read peer credentials")
	}
	return credential.Uid, nil
}

func ensureControlDirectory(path string, uid uint32) error {
	info, err := os.Lstat(path)
	created := false
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return errors.New("create control directory")
		} else if err == nil {
			created = true
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return errors.New("inspect control directory")
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status.Uid != uid || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("control directory must be a real directory owned by the daemon user")
	}
	if created {
		if err := os.Chmod(path, 0o700); err != nil {
			return errors.New("secure control directory")
		}
		info, err = os.Lstat(path)
		if err != nil {
			return errors.New("verify control directory")
		}
	}
	if info.Mode().Perm() != 0o700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("existing control directory must already have mode 0700")
	}
	return nil
}

func removeStaleControlSocket(path string, uid uint32) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("inspect existing control path")
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status.Uid != uid || info.Mode()&os.ModeSocket == 0 {
		return errors.New("existing control path is not an owned socket")
	}
	connection, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
	if dialErr == nil {
		_ = connection.Close()
		return ErrAlreadyRunning
	}
	if !errors.Is(dialErr, unix.ECONNREFUSED) {
		return fmt.Errorf("existing control socket is not safely stale: %w", dialErr)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("remove stale control socket")
	}
	return syncControlDirectory(filepath.Dir(path))
}

func syncControlDirectory(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("open control directory for sync")
	}
	return errors.Join(unix.Fsync(fd), unix.Close(fd))
}
