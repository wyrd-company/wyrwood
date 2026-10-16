// ---
// relationships:
//   verifies: engine-proxy
// ---

package engineproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/engine"
)

func rootFixture(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("run the engine-proxy root gate to exercise real UID and file ownership boundaries")
	}
	root, err := os.MkdirTemp("/run", "engine-boundary-")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

func TestRootConfigurationTrust(t *testing.T) {
	root := rootFixture(t)
	path := filepath.Join(root, "host.yml")
	data := []byte("controller:\n  url: ssh://controller.example\nengine:\n  allow-recreate: true\n")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfiguration(path)
	if err != nil || !cfg.AllowRecreate {
		t.Fatalf("trusted configuration = %#v %v", cfg, err)
	}
	link := filepath.Join(root, "link.yml")
	if err := os.Symlink("host.yml", link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfiguration(link); err != nil {
		t.Fatal("root controlled symlink", err)
	}
	_ = os.Lchown(link, 51001, 0)
	if _, err := LoadConfiguration(link); err == nil {
		t.Fatal("accepted foreign symlink owner")
	}
	_ = os.Lchown(link, 0, 0)
	for _, mode := range []os.FileMode{0664, 0666} {
		_ = os.Chmod(path, mode)
		if _, err := LoadConfiguration(path); err == nil {
			t.Fatalf("accepted mode %o", mode)
		}
	}
	_ = os.Chmod(path, 0644)
	_ = os.Chown(path, 51001, 0)
	if _, err := LoadConfiguration(path); err == nil {
		t.Fatal("accepted agent-owned configuration")
	}
	_ = os.Chown(path, 0, 0)
	_ = os.Chown(root, 51001, 0)
	if _, err := LoadConfiguration(path); err == nil {
		t.Fatal("accepted foreign ancestor owner")
	}
	_ = os.Chown(root, 0, 0)
	_ = os.Chmod(root, 0777)
	if _, err := LoadConfiguration(path); err == nil {
		t.Fatal("accepted writable ancestor")
	}
	_ = os.Chmod(root, 0755)
	fifo := filepath.Join(root, "fifo.yml")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	held, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	writer, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = writer.Write(data)
	_ = writer.Close()
	if _, err := LoadConfiguration(fifo); err == nil {
		t.Fatal("accepted FIFO configuration")
	}
	_ = os.WriteFile(path, []byte("unknown: true\n"), 0644)
	if _, err := LoadConfiguration(path); err == nil {
		t.Fatal("accepted malformed configuration")
	}
}

func TestRootListenerRejectsUnsafeDirectoryAndConflictingFiles(t *testing.T) {
	root := rootFixture(t)
	directory := filepath.Join(root, "proxy")
	_ = os.Mkdir(directory, 0750)
	path := filepath.Join(directory, "engine.sock")
	for _, mode := range []os.FileMode{0770, 0755} {
		_ = os.Chmod(directory, mode)
		if listener, err := Listen(path, 51001); err == nil {
			_ = listener.Close()
			t.Fatal("accepted unsafe directory mode", mode)
		}
	}
	_ = os.Chmod(directory, 0750)
	_ = os.Chown(directory, 51001, 0)
	if listener, err := Listen(path, 51002); err == nil {
		_ = listener.Close()
		t.Fatal("accepted foreign directory owner")
	}
	_ = os.Chown(directory, 0, 51001)
	if listener, err := Listen(path, 51002); err == nil {
		_ = listener.Close()
		t.Fatal("accepted foreign directory group")
	}
	_ = os.Chown(directory, 0, 0)
	_ = os.WriteFile(path, []byte("keep"), 0600)
	if listener, err := Listen(path, 51001); err == nil {
		_ = listener.Close()
		t.Fatal("removed conflicting file")
	}
	if data, _ := os.ReadFile(path); string(data) != "keep" {
		t.Fatal("conflicting file modified")
	}
	_ = os.Remove(path)
	foreign, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Chown(path, 51003, 0)
	if listener, err := Listen(path, 51001); err == nil {
		_ = listener.Close()
		t.Fatal("removed foreign socket")
	}
	_ = foreign.Close()
	listener, err := Listen(path, 51001)
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("socket not removed", err)
	}
}

func TestRootSeparateIdentities(t *testing.T) {
	root := rootFixture(t)
	const proxyUID = 51001
	const agentUID = 51002
	const sharedGID = 51003
	const engineGID = 51004
	proxyDir := filepath.Join(root, "proxy")
	_ = os.Mkdir(proxyDir, 0750)
	_ = os.Chown(proxyDir, proxyUID, sharedGID)
	raw := filepath.Join(root, "raw.sock")
	listener, err := net.Listen("unix", raw)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = os.Chown(raw, 0, engineGID)
	_ = os.Chmod(raw, 0660)
	// A real Unix HTTP upstream; the fixture owns all authority to its socket.
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = bufio.NewReader(conn).ReadString('\n')
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]")
			}()
		}
	}()
	original, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	binary := filepath.Join(root, "helper")
	target, err := os.OpenFile(binary, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(target, original)
	_ = target.Close()
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(proxyDir, "engine.sock")
	configFile := filepath.Join(root, "host.yml")
	_ = os.WriteFile(configFile, []byte("root config"), 0644)
	helper := func(action string, uid, gid uint32, groups []uint32) *exec.Cmd {
		command := exec.Command(binary, "-test.run=^TestBoundaryHelper$")
		command.Env = []string{"BOUNDARY_HELPER=" + action, "BOUNDARY_SOCKET=" + socket, "BOUNDARY_RAW=" + raw, "BOUNDARY_CONFIG=" + configFile}
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: groups}}
		return command
	}
	service := helper("serve", proxyUID, sharedGID, []uint32{engineGID})
	ready, err := service.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = service.Process.Kill(); _ = service.Wait() }()
	line, err := bufio.NewReader(ready).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("proxy startup = %q %v", line, err)
	}
	for _, sample := range []struct {
		action string
		uid    uint32
	}{{"agent", agentUID}, {"outsider", 51005}} {
		if output, err := helper(sample.action, sample.uid, sharedGID, nil).CombinedOutput(); err != nil {
			t.Fatalf("%s: %s %v", sample.action, output, err)
		}
	}
}

func TestBoundaryHelper(t *testing.T) {
	action := os.Getenv("BOUNDARY_HELPER")
	if action == "" {
		return
	}
	socket := os.Getenv("BOUNDARY_SOCKET")
	raw := os.Getenv("BOUNDARY_RAW")
	if action == "serve" {
		listener, err := Listen(socket, 51002)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("ready")
		if err := New(raw, false, nil).Serve(context.Background(), listener); err != nil {
			t.Fatal(err)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := engine.NewClient(socket).List(ctx)
	if action == "outsider" {
		if err == nil {
			t.Fatal("other UID impersonated agent")
		}
		return
	}
	if err != nil {
		t.Fatal("agent cannot observe through proxy", err)
	}
	conn, err := net.Dial("unix", raw)
	if err == nil {
		_ = conn.Close()
		t.Fatal("agent opened raw Engine")
	}
	if err := os.Remove(socket); err == nil {
		t.Fatal("agent replaced proxy socket")
	}
	if err := os.WriteFile(os.Getenv("BOUNDARY_CONFIG"), []byte("allow-recreate: true"), 0644); err == nil {
		t.Fatal("agent modified host permission")
	}
}

func TestRawEngineAccessGuard(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.sock")
	if err := checkRawAccess(missing, []int{42}, 42); err == nil {
		t.Fatal("accepted Docker group with Engine absent")
	}
	if err := checkRawAccess(missing, []int{43}, 42); err != nil {
		t.Fatal(err)
	}
	raw := filepath.Join(t.TempDir(), "raw.sock")
	listener, err := net.Listen("unix", raw)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	parent := filepath.Join(t.TempDir(), "not-a-directory")
	_ = os.WriteFile(parent, []byte{}, 0600)
	if err := checkRawAccess(filepath.Join(parent, "raw.sock"), nil, -1); err == nil {
		t.Fatal("accepted unexpected permission-check failure")
	}
	if err := checkRawAccess(raw, nil, -1); err == nil {
		t.Fatal("accepted effective raw socket access")
	}
}

func TestRootSymlinkResolutionPreservesParentTraversal(t *testing.T) {
	root := rootFixture(t)
	if err := os.MkdirAll(filepath.Join(root, "nested/deep"), 0755); err != nil {
		t.Fatal(err)
	}
	first := []byte("controller:\n  url: ssh://controller.example\nengine:\n  allow-recreate: true\n")
	second := []byte("controller:\n  url: ssh://controller.example\nengine:\n  allow-recreate: false\n")
	_ = os.WriteFile(filepath.Join(root, "host.yml"), first, 0644)
	_ = os.WriteFile(filepath.Join(root, "nested/host.yml"), second, 0644)
	if err := os.Symlink("nested/deep", filepath.Join(root, "directory-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("directory-link/../host.yml", filepath.Join(root, "config-link")); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfiguration(filepath.Join(root, "config-link"))
	if err != nil || cfg.AllowRecreate {
		t.Fatal("symlink was cleaned before resolving its directory", cfg, err)
	}
}

func TestRootRunActivatesHostPermissionOnlyOnRestart(t *testing.T) {
	root := rootFixture(t)
	directory := filepath.Join(root, "proxy")
	_ = os.Mkdir(directory, 0750)
	socket := filepath.Join(directory, "engine.sock")
	upstream := unixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_, _ = io.WriteString(w, "[]")
		} else {
			w.WriteHeader(204)
		}
	}))
	path := filepath.Join(root, "host.yml")
	write := func(enabled bool) {
		t.Helper()
		data := fmt.Sprintf("controller:\n  url: ssh://controller.example\nengine:\n  socket: %s\n  proxy-socket: %s\n  allow-recreate: %t\n", upstream, socket, enabled)
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(false)
	start := func() (context.CancelFunc, <-chan error, *engine.Client) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Run(ctx, path, io.Discard) }()
		client := engine.NewClient(socket)
		deadline := time.After(5 * time.Second)
		for {
			select {
			case err := <-done:
				cancel()
				t.Fatal("proxy exited", err)
			case <-deadline:
				cancel()
				t.Fatal("proxy not ready")
			default:
			}
			request, stop := context.WithTimeout(ctx, 100*time.Millisecond)
			_, err := client.List(request)
			stop()
			if err == nil {
				return cancel, done, client
			}
			time.Sleep(time.Millisecond)
		}
	}
	cancel, done, client := start()
	defer cancel()
	write(true)
	// The file cannot change the permission on an existing process/connection.
	if err := client.Start(context.Background(), "sample"); err != engine.ErrUnavailable {
		t.Fatal("host permission was not independently loaded and held", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	cancel, done, client = start()
	defer cancel()
	if err := client.Start(context.Background(), "sample"); err != nil {
		t.Fatal("restart did not activate host permission", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
