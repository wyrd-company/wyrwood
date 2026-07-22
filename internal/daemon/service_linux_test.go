//go:build linux

// ---
// relationships:
//   verifies: linux-per-user-agent-proxy
//   verifies: control-interface
// ---

package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/control"
	"github.com/wyrd-company/wyrwood/internal/events"
	"golang.org/x/crypto/ssh/agent"
)

func TestDaemonRestoresListenersDuringUpstreamOutageAndShutsDownEveryResource(t *testing.T) {
	fixture := newFixture(t)
	firstSocket := filepath.Join(fixture.root, "first", "agent.sock")
	fixture.writeConfig(firstSocket)

	service, err := Open(fixture.options)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	restored, err := net.DialTimeout("unix", firstSocket, time.Second)
	if err != nil {
		t.Fatalf("configured listener was not restored: %v", err)
	}
	_ = restored.Close()
	client, _ := control.NewClient(fixture.options.ControlPath)
	status, err := client.Status()
	if err != nil {
		t.Fatalf("Status(): %v", err)
	}
	if status.Daemon != control.HealthHealthy || status.Upstream != control.HealthUnavailable || len(status.Consumers) != 1 {
		t.Fatalf("status during outage = %#v", status)
	}
	if _, err := client.Keys(); !remoteCode(err, control.ErrorUpstreamUnavailable) {
		t.Fatalf("Keys() error = %v, want upstream-unavailable", err)
	}
	controlConnection, err := net.Dial("unix", fixture.options.ControlPath)
	if err != nil {
		t.Fatalf("dial control: %v", err)
	}
	consumerConnection, err := net.Dial("unix", firstSocket)
	if err != nil {
		t.Fatalf("dial consumer: %v", err)
	}

	if err := service.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	assertConnectionClosed(t, controlConnection)
	assertConnectionClosed(t, consumerConnection)
	for _, path := range []string{fixture.options.ControlPath, firstSocket} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("socket %s remained after shutdown: %v", path, err)
		}
	}
	store, err := events.Open(fixture.options.EventPath, fixture.options.EventRetention)
	if err != nil {
		t.Fatalf("event writer lock remained held: %v", err)
	}
	_ = store.Close()
}

func TestControlApplyIsAtomicAcrossInvalidPreparationAndSuccess(t *testing.T) {
	fixture := newFixture(t)
	firstSocket := filepath.Join(fixture.root, "first", "agent.sock")
	secondSocket := filepath.Join(fixture.root, "second", "agent.sock")
	fixture.writeConfig(firstSocket)
	service, err := Open(fixture.options)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer service.Close()
	client, _ := control.NewClient(fixture.options.ControlPath)

	if err := os.WriteFile(fixture.options.ConfigPath, []byte("unexpected: true\n"), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}
	if _, err := client.Apply(); !remoteCode(err, control.ErrorApplyInvalid) {
		t.Fatalf("invalid Apply() error = %v", err)
	}
	assertOnlyConsumer(t, client, "first")
	fixture.writeConfig(firstSocket)
	if err := os.Chmod(fixture.options.ConfigPath, 0o644); err != nil {
		t.Fatalf("make config insecure: %v", err)
	}
	if _, err := client.Apply(); !remoteCode(err, control.ErrorApplyInvalid) {
		t.Fatalf("insecure Apply() error = %v", err)
	}
	assertOnlyConsumer(t, client, "first")
	if err := os.Chmod(fixture.options.ConfigPath, 0o600); err != nil {
		t.Fatalf("restore config mode: %v", err)
	}

	if err := os.Mkdir(filepath.Dir(secondSocket), 0o700); err != nil {
		t.Fatalf("create second parent: %v", err)
	}
	if err := os.WriteFile(secondSocket, []byte("occupied"), 0o600); err != nil {
		t.Fatalf("occupy second path: %v", err)
	}
	fixture.writeConfig(firstSocket, secondSocket)
	if _, err := client.Apply(); !remoteCode(err, control.ErrorApplyFailed) {
		t.Fatalf("pre-commit Apply() error = %v", err)
	}
	assertOnlyConsumer(t, client, "first")
	active, err := net.DialTimeout("unix", firstSocket, time.Second)
	if err != nil {
		t.Fatalf("active listener changed after failed apply: %v", err)
	}
	_ = active.Close()

	if err := os.Remove(secondSocket); err != nil {
		t.Fatalf("remove occupied path: %v", err)
	}
	result, err := client.Apply()
	if err != nil {
		t.Fatalf("successful Apply(): %v", err)
	}
	if !result.Committed {
		t.Fatalf("Apply() = %#v", result)
	}
	status, err := client.Status()
	if err != nil || len(status.Consumers) != 2 {
		t.Fatalf("status after apply = %#v, %v", status, err)
	}
	data, err := os.ReadFile(fixture.options.ConfigPath)
	if err != nil {
		t.Fatalf("read applied config: %v", err)
	}
	updated := strings.Replace(string(data), "name: first", "name: renamed", 1)
	if err := os.WriteFile(fixture.options.ConfigPath, []byte(updated), 0o600); err != nil {
		t.Fatalf("write renamed config: %v", err)
	}
	if _, err := client.Apply(); err != nil {
		t.Fatalf("policy-only Apply(): %v", err)
	}
	status, err = client.Status()
	foundRenamed := false
	for _, consumer := range status.Consumers {
		foundRenamed = foundRenamed || consumer.Name == "renamed"
	}
	if err != nil || !foundRenamed {
		t.Fatalf("status did not use active snapshot display data: %#v, %v", status, err)
	}
}

func TestControlKeysAndEventsReturnOnlyBoundedSelectionAndEventProjections(t *testing.T) {
	fixture := newFixture(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(): %v", err)
	}
	upstream := startUpstream(t, fixture.upstreamPath, privateKey, strings.Repeat("display-", 80))
	defer upstream.close(t)
	consumerSocket := filepath.Join(fixture.root, "first", "agent.sock")
	fixture.writeConfig(consumerSocket)
	service, err := Open(fixture.options)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer service.Close()
	client, _ := control.NewClient(fixture.options.ControlPath)

	keys, err := client.Keys()
	if err != nil {
		t.Fatalf("Keys(): %v", err)
	}
	if len(keys.Keys) != 1 || !strings.HasPrefix(keys.Keys[0].Fingerprint, "SHA256:") || len(keys.Keys[0].Display) > control.MaximumDisplayBytes {
		t.Fatalf("keys = %#v", keys)
	}
	result, err := client.Events(control.MaximumEventLimit)
	if err != nil {
		t.Fatalf("Events(): %v", err)
	}
	if len(result.Events) == 0 {
		t.Fatal("startup reconciliation event was not projected")
	}
	for _, event := range result.Events {
		if strings.Contains(event.ConsumerID, fixture.root) || event.LatencyNS < 0 {
			t.Fatalf("sensitive or invalid event projection = %#v", event)
		}
	}
	if _, err := client.Events(control.MaximumEventLimit + 1); !remoteCode(err, control.ErrorBadRequest) {
		t.Fatalf("oversized Events() error = %v", err)
	}
}

func TestDaemonRestartsAgainstDurableEventsAndRecreatedControlSocket(t *testing.T) {
	fixture := newFixture(t)
	socket := filepath.Join(fixture.root, "first", "agent.sock")
	fixture.writeConfig(socket)
	first, err := Open(fixture.options)
	if err != nil {
		t.Fatalf("first Open(): %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close(): %v", err)
	}
	second, err := Open(fixture.options)
	if err != nil {
		t.Fatalf("second Open(): %v", err)
	}
	client, _ := control.NewClient(fixture.options.ControlPath)
	if _, err := client.Status(); err != nil {
		t.Fatalf("Status() after restart: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("second Close(): %v", err)
	}
}

type fixture struct {
	t            *testing.T
	root         string
	upstreamPath string
	options      Options
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"configuration", "runtime", "state"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatalf("Mkdir(%s): %v", name, err)
		}
	}
	return fixture{
		t:            t,
		root:         root,
		upstreamPath: filepath.Join(root, "upstream", "agent.sock"),
		options: Options{
			ConfigPath:     filepath.Join(root, "configuration", "config.yml"),
			ControlPath:    filepath.Join(root, "runtime", "control.sock"),
			EventPath:      filepath.Join(root, "state", "events.bin"),
			EventRetention: 128,
			UID:            uint32(os.Geteuid()),
		},
	}
}

func (fixture fixture) writeConfig(sockets ...string) {
	fixture.t.Helper()
	var builder strings.Builder
	builder.WriteString("upstream: " + fixture.upstreamPath + "\nconsumers:\n")
	for index, socket := range sockets {
		name := "first"
		if index > 0 {
			name = "second"
		}
		builder.WriteString("  - name: " + name + "\n    socket: " + socket + "\n    fingerprints:\n      - " + testFingerprint(byte(index+1)) + "\n")
	}
	builder.WriteString("timeouts:\n  connect: 100ms\n  list: 100ms\n  replay: 100ms\n  sign: 1s\n")
	if err := os.WriteFile(fixture.options.ConfigPath, []byte(builder.String()), 0o600); err != nil {
		fixture.t.Fatalf("write configuration: %v", err)
	}
}

func testFingerprint(value byte) string {
	return "SHA256:" + base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{value}), 32)))
}

func assertOnlyConsumer(t *testing.T, client *control.Client, name string) {
	t.Helper()
	status, err := client.Status()
	if err != nil {
		t.Fatalf("Status(): %v", err)
	}
	if len(status.Consumers) != 1 || status.Consumers[0].Name != name {
		t.Fatalf("active consumers = %#v", status.Consumers)
	}
}

func remoteCode(err error, code control.ErrorCode) bool {
	var remote *control.RemoteError
	return errors.As(err, &remote) && remote.Code == code
}

func assertConnectionClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection remained open")
	}
}

type upstreamServer struct {
	listener    *net.UnixListener
	done        chan struct{}
	mu          sync.Mutex
	connections []net.Conn
}

func startUpstream(t *testing.T, path string, privateKey ed25519.PrivateKey, comment string) *upstreamServer {
	t.Helper()
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create upstream directory: %v", err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix(): %v", err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey, Comment: comment}); err != nil {
		t.Fatalf("Add(): %v", err)
	}
	server := &upstreamServer{listener: listener, done: make(chan struct{})}
	go func() {
		defer close(server.done)
		for {
			connection, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			server.mu.Lock()
			server.connections = append(server.connections, connection)
			server.mu.Unlock()
			go func() { _ = agent.ServeAgent(keyring, connection); _ = connection.Close() }()
		}
	}()
	return server
}

func (server *upstreamServer) close(t *testing.T) {
	t.Helper()
	_ = server.listener.Close()
	server.mu.Lock()
	for _, connection := range server.connections {
		_ = connection.Close()
	}
	server.mu.Unlock()
	select {
	case <-server.done:
	case <-time.After(time.Second):
		t.Fatal("upstream server did not stop")
	}
}
