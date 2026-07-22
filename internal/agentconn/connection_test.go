// ---
// relationships:
//   verifies: linux-per-user-agent-proxy
// ---

package agentconn_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/agentconn"
	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/runtime"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const sessionBindExtension = "session-bind@openssh.com"

func TestServeReconnectsAtFixedPathAndReplaysBindingsBeforeNextRequest(t *testing.T) {
	fixture := newConnectionFixture(t)
	first := startUnixAgent(t, fixture.upstreamPath, func(int) *scriptedAgent {
		return newScriptedAgent(t, fixture.privateKey)
	})
	client, closeClient := serveDownstream(t, fixture)
	defer closeClient()

	firstBinding := sessionBinding("first")
	secondBinding := sessionBinding("second")
	for _, binding := range [][]byte{firstBinding, secondBinding} {
		if _, err := client.Extension(sessionBindExtension, binding); err != nil {
			t.Fatalf("Extension() error = %v", err)
		}
	}
	if _, err := client.List(); err != nil {
		t.Fatalf("List(before replacement) error = %v", err)
	}
	first.close(t)

	second := startUnixAgent(t, fixture.upstreamPath, func(int) *scriptedAgent {
		return newScriptedAgent(t, fixture.privateKey)
	})
	defer second.close(t)
	if _, err := client.List(); err == nil {
		t.Fatal("List(on stale stream) error = nil")
	}
	keys, err := client.List()
	if err != nil {
		t.Fatalf("List(after replacement) error = %v", err)
	}
	if len(keys) != 1 || ssh.FingerprintSHA256(keys[0]) != fixture.fingerprint {
		t.Fatalf("List(after replacement) returned %d unexpected keys", len(keys))
	}

	accepted := second.waitAccepted(t, 1)[0]
	want := []operation{
		{kind: "extension", contents: firstBinding},
		{kind: "extension", contents: secondBinding},
		{kind: "list"},
	}
	if got := accepted.agent.operations(); !operationsEqual(got, want) {
		t.Fatalf("replacement operations = %#v, want %#v", got, want)
	}
}

func TestServeKeepsDownstreamUsableWhileUpstreamIsInitiallyAbsent(t *testing.T) {
	fixture := newConnectionFixture(t)
	client, closeClient := serveDownstream(t, fixture)
	defer closeClient()

	if _, err := client.List(); err == nil {
		t.Fatal("List(without upstream) error = nil")
	}
	server := startUnixAgent(t, fixture.upstreamPath, func(int) *scriptedAgent {
		return newScriptedAgent(t, fixture.privateKey)
	})
	defer server.close(t)
	if keys, err := client.List(); err != nil {
		t.Fatalf("List(after upstream appears) error = %v", err)
	} else if len(keys) != 1 {
		t.Fatalf("len(List(after upstream appears)) = %d, want 1", len(keys))
	}
}

func TestServeDiscardsDelayedListStreamAndKeepsDownstreamUsable(t *testing.T) {
	fixture := newConnectionFixture(t)
	fixture.timeouts.List = 100 * time.Millisecond
	server := startUnixAgent(t, fixture.upstreamPath, func(index int) *scriptedAgent {
		upstream := newScriptedAgent(t, fixture.privateKey)
		if index == 0 {
			upstream.listDelay = 250 * time.Millisecond
		}
		return upstream
	})
	defer server.close(t)
	client, closeClient := serveDownstream(t, fixture)
	defer closeClient()

	started := time.Now()
	if _, err := client.List(); err == nil {
		t.Fatal("List(delayed) error = nil")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("List(delayed) elapsed = %s, want bounded failure", elapsed)
	}

	keys, err := client.List()
	if err != nil {
		t.Fatalf("List(after timeout) error = %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("len(List(after timeout)) = %d, want 1", len(keys))
	}
	accepted := server.waitAccepted(t, 2)
	accepted[0].waitDone(t)
}

func TestServeBoundsCompleteReplayAndRecoversAgain(t *testing.T) {
	fixture := newConnectionFixture(t)
	fixture.timeouts.Replay = 100 * time.Millisecond
	first := startUnixAgent(t, fixture.upstreamPath, func(int) *scriptedAgent {
		return newScriptedAgent(t, fixture.privateKey)
	})
	client, closeClient := serveDownstream(t, fixture)
	defer closeClient()

	binding := sessionBinding("accepted")
	if _, err := client.Extension(sessionBindExtension, binding); err != nil {
		t.Fatalf("Extension() error = %v", err)
	}
	first.close(t)

	second := startUnixAgent(t, fixture.upstreamPath, func(index int) *scriptedAgent {
		upstream := newScriptedAgent(t, fixture.privateKey)
		if index == 0 {
			upstream.extensionDelay = 250 * time.Millisecond
		}
		return upstream
	})
	defer second.close(t)
	if _, err := client.List(); err == nil {
		t.Fatal("List(on stale stream) error = nil")
	}
	if _, err := client.List(); err == nil {
		t.Fatal("List(after delayed replay) error = nil")
	}
	if keys, err := client.List(); err != nil {
		t.Fatalf("List(after replay recovery) error = %v", err)
	} else if len(keys) != 1 {
		t.Fatalf("len(List(after replay recovery)) = %d, want 1", len(keys))
	}

	accepted := second.waitAccepted(t, 2)
	accepted[0].waitDone(t)
	if got := accepted[0].agent.operations(); !operationsEqual(got, []operation{{kind: "extension", contents: binding}}) {
		t.Fatalf("timed-out replay operations = %#v", got)
	}
	if got := accepted[1].agent.operations(); !operationsEqual(got, []operation{
		{kind: "extension", contents: binding},
		{kind: "list"},
	}) {
		t.Fatalf("recovered replay operations = %#v", got)
	}
}

func TestServeUsesSeparateLongerSigningDeadline(t *testing.T) {
	fixture := newConnectionFixture(t)
	fixture.timeouts.List = 100 * time.Millisecond
	fixture.timeouts.Sign = time.Second
	server := startUnixAgent(t, fixture.upstreamPath, func(int) *scriptedAgent {
		upstream := newScriptedAgent(t, fixture.privateKey)
		upstream.signDelay = 200 * time.Millisecond
		return upstream
	})
	defer server.close(t)
	client, closeClient := serveDownstream(t, fixture)
	defer closeClient()

	payload := []byte("generic challenge")
	started := time.Now()
	signature, err := client.Sign(fixture.publicKey, payload)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed < 150*time.Millisecond || elapsed > 800*time.Millisecond {
		t.Fatalf("Sign() elapsed = %s, want separate signing allowance", elapsed)
	}
	if err := fixture.publicKey.Verify(payload, signature); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestServeDoesNotReplayRejectedBinding(t *testing.T) {
	fixture := newConnectionFixture(t)
	server := startUnixAgent(t, fixture.upstreamPath, func(index int) *scriptedAgent {
		upstream := newScriptedAgent(t, fixture.privateKey)
		if index == 0 {
			upstream.extensionError = errors.New("generic rejection")
		}
		return upstream
	})
	defer server.close(t)
	client, closeClient := serveDownstream(t, fixture)
	defer closeClient()

	if _, err := client.Extension(sessionBindExtension, sessionBinding("rejected")); err == nil {
		t.Fatal("Extension(rejected) error = nil")
	}
	if keys, err := client.List(); err != nil {
		t.Fatalf("List(after rejection) error = %v", err)
	} else if len(keys) != 1 {
		t.Fatalf("len(List(after rejection)) = %d, want 1", len(keys))
	}

	accepted := server.waitAccepted(t, 2)
	if got := accepted[1].agent.operations(); !operationsEqual(got, []operation{{kind: "list"}}) {
		t.Fatalf("operations after rejected binding = %#v", got)
	}
}

func TestServeUsesOneUnsharedUpstreamPerConcurrentDownstream(t *testing.T) {
	fixture := newConnectionFixture(t)
	release := make(chan struct{})
	server := startUnixAgent(t, fixture.upstreamPath, func(int) *scriptedAgent {
		upstream := newScriptedAgent(t, fixture.privateKey)
		upstream.listRelease = release
		return upstream
	})
	defer server.close(t)
	first, closeFirst := serveDownstream(t, fixture)
	defer closeFirst()
	second, closeSecond := serveDownstream(t, fixture)
	defer closeSecond()

	resultErrors := make(chan error, 2)
	for _, client := range []agent.ExtendedAgent{first, second} {
		go func(client agent.ExtendedAgent) {
			keys, err := client.List()
			if err == nil && len(keys) != 1 {
				err = errors.New("unexpected identity count")
			}
			resultErrors <- err
		}(client)
	}
	server.waitAccepted(t, 2)
	close(release)
	for range 2 {
		if err := <-resultErrors; err != nil {
			t.Fatalf("concurrent List() error = %v", err)
		}
	}
}

func TestServeCancellationInterruptsAnActiveUpstreamOperation(t *testing.T) {
	fixture := newConnectionFixture(t)
	release := make(chan struct{})
	server := startUnixAgent(t, fixture.upstreamPath, func(int) *scriptedAgent {
		upstream := newScriptedAgent(t, fixture.privateKey)
		upstream.signRelease = release
		return upstream
	})
	defer server.close(t)

	ctx, cancel := context.WithCancel(context.Background())
	clientConnection, serverConnection := net.Pipe()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- agentconn.Serve(
			ctx,
			fixture.store,
			fixture.consumerPath,
			fixture.upstreamPath,
			fixture.timeouts,
			serverConnection,
		)
	}()
	client := agent.NewClient(clientConnection)
	signDone := make(chan error, 1)
	go func() {
		_, err := client.Sign(fixture.publicKey, []byte("generic challenge"))
		signDone <- err
	}()
	accepted := server.waitAccepted(t, 1)[0]
	accepted.agent.waitForOperation(t, "sign")

	cancel()
	select {
	case <-serveDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Serve() did not stop after cancellation")
	}
	select {
	case err := <-signDone:
		if err == nil {
			t.Fatal("Sign() error = nil after cancellation")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Sign() remained blocked after cancellation")
	}
	close(release)
	accepted.waitDone(t)
	_ = clientConnection.Close()
}

func TestConnectionRejectsInvalidPathAndTimeouts(t *testing.T) {
	t.Parallel()

	if _, err := agentconn.New("relative.sock", config.DefaultTimeouts()); err == nil {
		t.Fatal("New(relative path) error = nil")
	}
	timeouts := config.DefaultTimeouts()
	timeouts.Replay = 0
	if _, err := agentconn.New("/tmp/service/endpoint.sock", timeouts); err == nil {
		t.Fatal("New(invalid replay timeout) error = nil")
	}
}

type connectionFixture struct {
	upstreamPath string
	consumerPath string
	timeouts     config.Timeouts
	store        *runtime.Store
	publicKey    ssh.PublicKey
	privateKey   ed25519.PrivateKey
	fingerprint  string
}

func newConnectionFixture(t *testing.T) connectionFixture {
	t.Helper()
	root := t.TempDir()
	upstreamPath := filepath.Join(root, "service", "endpoint.sock")
	consumerPath := filepath.Join(root, "client", "endpoint.sock")
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	publicKey, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatalf("NewPublicKey() error = %v", err)
	}
	fingerprint := ssh.FingerprintSHA256(publicKey)
	timeouts := config.DefaultTimeouts()
	configuration := config.Config{
		Upstream: upstreamPath,
		Consumers: []config.Consumer{{
			Name:         "sample",
			Socket:       consumerPath,
			Fingerprints: []string{fingerprint},
		}},
		Timeouts: timeouts,
	}
	store, err := runtime.NewStore(configuration)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	return connectionFixture{
		upstreamPath: upstreamPath,
		consumerPath: consumerPath,
		timeouts:     timeouts,
		store:        store,
		publicKey:    publicKey,
		privateKey:   private,
		fingerprint:  fingerprint,
	}
}

func serveDownstream(t *testing.T, fixture connectionFixture) (agent.ExtendedAgent, func()) {
	t.Helper()
	clientConnection, serverConnection := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- agentconn.Serve(
			context.Background(),
			fixture.store,
			fixture.consumerPath,
			fixture.upstreamPath,
			fixture.timeouts,
			serverConnection,
		)
	}()
	return agent.NewClient(clientConnection), func() {
		_ = clientConnection.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				t.Errorf("Serve() error = %v", err)
			}
		case <-time.After(time.Second):
			t.Error("Serve() did not stop")
		}
	}
}

type operation struct {
	kind     string
	contents []byte
}

type scriptedAgent struct {
	agent.ExtendedAgent
	mu             sync.Mutex
	seen           []operation
	listDelay      time.Duration
	signDelay      time.Duration
	extensionDelay time.Duration
	extensionError error
	listRelease    <-chan struct{}
	signRelease    <-chan struct{}
}

func newScriptedAgent(t *testing.T, privateKey ed25519.PrivateKey) *scriptedAgent {
	t.Helper()
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey, Comment: "display label"}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	return &scriptedAgent{ExtendedAgent: keyring.(agent.ExtendedAgent)}
}

func (upstream *scriptedAgent) List() ([]*agent.Key, error) {
	upstream.record(operation{kind: "list"})
	if upstream.listRelease != nil {
		<-upstream.listRelease
	}
	time.Sleep(upstream.listDelay)
	return upstream.ExtendedAgent.List()
}

func (upstream *scriptedAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	upstream.record(operation{kind: "sign"})
	if upstream.signRelease != nil {
		<-upstream.signRelease
	}
	time.Sleep(upstream.signDelay)
	return upstream.ExtendedAgent.SignWithFlags(key, data, flags)
}

func (upstream *scriptedAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	upstream.record(operation{kind: "extension", contents: slices.Clone(contents)})
	time.Sleep(upstream.extensionDelay)
	if extensionType != sessionBindExtension {
		return nil, agent.ErrExtensionUnsupported
	}
	if upstream.extensionError != nil {
		return nil, upstream.extensionError
	}
	return []byte{6}, nil
}

func (upstream *scriptedAgent) record(seen operation) {
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	upstream.seen = append(upstream.seen, seen)
}

func (upstream *scriptedAgent) operations() []operation {
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	return slices.Clone(upstream.seen)
}

func (upstream *scriptedAgent) waitForOperation(t *testing.T, kind string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if slices.ContainsFunc(upstream.operations(), func(seen operation) bool {
			return seen.kind == kind
		}) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("upstream operation %q was not observed", kind)
}

type acceptedConnection struct {
	agent *scriptedAgent
	done  chan struct{}
}

func (accepted *acceptedConnection) waitDone(t *testing.T) {
	t.Helper()
	select {
	case <-accepted.done:
	case <-time.After(time.Second):
		t.Fatal("discarded upstream stream remained open")
	}
}

type unixAgentServer struct {
	path     string
	listener net.Listener
	factory  func(int) *scriptedAgent

	mu       sync.Mutex
	accepted []*acceptedConnection
	active   map[net.Conn]struct{}
	done     chan struct{}
}

func startUnixAgent(t *testing.T, path string, factory func(int) *scriptedAgent) *unixAgentServer {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	server := &unixAgentServer{
		path:     path,
		listener: listener,
		factory:  factory,
		active:   make(map[net.Conn]struct{}),
		done:     make(chan struct{}),
	}
	go server.accept()
	return server
}

func (server *unixAgentServer) accept() {
	defer close(server.done)
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			return
		}
		server.mu.Lock()
		accepted := &acceptedConnection{
			agent: server.factory(len(server.accepted)),
			done:  make(chan struct{}),
		}
		server.accepted = append(server.accepted, accepted)
		server.active[connection] = struct{}{}
		server.mu.Unlock()
		go func() {
			defer close(accepted.done)
			_ = agent.ServeAgent(accepted.agent, connection)
			_ = connection.Close()
			server.mu.Lock()
			delete(server.active, connection)
			server.mu.Unlock()
		}()
	}
}

func (server *unixAgentServer) waitAccepted(t *testing.T, count int) []*acceptedConnection {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		server.mu.Lock()
		if len(server.accepted) >= count {
			accepted := slices.Clone(server.accepted[:count])
			server.mu.Unlock()
			return accepted
		}
		server.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("accepted connection count did not reach %d", count)
	return nil
}

func (server *unixAgentServer) close(t *testing.T) {
	t.Helper()
	if err := server.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("listener.Close() error = %v", err)
	}
	server.mu.Lock()
	for connection := range server.active {
		_ = connection.Close()
	}
	server.mu.Unlock()
	select {
	case <-server.done:
	case <-time.After(time.Second):
		t.Error("upstream accept loop did not stop")
	}
	if err := os.Remove(server.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Remove(socket) error = %v", err)
	}
}

func sessionBinding(marker string) []byte {
	return ssh.Marshal(struct {
		HostKey      []byte
		SessionID    []byte
		Signature    []byte
		IsForwarding bool
	}{
		HostKey:      []byte("opaque key"),
		SessionID:    []byte("opaque identifier " + marker),
		Signature:    []byte("opaque proof"),
		IsForwarding: true,
	})
}

func operationsEqual(left, right []operation) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].kind != right[index].kind || !bytes.Equal(left[index].contents, right[index].contents) {
			return false
		}
	}
	return true
}
