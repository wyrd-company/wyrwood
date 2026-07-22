//go:build linux && integration

// ---
// relationships:
//   verifies: linux-per-user-agent-proxy
//   verifies: operational-events
//   verifies: control-interface
// ---

package integration_test

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/control"
	"github.com/wyrd-company/wyrwood/internal/daemon"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	containerProbeEnvironment = "WYRWOOD_CONTAINER_PROBE"
	containerImage            = "ubuntu:24.04"
	sessionBindExtension      = "session-bind@openssh.com"
)

func TestMain(tests *testing.M) {
	if os.Getenv(containerProbeEnvironment) == "1" {
		os.Exit(runContainerProbe(os.Stdin, os.Stdout))
	}
	os.Exit(tests.Run())
}

func TestLinuxContainerMountedMilestone(t *testing.T) {
	requireDocker(t)
	root := shortTemporaryDirectory(t)
	paths := milestonePaths{
		root: root, configuration: filepath.Join(root, "configuration", "config.yml"),
		upstream: filepath.Join(root, "upstream", "agent.sock"),
		consumer: filepath.Join(root, "consumer", "agent.sock"),
		control:  filepath.Join(root, "runtime", "control.sock"),
		events:   filepath.Join(root, "state", "events.bin"),
		tools:    filepath.Join(root, "tools"),
	}
	for _, directory := range []string{
		filepath.Dir(paths.configuration), filepath.Dir(paths.upstream),
		filepath.Dir(paths.control), filepath.Dir(paths.events), paths.tools,
	} {
		makeOwnerOnlyDirectory(t, directory)
	}

	selectedPublic, selectedPrivate := generateIdentity(t)
	unselectedPublic, unselectedPrivate := generateIdentity(t)
	selectedFingerprint := ssh.FingerprintSHA256(selectedPublic)
	unselectedFingerprint := ssh.FingerprintSHA256(unselectedPublic)
	commentMarker := "private-display-marker"
	firstAgent := startFakeUpstream(t, paths.upstream, []agent.AddedKey{
		{PrivateKey: selectedPrivate, Comment: commentMarker},
		{PrivateKey: unselectedPrivate, Comment: "secondary-private-marker"},
	})

	writeConfiguration(t, paths, selectedFingerprint)
	options := daemon.Options{
		ConfigPath: paths.configuration, ControlPath: paths.control,
		EventPath: paths.events, EventRetention: 16, UID: uint32(os.Geteuid()),
	}
	service, err := daemon.Open(options)
	if err != nil {
		t.Fatalf("open daemon: %v", err)
	}
	serviceOpen := true
	t.Cleanup(func() {
		if serviceOpen {
			_ = service.Close()
		}
		firstAgent.close()
	})

	controlClient, err := control.NewClient(paths.control)
	if err != nil {
		t.Fatalf("construct same-user control client: %v", err)
	}
	assertSameUserControl(t, controlClient, paths.control)
	initialSocket := socketIdentity(t, paths.consumer)

	copyTestExecutable(t, paths.tools)
	container := startContainer(t, paths)
	initialContainer := container.inspect(t)
	probe := container.startProbe(t)

	if response := probe.call(t, probeCommand{Operation: "control-status"}); response.OK || response.Error != "control-rejected" {
		t.Fatalf("different-UID control result = %#v, want kernel-credential rejection after path access", response)
	}
	listed := probe.call(t, probeCommand{Operation: "list"})
	assertFingerprints(t, listed, selectedFingerprint)
	probePID := listed.PID

	payloadMarker := []byte("private-signing-payload-marker")
	signed := probe.call(t, probeCommand{Operation: "sign", Key: selectedPublic.Marshal(), Data: payloadMarker})
	assertSigned(t, selectedPublic, payloadMarker, signed)
	denied := probe.call(t, probeCommand{Operation: "sign", Key: unselectedPublic.Marshal(), Data: payloadMarker})
	if denied.OK {
		t.Fatal("unselected identity signed through consumer endpoint")
	}

	writeConfiguration(t, paths, selectedFingerprint, unselectedFingerprint)
	applyConfiguration(t, controlClient)
	added := probe.call(t, probeCommand{Operation: "list"})
	assertSameProbe(t, probePID, added)
	assertFingerprints(t, added, selectedFingerprint, unselectedFingerprint)
	assertSigned(t, unselectedPublic, payloadMarker, probe.call(t, probeCommand{
		Operation: "sign", Key: unselectedPublic.Marshal(), Data: payloadMarker,
	}))

	writeConfiguration(t, paths, unselectedFingerprint)
	applyConfiguration(t, controlClient)
	removed := probe.call(t, probeCommand{Operation: "list"})
	assertSameProbe(t, probePID, removed)
	assertFingerprints(t, removed, unselectedFingerprint)
	if response := probe.call(t, probeCommand{Operation: "sign", Key: selectedPublic.Marshal(), Data: payloadMarker}); response.OK {
		t.Fatal("removed identity remained usable on an existing downstream connection")
	}

	sessionMarker := []byte("private-session-context-marker")
	binding := sessionBinding(t, unselectedPublic, sessionMarker)
	if response := probe.call(t, probeCommand{Operation: "extension", Contents: binding}); !response.OK {
		t.Fatalf("session bind failed: %s", response.Error)
	}

	firstAgent.close()
	outageStarted := time.Now()
	if response := probe.call(t, probeCommand{Operation: "list"}); response.OK {
		t.Fatal("closed upstream stream unexpectedly completed a request")
	}
	if response := probe.call(t, probeCommand{Operation: "list"}); response.OK {
		t.Fatal("absent upstream socket unexpectedly completed a request")
	}
	if elapsed := time.Since(outageStarted); elapsed > 2*time.Second {
		t.Fatalf("upstream outage failure took %s, want a bounded failure", elapsed)
	}

	replacement := startFakeUpstream(t, paths.upstream, []agent.AddedKey{
		{PrivateKey: selectedPrivate, Comment: commentMarker},
		{PrivateKey: unselectedPrivate, Comment: "secondary-private-marker"},
	})
	t.Cleanup(replacement.close)
	recovered := probe.call(t, probeCommand{Operation: "list"})
	assertSameProbe(t, probePID, recovered)
	assertFingerprints(t, recovered, unselectedFingerprint)
	replacement.assertReplayBeforeList(t, binding)

	beforeRestartEvents := recentEvents(t, controlClient)
	assertOperation(t, beforeRestartEvents, "sign", "succeeded", &unselectedFingerprint)
	assertOperation(t, beforeRestartEvents, "sign", "denied", &selectedFingerprint)
	assertOperation(t, beforeRestartEvents, "session-bind", "succeeded", nil)
	assertOperation(t, beforeRestartEvents, "replay", "succeeded", nil)
	assertRedacted(t, beforeRestartEvents, paths, payloadMarker, sessionMarker, []byte(commentMarker))
	beforeRestartRaw, err := os.ReadFile(paths.events)
	if err != nil {
		t.Fatalf("read durable events before retention churn: %v", err)
	}
	assertNoMarkers(t, beforeRestartRaw, paths, payloadMarker, sessionMarker, []byte(commentMarker))

	if err := service.Close(); err != nil {
		t.Fatalf("close daemon for restart: %v", err)
	}
	serviceOpen = false
	probe.close(t)
	if _, err := os.Lstat(paths.consumer); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("consumer endpoint remained during daemon outage: %v", err)
	}

	service, err = daemon.Open(options)
	if err != nil {
		t.Fatalf("restart daemon: %v", err)
	}
	serviceOpen = true
	controlClient, _ = control.NewClient(paths.control)
	restartedSocket := socketIdentity(t, paths.consumer)
	if restartedSocket == initialSocket {
		t.Fatal("daemon restart did not recreate the consumer endpoint inode")
	}
	if afterRestart := container.inspect(t); afterRestart != initialContainer {
		t.Fatalf("container identity or mounts changed across daemon restart:\n before %s\n after  %s", initialContainer, afterRestart)
	}

	restartedProbe := container.startProbe(t)
	defer restartedProbe.close(t)
	assertFingerprints(t, restartedProbe.call(t, probeCommand{Operation: "list"}), unselectedFingerprint)
	assertSigned(t, unselectedPublic, payloadMarker, restartedProbe.call(t, probeCommand{
		Operation: "sign", Key: unselectedPublic.Marshal(), Data: payloadMarker,
	}))
	for index := 0; index < 20; index++ {
		assertFingerprints(t, restartedProbe.call(t, probeCommand{Operation: "list"}), unselectedFingerprint)
	}
	retained := recentEvents(t, controlClient)
	if len(retained) != options.EventRetention {
		t.Fatalf("retained events = %d, want exact bound %d", len(retained), options.EventRetention)
	}
	assertRedacted(t, retained, paths, payloadMarker, sessionMarker, []byte(commentMarker))
	rawEvents, err := os.ReadFile(paths.events)
	if err != nil {
		t.Fatalf("read durable events: %v", err)
	}
	assertNoMarkers(t, rawEvents, paths, payloadMarker, sessionMarker, []byte(commentMarker))
}

type milestonePaths struct {
	root, configuration, upstream, consumer, control, events, tools string
}

type probeCommand struct {
	Operation string `json:"operation"`
	Key       []byte `json:"key,omitempty"`
	Data      []byte `json:"data,omitempty"`
	Contents  []byte `json:"contents,omitempty"`
}

type probeResponse struct {
	OK           bool     `json:"ok"`
	PID          int      `json:"pid"`
	Fingerprints []string `json:"fingerprints,omitempty"`
	Format       string   `json:"format,omitempty"`
	Signature    []byte   `json:"signature,omitempty"`
	Error        string   `json:"error,omitempty"`
}

func runContainerProbe(input io.Reader, output io.Writer) int {
	socket := os.Getenv("SSH_AUTH_SOCK")
	connection, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		return 1
	}
	defer connection.Close()
	client := agent.NewClient(connection)
	decoder := json.NewDecoder(bufio.NewReader(input))
	encoder := json.NewEncoder(output)
	for {
		var command probeCommand
		if err := decoder.Decode(&command); errors.Is(err, io.EOF) {
			return 0
		} else if err != nil {
			return 2
		}
		response := executeProbeCommand(client, command)
		response.PID = os.Getpid()
		if err := encoder.Encode(response); err != nil {
			return 3
		}
	}
}

func executeProbeCommand(client agent.ExtendedAgent, command probeCommand) probeResponse {
	switch command.Operation {
	case "list":
		keys, err := client.List()
		if err != nil {
			return failedProbeResponse()
		}
		fingerprints := make([]string, 0, len(keys))
		for _, key := range keys {
			publicKey, parseErr := ssh.ParsePublicKey(key.Marshal())
			if parseErr != nil {
				return failedProbeResponse()
			}
			fingerprints = append(fingerprints, ssh.FingerprintSHA256(publicKey))
		}
		slices.Sort(fingerprints)
		return probeResponse{OK: true, Fingerprints: fingerprints}
	case "sign":
		key, err := ssh.ParsePublicKey(command.Key)
		if err != nil {
			return failedProbeResponse()
		}
		signature, err := client.Sign(key, command.Data)
		if err != nil || signature == nil {
			return failedProbeResponse()
		}
		return probeResponse{OK: true, Format: signature.Format, Signature: signature.Blob}
	case "extension":
		_, err := client.Extension(sessionBindExtension, command.Contents)
		if err != nil {
			return failedProbeResponse()
		}
		return probeResponse{OK: true}
	case "control-status":
		if _, err := os.Stat("/control/control.sock"); err != nil {
			return probeResponse{Error: "control-path-unavailable"}
		}
		client, err := control.NewClient("/control/control.sock")
		if err == nil {
			_, err = client.Status()
		}
		if err == nil {
			return probeResponse{OK: true}
		}
		return probeResponse{Error: "control-rejected"}
	default:
		return failedProbeResponse()
	}
}

func failedProbeResponse() probeResponse { return probeResponse{Error: "operation-failed"} }

type containerHarness struct {
	t      *testing.T
	name   string
	config string
}

func startContainer(t *testing.T, paths milestonePaths) *containerHarness {
	t.Helper()
	config := filepath.Join(paths.root, "docker-config")
	makeOwnerOnlyDirectory(t, config)
	name := fmt.Sprintf("agent-gate-%d-%d", os.Getpid(), time.Now().UnixNano())
	harness := &containerHarness{t: t, name: name, config: config}
	t.Cleanup(func() {
		output, err := dockerCommand(config, "rm", "--force", name).CombinedOutput()
		if err != nil && !bytes.Contains(output, []byte("No such container")) {
			t.Errorf("remove integration container: %v: %s", err, output)
		}
	})
	arguments := []string{
		"run", "--detach", "--name", name, "--pull=missing",
		"--mount", "type=bind,source=" + filepath.Dir(paths.consumer) + ",target=/agent",
		"--mount", "type=bind,source=" + filepath.Dir(paths.control) + ",target=/control,readonly",
		"--mount", "type=bind,source=" + paths.tools + ",target=/tool,readonly",
		"--env", "SSH_AUTH_SOCK=/agent/agent.sock", containerImage, "sleep", "infinity",
	}
	runDocker(t, config, arguments...)
	return harness
}

func (container *containerHarness) inspect(t *testing.T) string {
	t.Helper()
	type mount struct {
		Type, Source, Destination, Mode, Propagation string
		RW                                           bool
	}
	var inspected []struct {
		ID     string
		Mounts []mount
	}
	if err := json.Unmarshal([]byte(runDocker(t, container.config, "inspect", container.name)), &inspected); err != nil || len(inspected) != 1 {
		t.Fatalf("decode container identity and mounts: %v", err)
	}
	slices.SortFunc(inspected[0].Mounts, func(left, right mount) int {
		return strings.Compare(left.Destination, right.Destination)
	})
	canonical, err := json.Marshal(inspected[0])
	if err != nil {
		t.Fatalf("encode container identity and mounts: %v", err)
	}
	return string(canonical)
}

type probeHarness struct {
	command *exec.Cmd
	input   io.WriteCloser
	decoder *json.Decoder
	stderr  bytes.Buffer
	closed  bool
}

func (container *containerHarness) startProbe(t *testing.T) *probeHarness {
	t.Helper()
	command := dockerCommand(
		container.config, "exec", "--interactive", "--env", containerProbeEnvironment+"=1",
		container.name, "/tool/probe",
	)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("open probe stdin: %v", err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("open probe stdout: %v", err)
	}
	probe := &probeHarness{command: command, input: input, decoder: json.NewDecoder(output)}
	command.Stderr = &probe.stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start container probe: %v", err)
	}
	t.Cleanup(func() {
		if err := probe.stop(); err != nil {
			t.Errorf("clean container probe: %v; stderr: %s", err, probe.stderr.String())
		}
	})
	return probe
}

func (probe *probeHarness) call(t *testing.T, command probeCommand) probeResponse {
	t.Helper()
	if err := json.NewEncoder(probe.input).Encode(command); err != nil {
		t.Fatalf("write probe command: %v", err)
	}
	var response probeResponse
	if err := probe.decoder.Decode(&response); err != nil {
		t.Fatalf("read probe response: %v; stderr: %s", err, probe.stderr.String())
	}
	return response
}

func (probe *probeHarness) close(t *testing.T) {
	t.Helper()
	if err := probe.stop(); err != nil {
		t.Fatalf("wait for container probe: %v; stderr: %s", err, probe.stderr.String())
	}
}

func (probe *probeHarness) stop() error {
	if probe.closed {
		return nil
	}
	probe.closed = true
	_ = probe.input.Close()
	return probe.command.Wait()
}

type fakeOperation struct {
	kind     string
	contents []byte
}

type recordingAgent struct {
	agent.ExtendedAgent
	mu         sync.Mutex
	operations []fakeOperation
}

func (upstream *recordingAgent) List() ([]*agent.Key, error) {
	upstream.record(fakeOperation{kind: "list"})
	return upstream.ExtendedAgent.List()
}

func (upstream *recordingAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	upstream.record(fakeOperation{kind: "sign"})
	return upstream.ExtendedAgent.SignWithFlags(key, data, flags)
}

func (upstream *recordingAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return upstream.SignWithFlags(key, data, 0)
}

func (upstream *recordingAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType != sessionBindExtension {
		return nil, agent.ErrExtensionUnsupported
	}
	upstream.record(fakeOperation{kind: "extension", contents: slices.Clone(contents)})
	return []byte{6}, nil
}

func (upstream *recordingAgent) record(operation fakeOperation) {
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	upstream.operations = append(upstream.operations, operation)
}

type fakeUpstream struct {
	path        string
	listener    *net.UnixListener
	agent       *recordingAgent
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closed      bool
	wait        sync.WaitGroup
	closeOnce   sync.Once
}

func startFakeUpstream(t *testing.T, path string, keys []agent.AddedKey) *fakeUpstream {
	t.Helper()
	keyring := agent.NewKeyring()
	for _, key := range keys {
		if err := keyring.Add(key); err != nil {
			t.Fatalf("add fake upstream identity: %v", err)
		}
	}
	extended, ok := keyring.(agent.ExtendedAgent)
	if !ok {
		t.Fatal("keyring does not implement the extended agent contract")
	}
	_ = os.Remove(path)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("listen on fake upstream path: %v", err)
	}
	server := &fakeUpstream{
		path: path, listener: listener, agent: &recordingAgent{ExtendedAgent: extended},
		connections: make(map[net.Conn]struct{}),
	}
	server.wait.Add(1)
	go server.accept()
	return server
}

func (server *fakeUpstream) accept() {
	defer server.wait.Done()
	for {
		connection, err := server.listener.AcceptUnix()
		if err != nil {
			return
		}
		server.mu.Lock()
		if server.closed {
			server.mu.Unlock()
			_ = connection.Close()
			return
		}
		server.connections[connection] = struct{}{}
		server.wait.Add(1)
		server.mu.Unlock()
		go func() {
			defer server.wait.Done()
			_ = agent.ServeAgent(server.agent, connection)
			_ = connection.Close()
			server.mu.Lock()
			delete(server.connections, connection)
			server.mu.Unlock()
		}()
	}
}

func (server *fakeUpstream) close() {
	server.closeOnce.Do(func() {
		server.mu.Lock()
		server.closed = true
		_ = server.listener.Close()
		for connection := range server.connections {
			_ = connection.Close()
		}
		server.mu.Unlock()
		server.wait.Wait()
		_ = os.Remove(server.path)
	})
}

func (server *fakeUpstream) assertReplayBeforeList(t *testing.T, binding []byte) {
	t.Helper()
	server.agent.mu.Lock()
	defer server.agent.mu.Unlock()
	if len(server.agent.operations) < 2 || server.agent.operations[0].kind != "extension" ||
		!bytes.Equal(server.agent.operations[0].contents, binding) || server.agent.operations[1].kind != "list" {
		t.Fatalf("replacement operations = %#v, want exact session replay before list", server.agent.operations)
	}
}

func generateIdentity(t *testing.T) (ssh.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate generic identity: %v", err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatalf("convert generic identity: %v", err)
	}
	return sshPublic, private
}

func sessionBinding(t *testing.T, hostKey ssh.PublicKey, sessionID []byte) []byte {
	t.Helper()
	return ssh.Marshal(struct {
		HostKey      []byte
		SessionID    []byte
		Signature    []byte
		IsForwarding bool
	}{HostKey: hostKey.Marshal(), SessionID: sessionID, Signature: []byte("generic-signature")})
}

func writeConfiguration(t *testing.T, paths milestonePaths, fingerprints ...string) {
	t.Helper()
	var document strings.Builder
	document.WriteString("upstream: " + paths.upstream + "\nconsumers:\n")
	document.WriteString("  - name: sample workload\n    socket: " + paths.consumer + "\n    fingerprints:\n")
	for _, fingerprint := range fingerprints {
		document.WriteString("      - " + fingerprint + "\n")
	}
	document.WriteString("timeouts:\n  connect: 300ms\n  list: 300ms\n  replay: 300ms\n  sign: 1s\n")
	if err := os.WriteFile(paths.configuration, []byte(document.String()), 0o600); err != nil {
		t.Fatalf("write milestone configuration: %v", err)
	}
}

func applyConfiguration(t *testing.T, client *control.Client) {
	t.Helper()
	result, err := client.Apply()
	if err != nil || !result.Committed {
		t.Fatalf("apply configuration = %#v, %v", result, err)
	}
}

func assertSameUserControl(t *testing.T, client *control.Client, path string) {
	t.Helper()
	status, err := client.Status()
	if err != nil || status.Daemon != control.HealthHealthy || len(status.Consumers) != 1 {
		t.Fatalf("same-user status = %#v, %v", status, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("control socket mode = %v, %v", info, err)
	}
}

func assertFingerprints(t *testing.T, response probeResponse, expected ...string) {
	t.Helper()
	if !response.OK {
		t.Fatalf("identity list failed: %s", response.Error)
	}
	slices.Sort(expected)
	if !slices.Equal(response.Fingerprints, expected) {
		t.Fatalf("listed fingerprints = %v, want %v", response.Fingerprints, expected)
	}
}

func assertSigned(t *testing.T, key ssh.PublicKey, data []byte, response probeResponse) {
	t.Helper()
	if !response.OK {
		t.Fatalf("sign failed: %s", response.Error)
	}
	if err := key.Verify(data, &ssh.Signature{Format: response.Format, Blob: response.Signature}); err != nil {
		t.Fatalf("verify returned signature: %v", err)
	}
}

func assertSameProbe(t *testing.T, pid int, response probeResponse) {
	t.Helper()
	if response.PID != pid {
		t.Fatalf("container probe PID changed from %d to %d", pid, response.PID)
	}
}

func recentEvents(t *testing.T, client *control.Client) []control.Event {
	t.Helper()
	result, err := client.Events(control.MaximumEventLimit)
	if err != nil {
		t.Fatalf("query operational events: %v", err)
	}
	return result.Events
}

func assertOperation(t *testing.T, retained []control.Event, operation, outcome string, fingerprint *string) {
	t.Helper()
	for _, event := range retained {
		if event.Operation == operation && event.Outcome == outcome &&
			(fingerprint == nil || event.Fingerprint != nil && *event.Fingerprint == *fingerprint) {
			return
		}
	}
	t.Fatalf("operation %s/%s with fingerprint %v absent from %#v", operation, outcome, fingerprint, retained)
}

func assertRedacted(t *testing.T, retained []control.Event, paths milestonePaths, markers ...[]byte) {
	t.Helper()
	encoded, err := json.Marshal(retained)
	if err != nil {
		t.Fatalf("encode projected events: %v", err)
	}
	assertNoMarkers(t, encoded, paths, markers...)
}

func assertNoMarkers(t *testing.T, data []byte, paths milestonePaths, markers ...[]byte) {
	t.Helper()
	markers = append(markers, []byte(paths.root), []byte(paths.upstream), []byte(paths.consumer), []byte(paths.control))
	for _, marker := range markers {
		if bytes.Contains(data, marker) {
			t.Fatalf("operational events retained private marker %q", marker)
		}
	}
}

func socketIdentity(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat consumer endpoint: %v", err)
	}
	return fmt.Sprintf("%d-%d", info.Sys().(*syscall.Stat_t).Dev, info.Sys().(*syscall.Stat_t).Ino)
}

func shortTemporaryDirectory(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "agent-gate-")
	if err != nil {
		t.Fatalf("create short integration root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

func makeOwnerOnlyDirectory(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("create directory %s: %v", path, err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatalf("secure directory %s: %v", path, err)
	}
}

func copyTestExecutable(t *testing.T, toolDirectory string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve integration executable: %v", err)
	}
	source, err := os.Open(executable)
	if err != nil {
		t.Fatalf("open integration executable: %v", err)
	}
	defer source.Close()
	target, err := os.OpenFile(filepath.Join(toolDirectory, "probe"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatalf("create container probe: %v", err)
	}
	if _, err := io.Copy(target, source); err != nil {
		_ = target.Close()
		t.Fatalf("copy container probe: %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatalf("close container probe: %v", err)
	}
}

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("Docker is required for the Linux integration gate: %v", err)
	}
}

func dockerCommand(config string, arguments ...string) *exec.Cmd {
	command := exec.Command("docker", arguments...)
	command.Env = append(os.Environ(), "DOCKER_CONFIG="+config)
	return command
}

func runDocker(t *testing.T, config string, arguments ...string) string {
	t.Helper()
	command := dockerCommand(config, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(arguments, " "), err, output)
	}
	return string(output)
}
