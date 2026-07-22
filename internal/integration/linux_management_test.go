//go:build linux && integration

// ---
// relationships:
//   verifies: linux-per-user-agent-proxy
//   verifies: command-line-interface
//   verifies: terminal-interface
//   verifies: configuration
//   verifies: operational-events
// ---

package integration_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/unix"
)

const managementEventLimit = 100

type commandEnvelope struct {
	Version int             `json:"version"`
	Command string          `json:"command"`
	OK      bool            `json:"ok"`
	Result  json.RawMessage `json:"result"`
	Error   struct {
		Code string `json:"code"`
	} `json:"error"`
}

type configurationProjection struct {
	Revision string `json:"revision"`
	Upstream string `json:"upstream"`
	Timeouts struct {
		Connect string `json:"connect"`
		List    string `json:"list"`
		Replay  string `json:"replay"`
		Sign    string `json:"sign"`
	} `json:"timeouts"`
	Consumers []struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		Socket       string   `json:"socket"`
		Fingerprints []string `json:"fingerprints"`
	} `json:"consumers"`
}

type changeProjection struct {
	Revision   string `json:"revision"`
	Changed    bool   `json:"changed"`
	ConsumerID string `json:"consumer_id"`
}

type eventsProjection struct {
	Events []json.RawMessage `json:"events"`
}

type keysProjection struct {
	Keys []struct {
		Fingerprint string `json:"fingerprint"`
	} `json:"keys"`
}

// TestLinuxManagementMilestone is deliberately process-level. It builds the
// user-facing executable, runs its real daemon, and drives both management
// surfaces over the same owner-authenticated Unix control socket.
//
// The threat model treats a same-user management client as untrusted with
// respect to revision freshness and candidate values, a connected downstream
// principal as able to keep using its stream across policy changes, and
// upstream/configuration diagnostics as hostile data. The daemon must remain
// the sole durable and runtime mutation authority, recheck policy per request,
// project only bounded categorical operational data, and remove only the
// retired principal's owned socket and connections.
func TestLinuxManagementMilestone(t *testing.T) {
	root := shortTemporaryDirectory(t)
	paths := managementPaths{
		root:          root,
		upstream:      filepath.Join(root, "source", "agent.sock"),
		primary:       filepath.Join(root, "endpoints", "alpha", "agent.sock"),
		secondary:     filepath.Join(root, "endpoints", "beta", "agent.sock"),
		configuration: filepath.Join(root, "configuration", "wyrwood", "config.yml"),
		control:       filepath.Join(root, "runtime", "wyrwood", "control.sock"),
		events:        filepath.Join(root, "state", "wyrwood", "events.bin"),
		binary:        filepath.Join(root, "tools", "wyrwood"),
	}
	for _, directory := range []string{
		filepath.Dir(paths.upstream), filepath.Dir(filepath.Dir(paths.primary)),
		filepath.Dir(paths.binary), filepath.Dir(paths.control),
	} {
		makeOwnerOnlyDirectory(t, directory)
	}

	selectedPublic, selectedPrivate := generateIdentity(t)
	alternatePublic, alternatePrivate := generateIdentity(t)
	selectedFingerprint := ssh.FingerprintSHA256(selectedPublic)
	alternateFingerprint := ssh.FingerprintSHA256(alternatePublic)
	commentMarker := "display\x1b[31m-marker"
	upstream := startFakeUpstream(t, paths.upstream, []agent.AddedKey{
		{PrivateKey: selectedPrivate, Comment: commentMarker},
		{PrivateKey: alternatePrivate, Comment: "alternate display"},
	})
	t.Cleanup(upstream.close)

	environment := isolatedEnvironment(paths)
	buildManagementBinary(t, paths.binary)
	help := runManagementCommand(paths.binary, environment, "help")
	if help.exitCode != 0 || len(help.stderr) != 0 || !bytes.Contains(help.stdout, []byte("Open the terminal management interface")) || bytes.Contains(help.stdout, []byte("reserved")) {
		t.Fatalf("completed management help = exit %d stdout %q stderr %q", help.exitCode, help.stdout, help.stderr)
	}
	assertCommandSuccess(t, paths.binary, environment, "init", "--output", "json")
	daemon := startManagementDaemon(t, paths, environment)

	initial := showConfiguration(t, paths.binary, environment)
	if initial.Upstream != paths.upstream || len(initial.Consumers) != 0 {
		t.Fatalf("initialized configuration = %#v", initial)
	}
	keyIndex := availableKeyIndex(t, paths.binary, environment, selectedFingerprint)
	terminal := startManagementTUI(t, paths.binary, environment, 118, 34)
	terminal.waitFor("configuration EMPTY")
	terminal.write("n")
	terminal.waitFor("NEW CONSUMER")
	terminal.write("sample alpha")
	terminal.write("\t")
	terminal.write(paths.primary)
	terminal.write("\t")
	terminal.write("\t")
	terminal.waitFor(selectedFingerprint[:19])
	for index := 0; index < keyIndex; index++ {
		terminal.write("j")
		time.Sleep(5 * time.Millisecond)
	}
	terminal.write(" ")
	terminal.write("\t")
	terminal.write("\r")
	terminal.waitFor("SAVED · UNAPPLIED")
	terminal.waitFor("║ > sample alpha")
	terminal.write("a")
	terminal.waitFor("APPLIED · COMMITTED")
	terminal.write("q")
	terminal.waitClean()
	assertNoPrivateMarkers(t, terminal.output(), []byte(commentMarker))
	primaryConfiguration := showConfiguration(t, paths.binary, environment)
	primary := findConsumer(t, primaryConfiguration, "sample alpha")
	if !reflect.DeepEqual(primary.Fingerprints, []string{selectedFingerprint}) {
		t.Fatalf("terminal key selection = %v, want exact selected fingerprint", primary.Fingerprints)
	}
	primaryChange := changeProjection{Revision: primaryConfiguration.Revision, Changed: true, ConsumerID: primary.ID}
	secondaryChange := putConsumer(t, paths.binary, environment, primaryChange.Revision, "sample beta", paths.secondary, selectedFingerprint)

	// One PTY session proves CLI-to-TUI visibility, resize, stale-edit
	// protection, coherent reload, cancellation, TUI-to-CLI visibility, and
	// exact terminal restoration.
	terminal = startManagementTUI(t, paths.binary, environment, 118, 34)
	terminal.waitFor("sample beta")
	terminal.resize(58, 14)
	terminal.waitFor("DASHBOARD")
	terminal.resize(118, 34)
	terminal.waitFor("sample alpha")
	terminal.write("s")
	terminal.waitFor("SETTINGS / TIMEOUTS")
	terminal.write("\x7f\x7f6s")
	terminal.waitFor("DIRTY")
	rival := setTimeouts(t, paths.binary, environment, secondaryChange.Revision, "7s", "5s", "5s", "2m")
	terminal.write("\t\t\t\t\r")
	terminal.waitFor("CONFLICT")
	terminal.write("R")
	terminal.waitFor("CLEAN")
	terminal.waitFor("7s")
	terminal.write("\x7f\x7f6s")
	terminal.waitFor("DIRTY")
	terminal.write("\x1b")
	terminal.waitFor("Discard local edits?")
	terminal.write("k")
	terminal.waitFor("\x1b[J")
	terminal.write("\x1b")
	terminal.waitFor("Discard local edits?")
	terminal.write("d")
	terminal.waitFor("DASHBOARD")
	terminal.write("s")
	terminal.waitFor("SETTINGS / TIMEOUTS")
	terminal.write("\x7f\x7f6s\t\t\t\t\r")
	terminal.waitFor("SAVED")
	terminal.write("q")
	terminal.waitClean()

	afterTUI := showConfiguration(t, paths.binary, environment)
	if afterTUI.Revision == rival.Revision || afterTUI.Timeouts.Connect != "6s" {
		t.Fatalf("TUI mutation was not visible to CLI: %#v", afterTUI)
	}

	// The revision captured before the rival and TUI writes is stale and must
	// not overwrite their newer canonical YAML.
	beforeStale, err := os.ReadFile(paths.configuration)
	if err != nil {
		t.Fatal(err)
	}
	stale := runManagementCommand(paths.binary, environment,
		"configuration", "set-upstream", "--revision", secondaryChange.Revision,
		"--socket", paths.upstream, "--output", "json")
	assertCommandFailure(t, stale, 8, "configuration-conflict")
	afterStale, err := os.ReadFile(paths.configuration)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeStale, afterStale) {
		t.Fatal("stale mutation changed durable configuration")
	}

	assertCommandSuccess(t, paths.binary, environment, "apply", "--output", "json")
	primaryConnection, err := net.DialTimeout("unix", paths.primary, time.Second)
	if err != nil {
		t.Fatalf("connect primary endpoint: %v", err)
	}
	defer primaryConnection.Close()
	primaryClient := agent.NewClient(primaryConnection)
	assertAgentFingerprints(t, primaryClient, selectedFingerprint)

	current := showConfiguration(t, paths.binary, environment)
	primary = findConsumer(t, current, "sample alpha")
	added := putExistingConsumer(t, paths.binary, environment, current.Revision, primary.ID, primary.Name, primary.Socket, selectedFingerprint, alternateFingerprint)
	assertAgentFingerprints(t, primaryClient, selectedFingerprint)
	assertCommandSuccess(t, paths.binary, environment, "apply", "--output", "json")
	assertAgentFingerprints(t, primaryClient, alternateFingerprint, selectedFingerprint)

	removed := putExistingConsumer(t, paths.binary, environment, added.Revision, added.ConsumerID, primary.Name, primary.Socket, alternateFingerprint)
	assertAgentFingerprints(t, primaryClient, alternateFingerprint, selectedFingerprint)
	assertCommandSuccess(t, paths.binary, environment, "apply", "--output", "json")
	assertAgentFingerprints(t, primaryClient, alternateFingerprint)
	payloadMarker := []byte("private-request-payload-marker")
	if _, err := primaryClient.Sign(selectedPublic, payloadMarker); err == nil {
		t.Fatal("removed fingerprint signed on an existing downstream connection")
	}
	if signature, err := primaryClient.Sign(alternatePublic, payloadMarker); err != nil || signature == nil {
		t.Fatalf("selected fingerprint could not sign: signature=%#v err=%v", signature, err)
	}
	for index := 0; index < managementEventLimit+20; index++ {
		assertAgentFingerprints(t, primaryClient, alternateFingerprint)
	}

	assertOperationalOutputsRedacted(t, paths, environment, payloadMarker, []byte(commentMarker))

	retired := retireConsumer(t, paths.binary, environment, removed.Revision, removed.ConsumerID)
	assertCommandSuccess(t, paths.binary, environment, "apply", "--output", "json")
	waitForAbsent(t, paths.primary)
	if _, err := primaryClient.List(); err == nil {
		t.Fatal("retired consumer kept its existing downstream connection")
	}
	if info, err := os.Stat(filepath.Dir(paths.primary)); err != nil || !info.IsDir() {
		t.Fatalf("retirement removed the user-selected parent: info %#v err %v", info, err)
	}
	secondaryConnection, err := net.DialTimeout("unix", paths.secondary, time.Second)
	if err != nil {
		t.Fatalf("retirement removed or disabled the unrelated endpoint: %v", err)
	}
	secondaryClient := agent.NewClient(secondaryConnection)
	assertAgentFingerprints(t, secondaryClient, selectedFingerprint)
	_ = secondaryConnection.Close()

	// Create enough durable entries to cross the 16-consumer control page and
	// prove both user surfaces assemble one coherent revision.
	revision := retired.Revision
	for index := 0; index < 16; index++ {
		name := fmt.Sprintf("sample page %02d", index)
		socket := filepath.Join(paths.root, "endpoints", fmt.Sprintf("page-%02d", index), "agent.sock")
		change := putConsumer(t, paths.binary, environment, revision, name, socket, alternateFingerprint)
		revision = change.Revision
	}
	paged := showConfiguration(t, paths.binary, environment)
	if paged.Revision != revision || len(paged.Consumers) != 17 {
		t.Fatalf("fully paginated CLI projection = revision %q consumers %d", paged.Revision, len(paged.Consumers))
	}
	pagedTerminal := startManagementTUI(t, paths.binary, environment, 118, 34)
	pagedTerminal.waitFor("sample beta")
	for index := 0; index < 16; index++ {
		pagedTerminal.write("j")
		pagedTerminal.waitFor(fmt.Sprintf("║ > sample page %02d", index))
	}
	pagedTerminal.waitFor("sample page 15")
	pagedTerminal.write("q")
	pagedTerminal.waitClean()

	// Invalid durable YAML and upstream/daemon outages remain categorical; no
	// parser, path, or upstream diagnostic crosses either output surface.
	validDocument, err := os.ReadFile(paths.configuration)
	if err != nil {
		t.Fatal(err)
	}
	invalidMarker := "private-invalid-document-marker"
	if err := os.WriteFile(paths.configuration, []byte("unknown: "+invalidMarker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	invalidApply := runManagementCommand(paths.binary, environment, "apply", "--output", "json")
	assertCommandFailure(t, invalidApply, 5, "apply-invalid")
	assertNoPrivateMarkers(t, append(invalidApply.stdout, invalidApply.stderr...), []byte(invalidMarker), []byte(paths.root))
	invalidTerminal := startManagementTUI(t, paths.binary, environment, 58, 14)
	invalidTerminal.waitFor("UNAVAILABLE")
	invalidTerminal.write("q")
	invalidTerminal.waitClean()
	assertNoPrivateMarkers(t, invalidTerminal.output(), []byte(invalidMarker))
	if err := os.WriteFile(paths.configuration, validDocument, 0o600); err != nil {
		t.Fatal(err)
	}

	upstream.close()
	upstreamFailure := runManagementCommand(paths.binary, environment, "keys", "--output", "json")
	assertCommandFailure(t, upstreamFailure, 7, "upstream-unavailable")
	assertNoPrivateMarkers(t, append(upstreamFailure.stdout, upstreamFailure.stderr...), []byte(paths.upstream), []byte(paths.root))
	outageTerminal := startManagementTUI(t, paths.binary, environment, 58, 14)
	outageTerminal.waitFor("UNAVAILABLE")
	outageTerminal.write("q")
	outageTerminal.waitClean()
	upstream = startFakeUpstream(t, paths.upstream, []agent.AddedKey{
		{PrivateKey: selectedPrivate, Comment: "restored display"},
		{PrivateKey: alternatePrivate, Comment: "alternate display"},
	})
	t.Cleanup(upstream.close)

	if _, err := os.Lstat(paths.control); err != nil {
		t.Fatalf("daemon was not available for non-terminal refusal proof: %v", err)
	}
	nonTerminal := runManagementCommand(paths.binary, environment, "tui")
	assertCommandFailureText(t, nonTerminal, 1, "terminal interface unavailable")
	assertNoPrivateMarkers(t, append(nonTerminal.stdout, nonTerminal.stderr...), []byte(paths.control), []byte(paths.root))

	daemon.stop(t)
	daemonFailure := runManagementCommand(paths.binary, environment, "status", "--output", "json")
	assertCommandFailure(t, daemonFailure, 4, "daemon-unavailable")
	assertNoPrivateMarkers(t, append(daemonFailure.stdout, daemonFailure.stderr...), []byte(paths.control), []byte(paths.root))
	daemonOutageTerminal := startManagementTUI(t, paths.binary, environment, 58, 14)
	daemonOutageTerminal.waitFor("DISCONNECTED")
	daemonOutageTerminal.write("q")
	daemonOutageTerminal.waitClean()
	assertNoPrivateMarkers(t, daemonOutageTerminal.output(), []byte(paths.control), []byte(paths.root))

	daemon = startManagementDaemon(t, paths, environment)
	interrupted := startManagementTUI(t, paths.binary, environment, 118, 34)
	interrupted.waitFor("DASHBOARD")
	interrupted.interrupt()
	interrupted.waitClean()
	if _, err := os.Lstat(paths.control); err != nil {
		t.Fatalf("TUI interruption affected daemon lifecycle: %v", err)
	}
	daemon.stop(t)
	assertAbsent(t, paths.control)
	for _, consumer := range paged.Consumers {
		assertAbsent(t, consumer.Socket)
	}
	assertAbsent(t, paths.primary)
	if entries, err := os.ReadDir(filepath.Dir(paths.control)); err != nil || len(entries) != 0 {
		t.Fatalf("runtime cleanup = entries %#v err %v", entries, err)
	}
}

type managementPaths struct {
	root, upstream, primary, secondary, configuration, control, events, binary string
}

func isolatedEnvironment(paths managementPaths) []string {
	overrides := map[string]string{
		"HOME":            paths.root,
		"XDG_CONFIG_HOME": filepath.Dir(filepath.Dir(paths.configuration)),
		"XDG_DATA_HOME":   filepath.Join(paths.root, "data"),
		"XDG_STATE_HOME":  filepath.Dir(filepath.Dir(paths.events)),
		"XDG_RUNTIME_DIR": filepath.Dir(filepath.Dir(paths.control)),
		"SSH_AUTH_SOCK":   paths.upstream,
		"TERM":            "xterm-256color",
		"NO_COLOR":        "1",
	}
	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if _, replaced := overrides[name]; !replaced {
			environment = append(environment, entry)
		}
	}
	keys := make([]string, 0, len(overrides))
	for key := range overrides {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		environment = append(environment, key+"="+overrides[key])
	}
	return environment
}

func buildManagementBinary(t *testing.T, destination string) {
	t.Helper()
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "build", "-o", destination, "./cmd/wyrwood")
	command.Dir = repository
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build management executable: %v\n%s", err, output)
	}
}

type commandResult struct {
	stdout, stderr []byte
	exitCode       int
}

func runManagementCommand(binary string, environment []string, arguments ...string) commandResult {
	command := exec.Command(binary, arguments...)
	command.Env = environment
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		} else {
			code = -1
		}
	}
	return commandResult{stdout: stdout.Bytes(), stderr: stderr.Bytes(), exitCode: code}
}

func assertCommandSuccess(t *testing.T, binary string, environment []string, arguments ...string) commandEnvelope {
	t.Helper()
	result := runManagementCommand(binary, environment, arguments...)
	if result.exitCode != 0 || len(result.stderr) != 0 {
		t.Fatalf("wyrwood %s = exit %d stdout %q stderr %q", strings.Join(arguments, " "), result.exitCode, result.stdout, result.stderr)
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(result.stdout, &envelope); err != nil || !envelope.OK || envelope.Version != 1 {
		t.Fatalf("decode successful command: envelope %#v err %v output %q", envelope, err, result.stdout)
	}
	return envelope
}

func assertCommandFailure(t *testing.T, result commandResult, exitCode int, code string) {
	t.Helper()
	if result.exitCode != exitCode || len(result.stdout) != 0 {
		t.Fatalf("failure = exit %d stdout %q stderr %q", result.exitCode, result.stdout, result.stderr)
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(result.stderr, &envelope); err != nil || envelope.OK || envelope.Error.Code != code {
		t.Fatalf("failure envelope = %#v err %v output %q", envelope, err, result.stderr)
	}
}

func assertCommandFailureText(t *testing.T, result commandResult, exitCode int, text string) {
	t.Helper()
	if result.exitCode != exitCode || len(result.stdout) != 0 || !bytes.Contains(result.stderr, []byte(text)) {
		t.Fatalf("failure = exit %d stdout %q stderr %q", result.exitCode, result.stdout, result.stderr)
	}
}

func showConfiguration(t *testing.T, binary string, environment []string) configurationProjection {
	t.Helper()
	envelope := assertCommandSuccess(t, binary, environment, "configuration", "show", "--output", "json")
	var result configurationProjection
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func availableKeyIndex(t *testing.T, binary string, environment []string, fingerprint string) int {
	t.Helper()
	envelope := assertCommandSuccess(t, binary, environment, "keys", "--output", "json")
	var result keysProjection
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		t.Fatal(err)
	}
	for index, key := range result.Keys {
		if key.Fingerprint == fingerprint {
			return index
		}
	}
	t.Fatalf("upstream key %q absent from %#v", fingerprint, result.Keys)
	return 0
}

func decodeChange(t *testing.T, envelope commandEnvelope) changeProjection {
	t.Helper()
	var result changeProjection
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func putConsumer(t *testing.T, binary string, environment []string, revision, name, socket string, fingerprints ...string) changeProjection {
	t.Helper()
	arguments := []string{"consumer", "put", "--revision", revision, "--name", name, "--socket", socket}
	for _, fingerprint := range fingerprints {
		arguments = append(arguments, "--fingerprint", fingerprint)
	}
	arguments = append(arguments, "--output", "json")
	return decodeChange(t, assertCommandSuccess(t, binary, environment, arguments...))
}

func putExistingConsumer(t *testing.T, binary string, environment []string, revision, id, name, socket string, fingerprints ...string) changeProjection {
	t.Helper()
	arguments := []string{"consumer", "put", "--revision", revision, "--id", id, "--name", name, "--socket", socket}
	for _, fingerprint := range fingerprints {
		arguments = append(arguments, "--fingerprint", fingerprint)
	}
	arguments = append(arguments, "--output", "json")
	return decodeChange(t, assertCommandSuccess(t, binary, environment, arguments...))
}

func retireConsumer(t *testing.T, binary string, environment []string, revision, id string) changeProjection {
	t.Helper()
	return decodeChange(t, assertCommandSuccess(t, binary, environment,
		"consumer", "retire", "--revision", revision, "--id", id, "--output", "json"))
}

func setTimeouts(t *testing.T, binary string, environment []string, revision, connect, list, replay, sign string) changeProjection {
	t.Helper()
	return decodeChange(t, assertCommandSuccess(t, binary, environment,
		"configuration", "set-timeouts", "--revision", revision,
		"--connect", connect, "--list", list, "--replay", replay, "--sign", sign, "--output", "json"))
}

func findConsumer(t *testing.T, configuration configurationProjection, name string) struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Socket       string   `json:"socket"`
	Fingerprints []string `json:"fingerprints"`
} {
	t.Helper()
	for _, consumer := range configuration.Consumers {
		if consumer.Name == name {
			return consumer
		}
	}
	t.Fatalf("consumer %q absent from %#v", name, configuration.Consumers)
	return struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		Socket       string   `json:"socket"`
		Fingerprints []string `json:"fingerprints"`
	}{}
}

func assertAgentFingerprints(t *testing.T, client agent.Agent, want ...string) {
	t.Helper()
	listed, err := client.List()
	if err != nil {
		t.Fatalf("list consumer identities: %v", err)
	}
	got := make([]string, 0, len(listed))
	for _, identity := range listed {
		public, err := ssh.ParsePublicKey(identity.Marshal())
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, ssh.FingerprintSHA256(public))
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("consumer fingerprints = %v, want %v", got, want)
	}
}

func assertOperationalOutputsRedacted(t *testing.T, paths managementPaths, environment []string, markers ...[]byte) {
	t.Helper()
	for _, arguments := range [][]string{
		{"status"}, {"status", "--output", "json"},
		{"events", "--limit", "100"}, {"events", "--limit", "100", "--output", "json"},
	} {
		result := runManagementCommand(paths.binary, environment, arguments...)
		if result.exitCode != 0 || len(result.stderr) != 0 {
			t.Fatalf("operational command %v = exit %d stdout %q stderr %q", arguments, result.exitCode, result.stdout, result.stderr)
		}
		private := append([][]byte{[]byte(paths.root), []byte(paths.upstream), []byte(paths.primary), []byte(paths.secondary)}, markers...)
		assertNoPrivateMarkers(t, result.stdout, private...)
		if arguments[0] == "events" && arguments[len(arguments)-1] == "json" {
			var envelope commandEnvelope
			var projection eventsProjection
			if err := json.Unmarshal(result.stdout, &envelope); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(envelope.Result, &projection); err != nil || len(projection.Events) != managementEventLimit {
				t.Fatalf("bounded events = %d err %v", len(projection.Events), err)
			}
		}
	}
	raw, err := os.ReadFile(paths.events)
	if err != nil {
		t.Fatal(err)
	}
	private := append([][]byte{[]byte(paths.root), []byte(paths.upstream), []byte(paths.primary), []byte(paths.secondary)}, markers...)
	assertNoPrivateMarkers(t, raw, private...)
}

func assertNoPrivateMarkers(t *testing.T, output []byte, markers ...[]byte) {
	t.Helper()
	for _, marker := range markers {
		if len(marker) > 0 && bytes.Contains(output, marker) {
			t.Fatalf("output retained private marker %q: %q", marker, output)
		}
	}
}

type lockedBuffer struct {
	sync.Mutex
	bytes.Buffer
}

func (buffer *lockedBuffer) Write(data []byte) (int, error) {
	buffer.Lock()
	defer buffer.Unlock()
	return buffer.Buffer.Write(data)
}

func (buffer *lockedBuffer) String() string {
	buffer.Lock()
	defer buffer.Unlock()
	return buffer.Buffer.String()
}

type daemonProcess struct {
	command *exec.Cmd
	done    chan error
	stderr  lockedBuffer
	stopMu  sync.Mutex
	stopped bool
}

func startManagementDaemon(t *testing.T, paths managementPaths, environment []string) *daemonProcess {
	t.Helper()
	process := &daemonProcess{done: make(chan error, 1)}
	process.command = exec.Command(paths.binary, "daemon")
	process.command.Env = environment
	process.command.Stderr = &process.stderr
	if err := process.command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { process.done <- process.command.Wait() }()
	t.Cleanup(func() { process.stop(t) })
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if connection, err := net.DialTimeout("unix", paths.control, 20*time.Millisecond); err == nil {
			_ = connection.Close()
			return process
		}
		select {
		case err := <-process.done:
			process.stopped = true
			t.Fatalf("daemon exited during startup: %v: %s", err, process.stderr.String())
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	process.stop(t)
	t.Fatalf("daemon control socket did not become ready: %s", process.stderr.String())
	return nil
}

func (process *daemonProcess) stop(t *testing.T) {
	t.Helper()
	process.stopMu.Lock()
	defer process.stopMu.Unlock()
	if process.stopped {
		return
	}
	process.stopped = true
	if err := process.command.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("signal daemon: %v", err)
	}
	select {
	case err := <-process.done:
		if err != nil {
			t.Errorf("daemon exit: %v: %s", err, process.stderr.String())
		}
	case <-time.After(4 * time.Second):
		_ = process.command.Process.Kill()
		<-process.done
		t.Errorf("daemon did not stop cleanly: %s", process.stderr.String())
	}
}

type terminalProcess struct {
	t             *testing.T
	command       *exec.Cmd
	controller    *os.File
	terminal      *os.File
	before        *unix.Termios
	done          chan error
	outputBytes   bytes.Buffer
	transcript    bytes.Buffer
	finished      bool
	currentWidth  uint16
	currentHeight uint16
}

func startManagementTUI(t *testing.T, binary string, environment []string, width, height uint16) *terminalProcess {
	t.Helper()
	controller, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	if err := pty.Setsize(terminal, &pty.Winsize{Rows: height, Cols: width}); err != nil {
		t.Fatal(err)
	}
	before, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	process := &terminalProcess{
		t: t, controller: controller, terminal: terminal, before: before,
		done: make(chan error, 1), currentWidth: width, currentHeight: height,
	}
	process.command = exec.Command(binary, "tui")
	process.command.Env = environment
	process.command.Stdin, process.command.Stdout, process.command.Stderr = terminal, terminal, terminal
	if err := process.command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { process.done <- process.command.Wait() }()
	t.Cleanup(func() {
		if !process.finished {
			_ = process.command.Process.Kill()
			<-process.done
		}
		_ = process.controller.Close()
		_ = process.terminal.Close()
	})
	process.waitFor("DASHBOARD")
	return process
}

func (process *terminalProcess) waitFor(value string) {
	process.t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		process.drain()
		if bytes.Contains(process.outputBytes.Bytes(), []byte(value)) {
			return
		}
		select {
		case err := <-process.done:
			process.finished = true
			process.t.Fatalf("TUI exited while waiting for %q: %v: %q", value, err, process.outputBytes.Bytes())
		default:
		}
		time.Sleep(time.Millisecond)
	}
	process.t.Fatalf("TUI output did not contain %q: %q", value, process.outputBytes.Bytes())
}

func (process *terminalProcess) write(value string) {
	process.t.Helper()
	process.outputBytes.Reset()
	if _, err := process.controller.Write([]byte(value)); err != nil {
		process.t.Fatal(err)
	}
}

func (process *terminalProcess) resize(width, height uint16) {
	process.t.Helper()
	process.outputBytes.Reset()
	process.currentWidth, process.currentHeight = width, height
	if err := pty.Setsize(process.terminal, &pty.Winsize{Rows: height, Cols: width}); err != nil {
		process.t.Fatal(err)
	}
	if err := process.command.Process.Signal(syscall.SIGWINCH); err != nil {
		process.t.Fatal(err)
	}
}

func (process *terminalProcess) interrupt() {
	process.t.Helper()
	process.outputBytes.Reset()
	if err := process.command.Process.Signal(os.Interrupt); err != nil {
		process.t.Fatal(err)
	}
}

func (process *terminalProcess) waitClean() {
	process.t.Helper()
	select {
	case err := <-process.done:
		process.finished = true
		if err != nil {
			process.t.Fatalf("TUI exit = %v: %q", err, process.outputBytes.Bytes())
		}
	case <-time.After(4 * time.Second):
		process.t.Fatal("TUI did not exit")
	}
	process.drain()
	after, err := unix.IoctlGetTermios(int(process.terminal.Fd()), unix.TCGETS)
	if err != nil {
		process.t.Fatal(err)
	}
	if !reflect.DeepEqual(after, process.before) {
		process.t.Fatalf("terminal mode changed after TUI exit\nbefore: %#v\nafter: %#v", process.before, after)
	}
	if !bytes.Contains(process.outputBytes.Bytes(), []byte("\x1b[?1049l")) {
		process.t.Fatalf("TUI did not restore the prior screen: %q", process.outputBytes.Bytes())
	}
}

func (process *terminalProcess) output() []byte {
	process.drain()
	return bytes.Clone(process.transcript.Bytes())
}

func (process *terminalProcess) drain() {
	buffer := make([]byte, 8192)
	for {
		poll := []unix.PollFd{{Fd: int32(process.controller.Fd()), Events: unix.POLLIN}}
		ready, err := unix.Poll(poll, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || ready == 0 || poll[0].Revents&unix.POLLIN == 0 {
			return
		}
		count, err := unix.Read(int(process.controller.Fd()), buffer)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || count == 0 {
			return
		}
		if err != nil {
			return
		}
		process.outputBytes.Write(buffer[:count])
		process.transcript.Write(buffer[:count])
	}
}

func waitForAbsent(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("path remained present: %s", path)
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path %s remained: %v", path, err)
	}
}
