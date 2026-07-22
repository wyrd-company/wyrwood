// ---
// relationships:
//   verifies: command-line-interface
// ---

package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/control"
	"github.com/wyrd-company/wyrwood/internal/daemon"
	"github.com/wyrd-company/wyrwood/internal/userservice"
)

const sampleFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type fakeClient struct {
	applyResult  control.ApplyResult
	applyErr     error
	keysResult   control.KeysResult
	keysErr      error
	statusResult control.StatusResult
	statusErr    error
	eventsResult control.EventsResult
	eventsErr    error
	calls        []string
	eventLimit   int
}

func (client *fakeClient) Apply() (control.ApplyResult, error) {
	client.calls = append(client.calls, "apply")
	return client.applyResult, client.applyErr
}

func (client *fakeClient) Keys() (control.KeysResult, error) {
	client.calls = append(client.calls, "keys")
	return client.keysResult, client.keysErr
}

func (client *fakeClient) Status() (control.StatusResult, error) {
	client.calls = append(client.calls, "status")
	return client.statusResult, client.statusErr
}

func (client *fakeClient) Events(limit int) (control.EventsResult, error) {
	client.calls = append(client.calls, "events")
	client.eventLimit = limit
	return client.eventsResult, client.eventsErr
}

func testDependencies(client controlClient) dependencies {
	return dependencies{
		initialize: func() (string, error) { return "/tmp/sample/config.yml", nil },
		defaultControlPath: func() (string, error) {
			return "/tmp/sample/control.sock", nil
		},
		newClient: func(path string) (controlClient, error) {
			if path != "/tmp/sample/control.sock" {
				return nil, fmt.Errorf("unexpected control path")
			}
			return client, nil
		},
		defaultDaemon: func() (daemon.Options, error) { return daemon.Options{}, nil },
		runDaemon:     func(context.Context, daemon.Options) error { return nil },
		manageService: func(action userservice.Action) (userservice.Result, error) {
			return userservice.Result{Action: action, Installed: true, Enabled: true, State: userservice.StateInactive}, nil
		},
	}
}

func execute(t *testing.T, args []string, deps dependencies) (int, string, string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run(args, &stdout, &stderr, deps)
	return exitCode, stdout.String(), stderr.String()
}

func TestRunHelpAndVersion(t *testing.T) {
	client := &fakeClient{}
	deps := testDependencies(client)
	tests := []struct {
		name       string
		args       []string
		wantOutput string
	}{
		{name: "no arguments", wantOutput: "Usage:"},
		{name: "help", args: []string{"--help"}, wantOutput: "daemon    Run the per-user daemon"},
		{name: "version", args: []string{"version"}, wantOutput: "wyrwood dev\n"},
		{name: "command help", args: []string{"events", "--help"}, wantOutput: "Usage: wyrwood events"},
		{name: "daemon help", args: []string{"daemon", "--help"}, wantOutput: "Usage: wyrwood daemon"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exitCode, stdout, stderr := execute(t, test.args, deps)
			if exitCode != exitSuccess || !strings.Contains(stdout, test.wantOutput) || stderr != "" {
				t.Fatalf("run() = (%d, %q, %q)", exitCode, stdout, stderr)
			}
		})
	}
}

func TestInitIsTheOnlyDirectConfigurationOperation(t *testing.T) {
	initialized := 0
	deps := testDependencies(&fakeClient{})
	deps.initialize = func() (string, error) {
		initialized++
		return "/tmp/sample/config.yml", nil
	}
	deps.defaultControlPath = func() (string, error) { panic("init resolved runtime state") }
	deps.newClient = func(string) (controlClient, error) { panic("init used control client") }

	exitCode, stdout, stderr := execute(t, []string{"init"}, deps)
	if exitCode != exitSuccess || stdout != "Created configuration at \"/tmp/sample/config.yml\".\n" || stderr != "" || initialized != 1 {
		t.Fatalf("init = (%d, %q, %q, calls %d)", exitCode, stdout, stderr, initialized)
	}
}

func TestRuntimeCommandsUseExactlyOneLocalControlOperation(t *testing.T) {
	for _, command := range []string{"apply", "keys", "status", "events"} {
		t.Run(command, func(t *testing.T) {
			client := successfulClient()
			deps := testDependencies(client)
			deps.initialize = func() (string, error) { panic("runtime command accessed configuration") }
			exitCode, _, stderr := execute(t, []string{command}, deps)
			if exitCode != exitSuccess || stderr != "" {
				t.Fatalf("run() = (%d, stderr %q)", exitCode, stderr)
			}
			if !reflect.DeepEqual(client.calls, []string{command}) {
				t.Fatalf("control calls = %v, want only %s", client.calls, command)
			}
		})
	}
}

func TestHumanOutputGolden(t *testing.T) {
	timestamp := time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)
	fingerprint := sampleFingerprint
	tests := []struct {
		name   string
		args   []string
		client *fakeClient
		want   string
	}{
		{name: "apply", args: []string{"apply"}, client: &fakeClient{applyResult: control.ApplyResult{Committed: true, Degraded: true, PendingCleanup: 2, PendingPermissions: 1}}, want: "Configuration applied (degraded=true, pending-cleanup=2, pending-permissions=1).\n"},
		{name: "keys", args: []string{"keys"}, client: &fakeClient{keysResult: control.KeysResult{Keys: []control.Key{{Fingerprint: sampleFingerprint, Display: "line\nlabel"}}}}, want: "FINGERPRINT\tDISPLAY\n" + sampleFingerprint + "\t\"line\\nlabel\"\n"},
		{name: "status", args: []string{"status"}, client: &fakeClient{statusResult: control.StatusResult{Daemon: control.HealthHealthy, Upstream: control.HealthUnavailable, Consumers: []control.ConsumerStatus{{ID: "unit\nrecord", Name: "sample", Listener: control.HealthDegraded, ActiveConnections: 3}}, Truncated: true}}, want: "Daemon: healthy\nUpstream: unavailable\nConsumers: 1\nTruncated: true\nID\tNAME\tLISTENER\tCONNECTIONS\n\"unit\\nrecord\"\t\"sample\"\tdegraded\t3\n"},
		{name: "policy denial event", args: []string{"events", "--limit", "4"}, client: &fakeClient{eventsResult: control.EventsResult{Events: []control.Event{{Timestamp: timestamp, ConsumerID: "unit", Operation: "sign", Fingerprint: &fingerprint, Outcome: "denied", LatencyNS: 12, ErrorCode: "policy-denied"}}}}, want: "TIMESTAMP\tCONSUMER\tOPERATION\tFINGERPRINT\tOUTCOME\tLATENCY_NS\tERROR\n2026-01-02T03:04:05.000000006Z\t\"unit\"\tsign\t" + sampleFingerprint + "\tdenied\t12\tpolicy-denied\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exitCode, stdout, stderr := execute(t, test.args, testDependencies(test.client))
			if exitCode != exitSuccess || stdout != test.want || stderr != "" {
				t.Fatalf("run() = (%d, %q, %q), want stdout %q", exitCode, stdout, stderr, test.want)
			}
		})
	}
}

func TestEmptyHumanResultsAreExplicit(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{command: "keys", want: "No upstream keys are available.\n"},
		{command: "events", want: "No operational events are retained.\n"},
	}
	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			exitCode, stdout, stderr := execute(t, []string{test.command}, testDependencies(successfulClient()))
			if exitCode != exitSuccess || stdout != test.want || stderr != "" {
				t.Fatalf("run() = (%d, %q, %q)", exitCode, stdout, stderr)
			}
		})
	}
}

func TestEmptyStructuredResultsAreEmptyArrays(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{command: "keys", want: "{\"version\":1,\"command\":\"keys\",\"ok\":true,\"result\":{\"keys\":[]}}\n"},
		{command: "events", want: "{\"version\":1,\"command\":\"events\",\"ok\":true,\"result\":{\"events\":[]}}\n"},
	}
	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			exitCode, stdout, stderr := execute(t, []string{test.command, "--output=json"}, testDependencies(successfulClient()))
			if exitCode != exitSuccess || stdout != test.want || stderr != "" {
				t.Fatalf("run() = (%d, %q, %q), want stdout %q", exitCode, stdout, stderr, test.want)
			}
			if strings.Contains(stdout, "null") {
				t.Fatalf("structured empty result contains null: %s", stdout)
			}
		})
	}
}

func TestStructuredOutputGolden(t *testing.T) {
	timestamp := time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)
	fingerprint := sampleFingerprint
	tests := []struct {
		name   string
		args   []string
		client *fakeClient
		want   string
	}{
		{name: "init", args: []string{"init", "--output", "json"}, client: &fakeClient{}, want: `{"version":1,"command":"init","ok":true,"result":{"path":"/tmp/sample/config.yml"}}` + "\n"},
		{name: "apply", args: []string{"apply", "--output=json"}, client: &fakeClient{applyResult: control.ApplyResult{Committed: true}}, want: `{"version":1,"command":"apply","ok":true,"result":{"committed":true,"degraded":false,"pending_cleanup":0,"pending_permissions":0}}` + "\n"},
		{name: "keys", args: []string{"keys", "--output", "json"}, client: &fakeClient{keysResult: control.KeysResult{Keys: []control.Key{{Fingerprint: sampleFingerprint, Display: "sample"}}}}, want: `{"version":1,"command":"keys","ok":true,"result":{"keys":[{"fingerprint":"` + sampleFingerprint + `","display":"sample"}]}}` + "\n"},
		{name: "status", args: []string{"status", "--output", "json"}, client: &fakeClient{statusResult: control.StatusResult{Daemon: control.HealthHealthy, Upstream: control.HealthUnavailable, Consumers: []control.ConsumerStatus{}, Truncated: false}}, want: `{"version":1,"command":"status","ok":true,"result":{"daemon":"healthy","upstream":"unavailable","consumers":[],"truncated":false}}` + "\n"},
		{name: "events", args: []string{"events", "--output", "json"}, client: &fakeClient{eventsResult: control.EventsResult{Events: []control.Event{{Timestamp: timestamp, ConsumerID: "unit", Operation: "sign", Fingerprint: &fingerprint, Outcome: "denied", LatencyNS: 12, ErrorCode: "policy-denied"}}}}, want: `{"version":1,"command":"events","ok":true,"result":{"events":[{"timestamp":"2026-01-02T03:04:05.000000006Z","consumer_id":"unit","operation":"sign","fingerprint":"` + sampleFingerprint + `","outcome":"denied","latency_ns":12,"error_code":"policy-denied"}]}}` + "\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exitCode, stdout, stderr := execute(t, test.args, testDependencies(test.client))
			if exitCode != exitSuccess || stdout != test.want || stderr != "" {
				t.Fatalf("run() = (%d, %q, %q), want stdout %q", exitCode, stdout, stderr, test.want)
			}
			var document map[string]any
			if err := json.Unmarshal([]byte(stdout), &document); err != nil {
				t.Fatalf("structured output is invalid JSON: %v", err)
			}
		})
	}
}

func TestStableFailureExitCodesAndStructuredErrors(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		err      error
		wantExit int
		wantCode string
	}{
		{name: "invalid configuration", command: "apply", err: &control.RemoteError{Code: control.ErrorApplyInvalid}, wantExit: exitApplyInvalid, wantCode: "apply-invalid"},
		{name: "apply failure", command: "apply", err: &control.RemoteError{Code: control.ErrorApplyFailed}, wantExit: exitRequestFailed, wantCode: "apply-failed"},
		{name: "upstream unavailable", command: "keys", err: &control.RemoteError{Code: control.ErrorUpstreamUnavailable}, wantExit: exitUpstream, wantCode: "upstream-unavailable"},
		{name: "resource limit", command: "keys", err: &control.RemoteError{Code: control.ErrorResourceLimit}, wantExit: exitRequestFailed, wantCode: "resource-limit"},
		{name: "bad request", command: "status", err: &control.RemoteError{Code: control.ErrorBadRequest}, wantExit: exitRequestFailed, wantCode: "request-rejected"},
		{name: "version mismatch", command: "status", err: &control.RemoteError{Code: control.ErrorUnsupportedVersion}, wantExit: exitDaemonUnavailable, wantCode: "incompatible-daemon"},
		{name: "internal", command: "status", err: &control.RemoteError{Code: control.ErrorInternal}, wantExit: exitRequestFailed, wantCode: "daemon-failed"},
		{name: "transport", command: "status", err: errors.New("private marker"), wantExit: exitDaemonUnavailable, wantCode: "daemon-unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := successfulClient()
			switch test.command {
			case "apply":
				client.applyErr = test.err
			case "keys":
				client.keysErr = test.err
			case "status":
				client.statusErr = test.err
			}
			exitCode, stdout, stderr := execute(t, []string{test.command, "--output", "json"}, testDependencies(client))
			if exitCode != test.wantExit || stdout != "" || strings.Contains(stderr, "private marker") {
				t.Fatalf("run() = (%d, %q, %q)", exitCode, stdout, stderr)
			}
			var envelope failureEnvelope
			if err := json.Unmarshal([]byte(stderr), &envelope); err != nil {
				t.Fatalf("error output is invalid JSON: %v", err)
			}
			if envelope.Version != 1 || envelope.Command != test.command || envelope.OK || envelope.Error.Code != test.wantCode || envelope.Error.Action == "" {
				t.Fatalf("failure envelope = %#v", envelope)
			}
		})
	}
}

func TestApplyNeverReportsUncommittedConfigurationAsSuccess(t *testing.T) {
	client := &fakeClient{applyResult: control.ApplyResult{Committed: false, Degraded: true}}
	exitCode, stdout, stderr := execute(t, []string{"apply"}, testDependencies(client))
	if exitCode != exitRequestFailed || stdout != "" || !strings.Contains(stderr, "did not commit") {
		t.Fatalf("run() = (%d, %q, %q)", exitCode, stdout, stderr)
	}
}

func TestInitFailuresAreCategoricalAndDoNotLeakRawErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode string
	}{
		{name: "validation", err: errors.New("private marker"), wantCode: "initialization-failed"},
		{name: "durability", err: &config.DurabilityError{Path: "/private/marker", Err: errors.New("private marker")}, wantCode: "durability-uncertain"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deps := testDependencies(&fakeClient{})
			deps.initialize = func() (string, error) { return "", test.err }
			exitCode, stdout, stderr := execute(t, []string{"init", "--output=json"}, deps)
			if exitCode != exitInitialization || stdout != "" || strings.Contains(stderr, "private marker") || !strings.Contains(stderr, `"code":"`+test.wantCode+`"`) {
				t.Fatalf("run() = (%d, %q, %q)", exitCode, stdout, stderr)
			}
		})
	}
}

func TestUnavailableDaemonPathIsCategorical(t *testing.T) {
	deps := testDependencies(&fakeClient{})
	deps.defaultControlPath = func() (string, error) { return "", errors.New("private marker") }
	exitCode, stdout, stderr := execute(t, []string{"status"}, deps)
	if exitCode != exitDaemonUnavailable || stdout != "" || strings.Contains(stderr, "private marker") || !strings.Contains(stderr, "daemon request") {
		t.Fatalf("run() = (%d, %q, %q)", exitCode, stdout, stderr)
	}
}

func TestUnavailableDaemonSocketThroughRealClient(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.sock")
	deps := testDependencies(nil)
	deps.defaultControlPath = func() (string, error) { return path, nil }
	deps.newClient = func(path string) (controlClient, error) { return control.NewClient(path) }

	exitCode, stdout, stderr := execute(t, []string{"status", "--output=json"}, deps)
	if exitCode != exitDaemonUnavailable || stdout != "" || !strings.Contains(stderr, `"code":"daemon-unavailable"`) {
		t.Fatalf("run() = (%d, %q, %q)", exitCode, stdout, stderr)
	}
}

func TestEventsLimitIsBoundedAndDefaultsToOneHundred(t *testing.T) {
	client := successfulClient()
	exitCode, _, _ := execute(t, []string{"events"}, testDependencies(client))
	if exitCode != exitSuccess || client.eventLimit != defaultEventLimit {
		t.Fatalf("default limit = %d, exit %d", client.eventLimit, exitCode)
	}
	for _, value := range []string{"0", "1001", "invalid"} {
		client = successfulClient()
		exitCode, stdout, stderr := execute(t, []string{"events", "--limit", value, "--output", "json"}, testDependencies(client))
		if exitCode != exitUsage || stdout != "" || !strings.Contains(stderr, `"code":"usage"`) || len(client.calls) != 0 {
			t.Fatalf("limit %q = (%d, %q, %q, calls %v)", value, exitCode, stdout, stderr, client.calls)
		}
	}
}

func TestLimitIsRejectedByEveryNonEventsManagementCommand(t *testing.T) {
	for _, command := range []string{"apply", "keys", "status"} {
		t.Run(command, func(t *testing.T) {
			client := successfulClient()
			exitCode, stdout, stderr := execute(t, []string{command, "--limit", "10", "--output=json"}, testDependencies(client))
			if exitCode != exitUsage || stdout != "" || !strings.Contains(stderr, `"code":"usage"`) {
				t.Fatalf("%s --limit = (%d, %q, %q)", command, exitCode, stdout, stderr)
			}
			if len(client.calls) != 0 {
				t.Fatalf("%s --limit made control calls %v", command, client.calls)
			}
		})
	}
}

func TestUnknownAndReservedCommandsHaveStableFailures(t *testing.T) {
	deps := testDependencies(&fakeClient{})
	for _, command := range []string{"tui"} {
		exitCode, stdout, stderr := execute(t, []string{command}, deps)
		if exitCode != exitOperational || stdout != "" || stderr != "wyrwood "+command+" is not implemented yet\n" {
			t.Fatalf("%s = (%d, %q, %q)", command, exitCode, stdout, stderr)
		}
	}
	exitCode, stdout, stderr := execute(t, []string{"unrecognized"}, deps)
	if exitCode != exitUsage || stdout != "" || stderr != "unknown command\nRun 'wyrwood help' for usage.\n" {
		t.Fatalf("unknown = (%d, %q, %q)", exitCode, stdout, stderr)
	}
}

func TestServiceActionsHaveStableHumanAndStructuredOutput(t *testing.T) {
	deps := testDependencies(&fakeClient{})
	var actions []userservice.Action
	deps.manageService = func(action userservice.Action) (userservice.Result, error) {
		actions = append(actions, action)
		return userservice.Result{Action: action, Installed: action != userservice.ActionRemove, Enabled: action == userservice.ActionInstall, State: userservice.StateInactive}, nil
	}
	exitCode, stdout, stderr := execute(t, []string{"service", "install"}, deps)
	if exitCode != exitSuccess || stdout != "Service install: installed=true, enabled=true, state=inactive.\n" || stderr != "" {
		t.Fatalf("human service = (%d, %q, %q)", exitCode, stdout, stderr)
	}
	exitCode, stdout, stderr = execute(t, []string{"service", "status", "--output=json"}, deps)
	want := "{\"version\":1,\"command\":\"service\",\"ok\":true,\"result\":{\"action\":\"status\",\"installed\":true,\"enabled\":false,\"state\":\"inactive\"}}\n"
	if exitCode != exitSuccess || stdout != want || stderr != "" || !reflect.DeepEqual(actions, []userservice.Action{userservice.ActionInstall, userservice.ActionStatus}) {
		t.Fatalf("structured service = (%d, %q, %q), actions %v", exitCode, stdout, stderr, actions)
	}
}

func TestServiceUsageAndFailuresAreCategorical(t *testing.T) {
	deps := testDependencies(&fakeClient{})
	for _, args := range [][]string{{"service"}, {"service", "unknown"}, {"service", "start", "--limit", "2"}} {
		exitCode, stdout, stderr := execute(t, append(args, "--output=json"), deps)
		if exitCode != exitUsage || stdout != "" || !strings.Contains(stderr, `"code":"usage"`) {
			t.Fatalf("usage %v = (%d, %q, %q)", args, exitCode, stdout, stderr)
		}
	}
	for _, test := range []struct {
		err  error
		code string
	}{
		{err: userservice.ErrUnavailable, code: "service-unavailable"},
		{err: userservice.ErrNotInstalled, code: "service-not-installed"},
		{err: errors.New("private marker"), code: "service-failed"},
	} {
		deps.manageService = func(userservice.Action) (userservice.Result, error) { return userservice.Result{}, test.err }
		exitCode, stdout, stderr := execute(t, []string{"service", "status", "--output=json"}, deps)
		if exitCode != exitOperational || stdout != "" || strings.Contains(stderr, "private marker") || !strings.Contains(stderr, `"code":"`+test.code+`"`) {
			t.Fatalf("service failure = (%d, %q, %q)", exitCode, stdout, stderr)
		}
	}
}

func TestServiceNotInstalledFailureIsAccurateAndActionable(t *testing.T) {
	deps := testDependencies(&fakeClient{})
	deps.manageService = func(userservice.Action) (userservice.Result, error) {
		return userservice.Result{}, userservice.ErrNotInstalled
	}
	exitCode, stdout, stderr := execute(t, []string{"service", "start"}, deps)
	wantHuman := "wyrwood service: the per-user service is not installed. Run 'wyrwood service install' before retrying.\n"
	if exitCode != exitOperational || stdout != "" || stderr != wantHuman {
		t.Fatalf("human = (%d, %q, %q)", exitCode, stdout, stderr)
	}
	exitCode, stdout, stderr = execute(t, []string{"service", "stop", "--output=json"}, deps)
	wantJSON := "{\"version\":1,\"command\":\"service\",\"ok\":false,\"error\":{\"code\":\"service-not-installed\",\"message\":\"the per-user service is not installed\",\"action\":\"Run 'wyrwood service install' before retrying.\"}}\n"
	if exitCode != exitOperational || stdout != "" || stderr != wantJSON {
		t.Fatalf("json = (%d, %q, %q)", exitCode, stdout, stderr)
	}
}

func TestServiceHelpDoesNotRunAnOperation(t *testing.T) {
	deps := testDependencies(&fakeClient{})
	deps.manageService = func(userservice.Action) (userservice.Result, error) { panic("service operation ran") }
	for _, args := range [][]string{{"service", "--help"}, {"service", "install", "--help"}} {
		exitCode, stdout, stderr := execute(t, args, deps)
		if exitCode != exitSuccess || !strings.Contains(stdout, "service install|remove|start|stop|status") || stderr != "" {
			t.Fatalf("help %v = (%d, %q, %q)", args, exitCode, stdout, stderr)
		}
	}
}

func TestDaemonDelegatesToRuntime(t *testing.T) {
	called := 0
	deps := testDependencies(&fakeClient{})
	deps.runDaemon = func(ctx context.Context, options daemon.Options) error {
		called++
		if ctx == nil {
			t.Fatal("daemon context is nil")
		}
		return nil
	}
	exitCode, stdout, stderr := execute(t, []string{"daemon"}, deps)
	if exitCode != exitSuccess || stdout != "" || stderr != "" || called != 1 {
		t.Fatalf("daemon = (%d, %q, %q, calls %d)", exitCode, stdout, stderr, called)
	}
}

func TestManagementCommandsTraverseTheRealControlClient(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("Chmod(): %v", err)
	}
	path := filepath.Join(directory, "control.sock")
	handler := &commandHandler{}
	server, err := control.Listen(path, uint32(os.Geteuid()), handler)
	if err != nil {
		t.Fatalf("control.Listen(): %v", err)
	}
	defer server.Close()
	deps := testDependencies(nil)
	deps.defaultControlPath = func() (string, error) { return path, nil }
	deps.newClient = func(path string) (controlClient, error) { return control.NewClient(path) }
	for _, command := range []string{"apply", "keys", "status", "events"} {
		exitCode, _, stderr := execute(t, []string{command}, deps)
		if exitCode != exitSuccess || stderr != "" {
			t.Fatalf("%s = (%d, stderr %q)", command, exitCode, stderr)
		}
	}
	if !reflect.DeepEqual(handler.calls, []string{"apply", "keys", "status", "events"}) {
		t.Fatalf("handler calls = %v", handler.calls)
	}
}

type commandHandler struct{ calls []string }

func (handler *commandHandler) Apply() (control.ApplyResult, control.ErrorCode) {
	handler.calls = append(handler.calls, "apply")
	return control.ApplyResult{Committed: true}, control.ErrorNone
}

func (handler *commandHandler) Keys() (control.KeysResult, control.ErrorCode) {
	handler.calls = append(handler.calls, "keys")
	return control.KeysResult{Keys: []control.Key{}}, control.ErrorNone
}

func (handler *commandHandler) Status() (control.StatusResult, control.ErrorCode) {
	handler.calls = append(handler.calls, "status")
	return control.StatusResult{Daemon: control.HealthHealthy, Upstream: control.HealthUnavailable, Consumers: []control.ConsumerStatus{}}, control.ErrorNone
}

func (handler *commandHandler) Events(int) (control.EventsResult, control.ErrorCode) {
	handler.calls = append(handler.calls, "events")
	return control.EventsResult{Events: []control.Event{}}, control.ErrorNone
}

func successfulClient() *fakeClient {
	return &fakeClient{
		applyResult:  control.ApplyResult{Committed: true},
		keysResult:   control.KeysResult{Keys: []control.Key{}},
		statusResult: control.StatusResult{Daemon: control.HealthHealthy, Upstream: control.HealthUnavailable, Consumers: []control.ConsumerStatus{}},
		eventsResult: control.EventsResult{Events: []control.Event{}},
	}
}
