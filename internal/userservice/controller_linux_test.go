//go:build linux

// ---
// relationships:
//   verifies: linux-user-service
// ---

package userservice

import (
	"reflect"
	"strings"
	"testing"
)

type runnerCall struct {
	name string
	args []string
}

type fakeRunner struct {
	results []commandResult
	calls   []runnerCall
}

func (runner *fakeRunner) run(name string, args ...string) commandResult {
	runner.calls = append(runner.calls, runnerCall{name: name, args: append([]string(nil), args...)})
	if len(runner.results) == 0 {
		return commandResult{}
	}
	result := runner.results[0]
	runner.results = runner.results[1:]
	return result
}

func TestSystemdControllerUsesOnlyUnprivilegedArgvCommands(t *testing.T) {
	runner := &fakeRunner{}
	control := systemdController{runner: runner}
	operations := []func() error{
		control.reload,
		func() error { return control.enable("/tmp/sample path/wyrwood.service") },
		control.tryRestart, control.disableNow, control.start, control.stop,
	}
	for _, operation := range operations {
		if err := operation(); err != nil {
			t.Fatalf("operation: %v", err)
		}
	}
	want := [][]string{
		{"--user", "--no-pager", "--no-ask-password", "daemon-reload"},
		{"--user", "--no-pager", "--no-ask-password", "enable", "/tmp/sample path/wyrwood.service"},
		{"--user", "--no-pager", "--no-ask-password", "try-restart", UnitName},
		{"--user", "--no-pager", "--no-ask-password", "disable", "--now", UnitName},
		{"--user", "--no-pager", "--no-ask-password", "start", UnitName},
		{"--user", "--no-pager", "--no-ask-password", "stop", UnitName},
	}
	if len(runner.calls) != len(want) {
		t.Fatalf("calls = %v", runner.calls)
	}
	for index, call := range runner.calls {
		if call.name != "systemctl" || !reflect.DeepEqual(call.args, want[index]) {
			t.Fatalf("call %d = %#v, want %v", index, call, want[index])
		}
		joined := strings.Join(call.args, " ")
		if strings.Contains(joined, "sudo") || strings.Contains(joined, "--system") {
			t.Fatalf("privileged call = %#v", call)
		}
	}
}

func TestSystemdControllerProjectsClosedStatus(t *testing.T) {
	tests := []struct {
		name    string
		results []commandResult
		enabled bool
		state   State
		wantErr error
	}{
		{name: "active and enabled", results: []commandResult{{}, {exitCode: 1}, {}}, enabled: true, state: StateActive},
		{name: "inactive and disabled", results: []commandResult{{exitCode: 1}, {exitCode: 1}, {exitCode: 3}}, state: StateInactive},
		{name: "failed", results: []commandResult{{}, {}}, enabled: true, state: StateFailed},
		{name: "missing executable", results: []commandResult{{missing: true}}, wantErr: ErrUnavailable},
		{name: "manager failure", results: []commandResult{{exitCode: 4}}, wantErr: ErrController},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakeRunner{results: append([]commandResult(nil), test.results...)}
			enabled, state, err := (systemdController{runner: runner}).status()
			if enabled != test.enabled || state != test.state || err != test.wantErr {
				t.Fatalf("status = (%t, %q, %v)", enabled, state, err)
			}
			for _, call := range runner.calls {
				if call.name != "systemctl" || len(call.args) < 5 ||
					!reflect.DeepEqual(call.args[:4], []string{"--user", "--no-pager", "--no-ask-password", "--quiet"}) ||
					call.args[len(call.args)-1] != UnitName {
					t.Fatalf("status call = %#v", call)
				}
			}
		})
	}
}

func TestSystemdControllerCategorizesMutationFailures(t *testing.T) {
	if err := (systemdController{runner: &fakeRunner{results: []commandResult{{missing: true}}}}).reload(); err != ErrUnavailable {
		t.Fatalf("missing systemctl = %v", err)
	}
	if err := (systemdController{runner: &fakeRunner{results: []commandResult{{exitCode: 1}}}}).reload(); err != ErrController {
		t.Fatalf("failed user manager = %v", err)
	}
}
