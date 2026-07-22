//go:build linux

// ---
// relationships:
//   verifies: linux-user-service
// ---

package userservice

import (
	"io"
	"os"
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
		result  commandResult
		enabled bool
		state   State
		wantErr error
	}{
		{name: "active and enabled", result: commandResult{output: statusOutput("enabled", StateActive)}, enabled: true, state: StateActive},
		{name: "inactive and disabled", result: commandResult{output: statusOutput("disabled", StateInactive)}, state: StateInactive},
		{name: "failed and enabled", result: commandResult{output: statusOutput("enabled", StateFailed)}, enabled: true, state: StateFailed},
		{name: "missing executable", result: commandResult{missing: true}, wantErr: ErrUnavailable},
		{name: "manager failure", result: commandResult{exitCode: 1}, wantErr: ErrController},
		{name: "bounded output overflow", result: commandResult{output: statusOutput("enabled", StateActive), overflow: true}, wantErr: ErrController},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakeRunner{results: []commandResult{test.result}}
			enabled, state, err := (systemdController{runner: runner}).status()
			if enabled != test.enabled || state != test.state || err != test.wantErr {
				t.Fatalf("status = (%t, %q, %v)", enabled, state, err)
			}
			want := runnerCall{name: "systemctl", args: []string{
				"--user", "--no-pager", "--no-ask-password", "show", UnitName,
				"--property=LoadState,UnitFileState,ActiveState",
			}}
			if !reflect.DeepEqual(runner.calls, []runnerCall{want}) {
				t.Fatalf("status calls = %#v, want %#v", runner.calls, []runnerCall{want})
			}
		})
	}
}

func TestParseStatusProjectionAcceptsOnlyClosedValidStates(t *testing.T) {
	for _, enabledValue := range []string{"enabled", "disabled"} {
		for _, state := range []State{StateActive, StateInactive, StateFailed} {
			t.Run(enabledValue+" "+string(state), func(t *testing.T) {
				enabled, actual, err := parseStatusProjection(statusOutput(enabledValue, state))
				if err != nil || enabled != (enabledValue == "enabled") || actual != state {
					t.Fatalf("projection = (%t, %q, %v)", enabled, actual, err)
				}
			})
		}
	}
}

func TestParseStatusProjectionRejectsMalformedOrInconsistentOutput(t *testing.T) {
	valid := string(statusOutput("enabled", StateActive))
	tests := map[string]string{
		"empty":               "",
		"missing newline":     strings.TrimSuffix(valid, "\n"),
		"carriage return":     strings.Replace(valid, "\n", "\r\n", 1),
		"duplicate":           valid + "ActiveState=active\n",
		"unknown":             valid + "PrivateState=value\n",
		"missing":             "LoadState=loaded\nActiveState=active\n",
		"malformed":           "LoadState=loaded\nUnitFileState\nActiveState=active\n",
		"not found":           "LoadState=not-found\nUnitFileState=disabled\nActiveState=inactive\n",
		"not loaded":          "LoadState=not-loaded\nUnitFileState=disabled\nActiveState=inactive\n",
		"unsupported enabled": "LoadState=loaded\nUnitFileState=static\nActiveState=inactive\n",
		"transitional state":  "LoadState=loaded\nUnitFileState=enabled\nActiveState=activating\n",
		"blank value":         "LoadState=loaded\nUnitFileState=\nActiveState=inactive\n",
	}
	for name, output := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseStatusProjection([]byte(output)); err != ErrController {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if _, _, err := parseStatusProjection([]byte(strings.Repeat("x", maximumSystemctlOutput+1))); err != ErrController {
		t.Fatalf("oversized error = %v", err)
	}
}

func TestExecRunnerBoundsOutputAndCategorizesExecution(t *testing.T) {
	runner := execRunner{}
	small := runner.run(os.Args[0], "-test.run=^TestExecRunnerHelper$", "--", "small")
	if small.exitCode != 0 || small.missing || small.overflow || string(small.output) != "sample\n" {
		t.Fatalf("small result = %#v", small)
	}
	large := runner.run(os.Args[0], "-test.run=^TestExecRunnerHelper$", "--", "large")
	if large.exitCode != 0 || large.missing || !large.overflow || len(large.output) != maximumSystemctlOutput {
		t.Fatalf("large result = %#v", large)
	}
	failed := runner.run(os.Args[0], "-test.run=^TestExecRunnerHelper$", "--", "fail")
	if failed.exitCode != 9 || failed.missing || string(failed.output) != "private marker\n" {
		t.Fatalf("failed result = %#v", failed)
	}
	missing := runner.run("/path/that/does/not/exist")
	if !missing.missing || missing.exitCode != -1 {
		t.Fatalf("missing result = %#v", missing)
	}
}

func TestExecRunnerHelper(t *testing.T) {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "small":
		_, _ = io.WriteString(os.Stdout, "sample\n")
		os.Exit(0)
	case "large":
		_, _ = io.WriteString(os.Stdout, strings.Repeat("x", maximumSystemctlOutput+100))
		os.Exit(0)
	case "fail":
		_, _ = io.WriteString(os.Stdout, "private marker\n")
		os.Exit(9)
	}
}

func statusOutput(enabled string, state State) []byte {
	return []byte("UnitFileState=" + enabled + "\nActiveState=" + string(state) + "\nLoadState=loaded\n")
}

func TestSystemdControllerCategorizesMutationFailures(t *testing.T) {
	if err := (systemdController{runner: &fakeRunner{results: []commandResult{{missing: true}}}}).reload(); err != ErrUnavailable {
		t.Fatalf("missing systemctl = %v", err)
	}
	if err := (systemdController{runner: &fakeRunner{results: []commandResult{{exitCode: 1}}}}).reload(); err != ErrController {
		t.Fatalf("failed user manager = %v", err)
	}
}
