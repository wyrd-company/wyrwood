// ---
// relationships: {}
// ---

package command

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunHelp(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"--help"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("Run() exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(stdout.String(), "daemon    Run the per-user daemon") {
		t.Fatalf("Run() stdout = %q, want command help", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("Run() stderr = %q, want empty", stderr.String())
	}
}

func TestRunWithoutArgumentsShowsHelp(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run(nil, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("Run() exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("Run() stdout = %q, want usage help", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("Run() stderr = %q, want empty", stderr.String())
	}
}

func TestRunVersion(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"version"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("Run() exit code = %d, want 0", exitCode)
	}
	if stdout.String() != "wyrwood dev\n" {
		t.Fatalf("Run() stdout = %q, want version", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("Run() stderr = %q, want empty", stderr.String())
	}
}

func TestRunRejectsUnimplementedCommands(t *testing.T) {
	t.Parallel()

	commands := []string{
		"init",
		"apply",
		"keys",
		"status",
		"events",
		"tui",
		"service",
	}

	for _, name := range commands {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			var stderr bytes.Buffer

			exitCode := Run([]string{name}, &stdout, &stderr)

			if exitCode != 1 {
				t.Fatalf("Run() exit code = %d, want 1", exitCode)
			}
			if stdout.Len() != 0 {
				t.Fatalf("Run() stdout = %q, want empty", stdout.String())
			}
			wantError := "wyrwood " + name + " is not implemented yet\n"
			if stderr.String() != wantError {
				t.Fatalf("Run() stderr = %q, want %q", stderr.String(), wantError)
			}
		})
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"unrecognized"}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("Run() exit code = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("Run() stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), `unknown command "unrecognized"`) {
		t.Fatalf("Run() stderr = %q, want unknown-command error", stderr.String())
	}
}
