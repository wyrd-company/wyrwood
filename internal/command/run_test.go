// ---
// relationships:
//   verifies: command-line-interface
// ---

package command

import (
	"bytes"
	"strings"
	"testing"
)

func runForTest(t *testing.T, deps dependencies, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	status := run(args, strings.NewReader(""), &stdout, &stderr, deps)
	return status, stdout.String(), stderr.String()
}

func TestVersionAndHelp(t *testing.T) {
	status, stdout, _ := runForTest(t, defaultDependencies(), "version")
	if status != exitSuccess || stdout != "wyrwood dev\n" {
		t.Fatalf("version = %d %q", status, stdout)
	}
	status, stdout, _ = runForTest(t, defaultDependencies(), "version", "--output", "json")
	if status != exitSuccess || stdout != "{\"version\":1,\"wyrwood\":\"dev\"}\n" {
		t.Fatalf("version json = %d %q", status, stdout)
	}
	status, stdout, _ = runForTest(t, defaultDependencies(), "help")
	if status != exitSuccess || !strings.Contains(stdout, "controller serve") || !strings.Contains(stdout, "agent login") {
		t.Fatalf("help = %d %q", status, stdout)
	}
}

func TestUsageFailuresAreCategorical(t *testing.T) {
	for _, args := range [][]string{
		{"bogus"},
		{"agent"},
		{"agent", "bogus"},
		{"controller"},
		{"controller", "serve", "extra"},
		{"controller", "host-key", "--output", "yaml"},
		{"version", "--limit", "5"},
	} {
		status, stdout, stderr := runForTest(t, defaultDependencies(), args...)
		if status != exitUsage || stdout != "" || stderr == "" {
			t.Errorf("%v = %d %q %q", args, status, stdout, stderr)
		}
	}
	status, _, stderr := runForTest(t, defaultDependencies(), "controller", "host-key", "--output", "json", "--bogus", "x")
	if status != exitUsage || stderr != "{\"version\":1,\"command\":\"controller host-key\",\"error\":\"usage\"}\n" {
		t.Fatalf("json usage = %d %q", status, stderr)
	}
}

func TestControllerHostKeyProjections(t *testing.T) {
	deps := defaultDependencies()
	deps.controllerHostKey = func(path string) (string, error) {
		if path != "/etc/wyrwood/controller.yml" {
			t.Fatalf("config path = %q", path)
		}
		return "SHA256:abc", nil
	}
	status, stdout, _ := runForTest(t, deps, "controller", "host-key")
	if status != exitSuccess || stdout != "SHA256:abc\n" {
		t.Fatalf("host-key = %d %q", status, stdout)
	}
	status, stdout, _ = runForTest(t, deps, "controller", "host-key", "--output", "json")
	if status != exitSuccess || stdout != "{\"version\":1,\"fingerprint\":\"SHA256:abc\"}\n" {
		t.Fatalf("host-key json = %d %q", status, stdout)
	}
	deps.controllerHostKey = func(string) (string, error) { return "", errConfiguration }
	status, _, stderr := runForTest(t, deps, "controller", "host-key", "--config", "/tmp/secret/path.yml")
	if status != exitOperational || strings.Contains(stderr, "/tmp/secret") {
		t.Fatalf("host-key failure = %d %q", status, stderr)
	}
}
