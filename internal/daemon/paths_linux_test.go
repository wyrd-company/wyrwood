//go:build linux

// ---
// relationships:
//   verifies: linux-per-user-agent-proxy
// ---

package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultOptionsUsePerUserXDGLocations(t *testing.T) {
	root := t.TempDir()
	configurationRoot := filepath.Join(root, "configuration")
	runtimeRoot := filepath.Join(root, "runtime")
	stateRoot := filepath.Join(root, "state")
	t.Setenv("XDG_CONFIG_HOME", configurationRoot)
	t.Setenv("XDG_RUNTIME_DIR", runtimeRoot)
	t.Setenv("XDG_STATE_HOME", stateRoot)

	options, err := DefaultOptions()
	if err != nil {
		t.Fatalf("DefaultOptions(): %v", err)
	}
	if options.ConfigPath != filepath.Join(configurationRoot, "wyrwood", "config.yml") ||
		options.ControlPath != filepath.Join(runtimeRoot, "wyrwood", "control.sock") ||
		options.EventPath != filepath.Join(stateRoot, "wyrwood", "events.bin") ||
		options.UID != uint32(os.Geteuid()) {
		t.Fatalf("DefaultOptions() = %#v", options)
	}
}
