//go:build linux

// ---
// relationships:
//   verifies: linux-user-service
// ---

package userservice

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultPathsPinCanonicalPlatformLocations(t *testing.T) {
	root := t.TempDir()
	configuration := filepath.Join(root, `configuration space"slash\percent%cash$`)
	data := filepath.Join(root, "data")
	state := filepath.Join(root, "state")
	runtime := filepath.Join(root, "runtime")
	t.Setenv("XDG_CONFIG_HOME", configuration)
	t.Setenv("XDG_DATA_HOME", data)
	t.Setenv("XDG_STATE_HOME", state)
	t.Setenv("XDG_RUNTIME_DIR", runtime)

	resolved, err := defaultPaths()
	if err != nil {
		t.Fatalf("defaultPaths(): %v", err)
	}
	if resolved.unit != filepath.Join(configuration, "systemd", "user", UnitName) ||
		resolved.environment != (environmentPaths{configuration: configuration, data: data, state: state, runtime: runtime}) ||
		!filepath.IsAbs(resolved.executable) || filepath.Clean(resolved.executable) != resolved.executable {
		t.Fatalf("defaultPaths() = %#v", resolved)
	}
}

func TestDefaultPathsRejectHostileEnvironmentLocations(t *testing.T) {
	root := t.TempDir()
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "relative config", key: "XDG_CONFIG_HOME", value: "relative"},
		{name: "relative data", key: "XDG_DATA_HOME", value: "relative"},
		{name: "relative state", key: "XDG_STATE_HOME", value: "relative"},
		{name: "relative runtime", key: "XDG_RUNTIME_DIR", value: "relative"},
		{name: "config line feed", key: "XDG_CONFIG_HOME", value: "/tmp/line\nbreak"},
		{name: "data carriage return", key: "XDG_DATA_HOME", value: "/tmp/line\rbreak"},
		{name: "runtime tab", key: "XDG_RUNTIME_DIR", value: "/tmp/tab\tbreak"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("HOME", root)
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
			t.Setenv("XDG_DATA_HOME", filepath.Join(root, "data"))
			t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
			t.Setenv("XDG_RUNTIME_DIR", filepath.Join(root, "runtime"))
			t.Setenv(test.key, test.value)
			if _, err := defaultPaths(); err == nil {
				t.Fatal("defaultPaths() accepted hostile environment value")
			}
		})
	}
}

func TestDefaultPathsUseXDGFallbacks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, key := range []string{"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR"} {
		t.Setenv(key, "")
	}
	resolved, err := defaultPaths()
	if err != nil {
		t.Fatalf("defaultPaths(): %v", err)
	}
	if resolved.environment.configuration != filepath.Join(home, ".config") ||
		resolved.environment.data != filepath.Join(home, ".local", "share") ||
		resolved.environment.state != filepath.Join(home, ".local", "state") ||
		resolved.environment.runtime != filepath.Join("/run/user", fmt.Sprint(os.Geteuid())) {
		t.Fatalf("fallback environment = %#v", resolved.environment)
	}
}
