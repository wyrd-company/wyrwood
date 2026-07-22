//go:build linux

// ---
// relationships:
//   verifies: control-interface
// ---

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLoadConfigurationRejectsSymlinkedAndNonRegularInputs(t *testing.T) {
	t.Run("leaf symlink", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.writeConfig(filepath.Join(fixture.root, "first", "agent.sock"))
		target := filepath.Join(filepath.Dir(fixture.options.ConfigPath), "target.yml")
		if err := os.Rename(fixture.options.ConfigPath, target); err != nil {
			t.Fatalf("rename config: %v", err)
		}
		if err := os.Symlink(filepath.Base(target), fixture.options.ConfigPath); err != nil {
			t.Fatalf("symlink config: %v", err)
		}
		if _, err := loadConfiguration(fixture.options.ConfigPath, fixture.options.UID); err == nil {
			t.Fatal("loadConfiguration() followed a leaf symlink")
		}
	})

	t.Run("parent symlink", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.writeConfig(filepath.Join(fixture.root, "first", "agent.sock"))
		directory := filepath.Dir(fixture.options.ConfigPath)
		realDirectory := directory + "-real"
		if err := os.Rename(directory, realDirectory); err != nil {
			t.Fatalf("rename config directory: %v", err)
		}
		if err := os.Symlink(filepath.Base(realDirectory), directory); err != nil {
			t.Fatalf("symlink config directory: %v", err)
		}
		if _, err := loadConfiguration(fixture.options.ConfigPath, fixture.options.UID); err == nil {
			t.Fatal("loadConfiguration() followed a parent symlink")
		}
	})

	t.Run("named pipe", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.writeConfig(filepath.Join(fixture.root, "first", "agent.sock"))
		if err := os.Remove(fixture.options.ConfigPath); err != nil {
			t.Fatalf("remove config: %v", err)
		}
		if err := unix.Mkfifo(fixture.options.ConfigPath, 0o600); err != nil {
			t.Fatalf("Mkfifo(): %v", err)
		}
		if _, err := loadConfiguration(fixture.options.ConfigPath, fixture.options.UID); err == nil {
			t.Fatal("loadConfiguration() accepted a named pipe")
		}
	})
}

func TestLoadConfigurationReadsTheValidatedOpenDescriptorAfterPathReplacement(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeConfig(filepath.Join(fixture.root, "first", "agent.sock"))
	originalPath := fixture.options.ConfigPath + ".opened"
	var hookErr error
	loaded, err := loadConfigurationWithHook(fixture.options.ConfigPath, fixture.options.UID, func() {
		hookErr = os.Rename(fixture.options.ConfigPath, originalPath)
		if hookErr == nil {
			hookErr = os.WriteFile(fixture.options.ConfigPath, []byte("unexpected: true\n"), 0o600)
		}
	})
	if hookErr != nil {
		t.Fatalf("replace configuration path: %v", hookErr)
	}
	if err != nil {
		t.Fatalf("loadConfigurationWithHook(): %v", err)
	}
	if loaded.Upstream != fixture.upstreamPath {
		t.Fatalf("loaded upstream = %q, want the pinned original", loaded.Upstream)
	}
}
