//go:build linux

// ---
// relationships:
//   verifies: linux-user-service
// ---

package userservice

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileUnitStoreInstallsAtomicallyAndIsIdempotent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "systemd", "user", UnitName)
	store := fileUnitStore{}
	uid := uint32(os.Geteuid())

	changed, err := store.install(path, []byte("first\n"), uid)
	if err != nil || !changed {
		t.Fatalf("first install = (%t, %v)", changed, err)
	}
	assertUnitFile(t, path, "first\n")
	changed, err = store.install(path, []byte("first\n"), uid)
	if err != nil || changed {
		t.Fatalf("idempotent install = (%t, %v)", changed, err)
	}
	changed, err = store.install(path, []byte("second\n"), uid)
	if err != nil || !changed {
		t.Fatalf("replacement install = (%t, %v)", changed, err)
	}
	assertUnitFile(t, path, "second\n")
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".wyrwood.service-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("replacement files = %v, %v", matches, err)
	}
}

func TestFileUnitStoreRemovalIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "systemd", "user", UnitName)
	store := fileUnitStore{}
	uid := uint32(os.Geteuid())
	if _, err := store.install(path, []byte("unit\n"), uid); err != nil {
		t.Fatalf("install: %v", err)
	}
	removed, err := store.remove(path, uid)
	if err != nil || !removed {
		t.Fatalf("first remove = (%t, %v)", removed, err)
	}
	removed, err = store.remove(path, uid)
	if err != nil || removed {
		t.Fatalf("second remove = (%t, %v)", removed, err)
	}
}

func TestPendingRestartIsBoundToTheUnitBytesThatCommitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "systemd", "user", UnitName)
	uid := uint32(os.Geteuid())
	store := fileUnitStore{}
	oldUnit := []byte("old unit\n")
	newUnit := []byte("new unit\n")
	if _, err := store.install(path, oldUnit, uid); err != nil {
		t.Fatalf("install old unit: %v", err)
	}
	if err := store.clearPending(path, uid); err != nil {
		t.Fatalf("clear initial pending marker: %v", err)
	}
	interrupted := fileUnitStore{beforeReplace: func() error { return errors.New("fixture pre-rename failure") }}
	if _, err := interrupted.install(path, newUnit, uid); err == nil {
		t.Fatal("interrupted install succeeded")
	}
	assertUnitFile(t, path, string(oldUnit))
	if pending, err := store.pending(path, uid); err != nil || pending {
		t.Fatalf("old unit pending after target-only marker = (%t, %v)", pending, err)
	}

	changed, err := store.install(path, oldUnit, uid)
	if err != nil || changed {
		t.Fatalf("rollback to installed bytes = (%t, %v)", changed, err)
	}
	if pending, err := store.pending(path, uid); err != nil || pending {
		t.Fatalf("obsolete target marker survived rollback = (%t, %v)", pending, err)
	}

	if _, err := interrupted.install(path, newUnit, uid); err == nil {
		t.Fatal("second interrupted install succeeded")
	}
	changed, err = store.install(path, newUnit, uid)
	if err != nil || !changed {
		t.Fatalf("retry changed unit = (%t, %v)", changed, err)
	}
	if pending, err := store.pending(path, uid); err != nil || !pending {
		t.Fatalf("committed target is not pending restart = (%t, %v)", pending, err)
	}
}

func TestFileUnitStoreRejectsUnsafeExistingEntries(t *testing.T) {
	uid := uint32(os.Geteuid())
	for _, setup := range []struct {
		name string
		make func(string) error
	}{
		{name: "symlink", make: func(path string) error { return os.Symlink("target", path) }},
		{name: "directory", make: func(path string) error { return os.Mkdir(path, 0o700) }},
		{name: "broad mode", make: func(path string) error { return os.WriteFile(path, []byte("unit"), 0o644) }},
	} {
		t.Run(setup.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, UnitName)
			if err := setup.make(path); err != nil {
				t.Fatalf("setup: %v", err)
			}
			if _, err := (fileUnitStore{}).install(path, []byte("replacement"), uid); err == nil {
				t.Fatal("unsafe entry was replaced")
			}
		})
	}
}

func TestFileUnitStoreRejectsSharedUnitDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(directory, 0o777); err != nil {
		t.Fatalf("Mkdir(): %v", err)
	}
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatalf("Chmod(): %v", err)
	}
	if _, err := (fileUnitStore{}).install(filepath.Join(directory, UnitName), []byte("unit"), uint32(os.Geteuid())); err == nil {
		t.Fatal("install accepted a group/world-writable directory")
	}
}

func TestFileUnitStoreRejectsSymlinkedDirectoryComponents(t *testing.T) {
	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatalf("Mkdir(): %v", err)
	}
	linkedDirectory := filepath.Join(root, "linked")
	if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
		t.Fatalf("Symlink(): %v", err)
	}
	path := filepath.Join(linkedDirectory, "user", UnitName)
	if _, err := (fileUnitStore{}).install(path, []byte("unit"), uint32(os.Geteuid())); err == nil {
		t.Fatal("install followed a symlinked directory component")
	}
	if _, err := os.Stat(filepath.Join(realDirectory, "user", UnitName)); !os.IsNotExist(err) {
		t.Fatalf("unit was redirected through symlink: %v", err)
	}
}

func TestValidatePathRejectsHostileEnvironmentValues(t *testing.T) {
	for _, path := range []string{"relative", "/tmp/root/../unit", "/tmp/line\nbreak", "/tmp/line\rbreak", "/tmp/zero\x00byte"} {
		if err := validatePath(path); err == nil {
			t.Fatalf("validatePath(%q) succeeded", path)
		}
	}
}

func assertUnitFile(t *testing.T, path, contents string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(): %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(): %v", err)
	}
	if string(data) != contents || !info.Mode().IsRegular() || info.Mode().Perm() != unitMode || ownerUID(info) != uint32(os.Geteuid()) {
		t.Fatalf("unit = (%q, %v, %#o, uid %d)", data, info.Mode(), info.Mode().Perm(), ownerUID(info))
	}
}
