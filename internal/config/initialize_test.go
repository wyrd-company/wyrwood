// ---
// relationships: {}
// ---

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestInitializeWritesOwnerOnlyConfiguration(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "configuration", "config.yml")
	lookup := lookupEnvironment(map[string]string{"SSH_AUTH_SOCK": "/run/upstream/agent.sock"})

	if _, err := initializeAt(path, lookup, publish); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	assertMode(t, filepath.Dir(path), 0o700)
	assertMode(t, path, 0o600)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	configuration, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse(initialized) error = %v", err)
	}
	if configuration.Upstream != "/run/upstream/agent.sock" {
		t.Fatalf("initialized upstream = %q", configuration.Upstream)
	}
	if len(configuration.Consumers) != 0 {
		t.Fatalf("initialized consumers = %v, want empty", configuration.Consumers)
	}
	if configuration.Timeouts != DefaultTimeouts() {
		t.Fatalf("initialized timeouts = %+v, want %+v", configuration.Timeouts, DefaultTimeouts())
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "config.yml" {
		t.Fatalf("configuration directory entries = %v, want only config.yml", entries)
	}
}

func TestInitializeNeverOverwritesExistingPath(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "configuration", "config.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	const original = "preserve this file\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := initializeAt(path, lookupEnvironment(map[string]string{"SSH_AUTH_SOCK": "/run/upstream/agent.sock"}), publish)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Initialize() error = %v, want already-exists error", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != original {
		t.Fatalf("existing configuration = %q, want %q", data, original)
	}
}

func TestInitializePublishesAtMostOneConcurrentConfiguration(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "configuration", "config.yml")
	lookup := lookupEnvironment(map[string]string{"SSH_AUTH_SOCK": "/run/upstream/agent.sock"})
	results := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			ready.Done()
			<-start
			_, err := initializeAt(path, lookup, publish)
			results <- err
		}()
	}
	ready.Wait()
	close(start)

	var successes, existing int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case strings.Contains(err.Error(), "already exists"):
			existing++
		default:
			t.Fatalf("Initialize() error = %v", err)
		}
	}
	if successes != 1 || existing != 1 {
		t.Fatalf("concurrent results = %d success, %d existing", successes, existing)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data); err != nil {
		t.Fatalf("published configuration is invalid: %v", err)
	}
}

func TestInitializeRejectsMissingOrInvalidEnvironment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values map[string]string
		want   string
	}{
		{name: "missing", values: map[string]string{}, want: "SSH_AUTH_SOCK"},
		{name: "empty", values: map[string]string{"SSH_AUTH_SOCK": ""}, want: "SSH_AUTH_SOCK"},
		{name: "relative", values: map[string]string{"SSH_AUTH_SOCK": "relative.sock"}, want: "upstream"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "configuration", "config.yml")
			_, err := initializeAt(path, lookupEnvironment(test.values), publish)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Initialize() error = %v, want %q", err, test.want)
			}
			if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("configuration path stat error = %v, want not exist", statErr)
			}
		})
	}
}

func TestInitializeRejectsRelativeDestination(t *testing.T) {
	t.Parallel()

	_, err := initializeAt("relative/config.yml", lookupEnvironment(map[string]string{"SSH_AUTH_SOCK": "/run/upstream/agent.sock"}), publish)
	if err == nil || !strings.Contains(err.Error(), "configuration path") {
		t.Fatalf("Initialize() error = %v, want configuration-path error", err)
	}
}

func TestInitializeUsesSSHAuthSockEnvironment(t *testing.T) {
	configurationRoot := filepath.Join(t.TempDir(), "configuration")
	t.Setenv("XDG_CONFIG_HOME", configurationRoot)
	t.Setenv("SSH_AUTH_SOCK", "/run/environment/agent.sock")

	path, err := Initialize()
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	wantPath := filepath.Join(configurationRoot, "wyrwood", "config.yml")
	if path != wantPath {
		t.Fatalf("Initialize() path = %q, want %q", path, wantPath)
	}
	configuration, err := Load(wantPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if configuration.Upstream != "/run/environment/agent.sock" {
		t.Fatalf("Initialize().Upstream = %q, want environment value", configuration.Upstream)
	}
}

func TestPublishIgnoresTemporaryCleanupFailureAfterPublication(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "configuration", "config.yml")
	cleanupFailure := errors.New("injected temporary cleanup failure")
	removeCalls := 0
	createdPath, err := initializeAt(
		path,
		lookupEnvironment(map[string]string{"SSH_AUTH_SOCK": "/run/upstream/agent.sock"}),
		func(path string, data []byte) (publication, error) {
			return publishWith(path, data, publicationOperations{
				remove: func(path string) error {
					removeCalls++
					if removeCalls == 1 {
						return cleanupFailure
					}
					return os.Remove(path)
				},
				syncDirectory: syncDirectory,
			})
		},
	)
	if err != nil {
		t.Fatalf("initializeAt() error = %v", err)
	}
	if createdPath != path {
		t.Fatalf("initializeAt() path = %q, want %q", createdPath, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if _, err := Parse(data); err != nil {
		t.Fatalf("published configuration is invalid: %v", err)
	}
	if removeCalls != 2 {
		t.Fatalf("temporary cleanup calls = %d, want explicit attempt and deferred backstop", removeCalls)
	}
}

func TestInitializeReturnsPublishedPathWhenDurabilityIsUncertain(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "configuration", "config.yml")
	durabilityFailure := errors.New("injected directory sync failure")
	createdPath, err := initializeAt(
		path,
		lookupEnvironment(map[string]string{"SSH_AUTH_SOCK": "/run/upstream/agent.sock"}),
		func(path string, data []byte) (publication, error) {
			return publishWith(path, data, publicationOperations{
				remove: os.Remove,
				syncDirectory: func(string) error {
					return durabilityFailure
				},
			})
		},
	)
	if createdPath != path {
		t.Fatalf("initializeAt() path = %q, want published path %q", createdPath, path)
	}
	var durabilityErr *DurabilityError
	if !errors.As(err, &durabilityErr) {
		t.Fatalf("initializeAt() error = %v, want DurabilityError", err)
	}
	if durabilityErr.Path != path {
		t.Fatalf("DurabilityError.Path = %q, want %q", durabilityErr.Path, path)
	}
	if !errors.Is(err, durabilityFailure) {
		t.Fatalf("initializeAt() error = %v, want wrapped sync failure", err)
	}
	if !strings.Contains(err.Error(), "published") || !strings.Contains(err.Error(), "durability is uncertain") {
		t.Fatalf("initializeAt() error = %q, want explicit publication uncertainty", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("published configuration Stat() error = %v", statErr)
	}
}

func TestInitializeReturnsNoPathForPrePublicationFailure(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "configuration", "config.yml")
	publicationFailure := errors.New("injected publication failure")
	createdPath, err := initializeAt(
		path,
		lookupEnvironment(map[string]string{"SSH_AUTH_SOCK": "/run/upstream/agent.sock"}),
		func(string, []byte) (publication, error) {
			return publication{}, publicationFailure
		},
	)
	if createdPath != "" {
		t.Fatalf("initializeAt() path = %q, want empty before publication", createdPath)
	}
	if !errors.Is(err, publicationFailure) {
		t.Fatalf("initializeAt() error = %v, want publication failure", err)
	}
	var durabilityErr *DurabilityError
	if errors.As(err, &durabilityErr) {
		t.Fatalf("initializeAt() error = %v, must not report durability uncertainty", err)
	}
}

func lookupEnvironment(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode(%q) = %04o, want %04o", path, got, want)
	}
}
