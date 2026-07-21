// ---
// relationships: {}
// ---

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Initialize creates a complete configuration at the platform-default path
// using the process's current SSH_AUTH_SOCK value. It never replaces an
// existing path and returns the created path.
func Initialize() (string, error) {
	path, err := DefaultPath()
	if err != nil {
		return "", fmt.Errorf("initialize configuration: %w", err)
	}
	return initializeAt(path, os.LookupEnv, publish)
}

type publisher func(path string, data []byte) (publication, error)

type publication struct {
	published bool
}

func initializeAt(path string, lookupEnv func(string) (string, bool), publishConfiguration publisher) (string, error) {
	upstream, present := lookupEnv("SSH_AUTH_SOCK")
	if !present || upstream == "" {
		return "", fieldError("SSH_AUTH_SOCK", "must name the initial upstream socket")
	}
	configuration := Config{
		Upstream:  upstream,
		Consumers: []Consumer{},
		Timeouts:  DefaultTimeouts(),
	}
	if err := Validate(configuration); err != nil {
		return "", fmt.Errorf("initialize configuration: %w", err)
	}

	data, err := marshal(configuration)
	if err != nil {
		return "", fmt.Errorf("initialize configuration: %w", err)
	}
	result, err := publishConfiguration(path, data)
	if err != nil {
		wrapped := fmt.Errorf("initialize configuration: %w", err)
		if result.published {
			return path, &DurabilityError{Path: path, Err: wrapped}
		}
		return "", wrapped
	}
	return path, nil
}

func marshal(configuration Config) ([]byte, error) {
	type persistedTimeouts struct {
		Connect string `yaml:"connect"`
		List    string `yaml:"list"`
		Replay  string `yaml:"replay"`
		Sign    string `yaml:"sign"`
	}
	type persistedConfig struct {
		Upstream  string            `yaml:"upstream"`
		Consumers []Consumer        `yaml:"consumers"`
		Timeouts  persistedTimeouts `yaml:"timeouts"`
	}
	return yaml.Marshal(persistedConfig{
		Upstream:  configuration.Upstream,
		Consumers: configuration.Consumers,
		Timeouts: persistedTimeouts{
			Connect: configuration.Timeouts.Connect.String(),
			List:    configuration.Timeouts.List.String(),
			Replay:  configuration.Timeouts.Replay.String(),
			Sign:    configuration.Timeouts.Sign.String(),
		},
	})
}

type publicationOperations struct {
	remove        func(string) error
	syncDirectory func(string) error
}

func publish(path string, data []byte) (publication, error) {
	return publishWith(path, data, publicationOperations{
		remove:        os.Remove,
		syncDirectory: syncDirectory,
	})
}

func publishWith(path string, data []byte, operations publicationOperations) (publication, error) {
	if !filepath.IsAbs(path) {
		return publication{}, fmt.Errorf("configuration path %q is not absolute", path)
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return publication{}, fmt.Errorf("create configuration directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return publication{}, fmt.Errorf("set configuration directory permissions: %w", err)
	}

	temporary, err := os.CreateTemp(directory, ".config-*")
	if err != nil {
		return publication{}, fmt.Errorf("create temporary configuration: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = operations.remove(temporaryPath) }()

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return publication{}, fmt.Errorf("set temporary configuration permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return publication{}, fmt.Errorf("write temporary configuration: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return publication{}, fmt.Errorf("sync temporary configuration: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return publication{}, fmt.Errorf("close temporary configuration: %w", err)
	}

	if err := os.Link(temporaryPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return publication{}, fmt.Errorf("configuration already exists at %s", path)
		}
		return publication{}, fmt.Errorf("publish configuration: %w", err)
	}
	result := publication{published: true}
	_ = operations.remove(temporaryPath)
	if err := operations.syncDirectory(directory); err != nil {
		return result, err
	}
	return result, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open configuration directory for sync: %w", err)
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync configuration directory: %w", err)
	}
	return nil
}
