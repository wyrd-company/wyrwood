//go:build linux

// ---
// relationships:
//   implements: linux-user-service
// ---

package userservice

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type paths struct {
	unit        string
	executable  string
	environment environmentPaths
}

type environmentPaths struct {
	configuration string
	data          string
	state         string
	runtime       string
}

func defaultPaths() (paths, error) {
	configurationRoot, err := os.UserConfigDir()
	if err != nil {
		return paths{}, errors.New("resolve per-user service directory")
	}
	executable, err := os.Executable()
	if err != nil {
		return paths{}, errors.New("resolve current executable")
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return paths{}, errors.New("resolve current executable")
	}
	launcher, err := os.Stat(environmentLauncher)
	if err != nil || !launcher.Mode().IsRegular() || launcher.Mode().Perm()&0o111 == 0 {
		return paths{}, errors.New("resolve systemd executable launcher")
	}
	unit := filepath.Join(configurationRoot, "systemd", "user", UnitName)
	home, err := os.UserHomeDir()
	if err != nil {
		return paths{}, errors.New("resolve user home directory")
	}
	dataRoot := os.Getenv("XDG_DATA_HOME")
	if dataRoot == "" {
		dataRoot = filepath.Join(home, ".local", "share")
	}
	stateRoot := os.Getenv("XDG_STATE_HOME")
	if stateRoot == "" {
		stateRoot = filepath.Join(home, ".local", "state")
	}
	runtimeRoot := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeRoot == "" {
		runtimeRoot = filepath.Join("/run/user", fmt.Sprint(os.Geteuid()))
	}
	environment := environmentPaths{configuration: configurationRoot, data: dataRoot, state: stateRoot, runtime: runtimeRoot}
	for _, candidate := range []string{unit, environment.configuration, environment.data, environment.state, environment.runtime} {
		if err := validatePath(candidate); err != nil {
			return paths{}, err
		}
	}
	if _, err := systemdExecWord(executable); err != nil {
		return paths{}, err
	}
	return paths{unit: unit, executable: executable, environment: environment}, nil
}

func validatePath(path string) error {
	if hasUnsafeControl(path) ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("per-user service path is unsafe")
	}
	return nil
}

func hasUnsafeControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
