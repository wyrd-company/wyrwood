//go:build linux

// ---
// relationships:
//   implements: linux-user-service
// ---

package userservice

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

const systemctlTimeout = 30 * time.Second

type commandResult struct {
	exitCode int
	missing  bool
}

type commandRunner interface {
	run(string, ...string) commandResult
}

type execRunner struct{}

func (execRunner) run(name string, arguments ...string) commandResult {
	ctx, cancel := context.WithTimeout(context.Background(), systemctlTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, name, arguments...)
	err := command.Run()
	if err == nil {
		return commandResult{}
	}
	if errors.Is(err, exec.ErrNotFound) {
		return commandResult{exitCode: -1, missing: true}
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return commandResult{exitCode: exitError.ExitCode()}
	}
	return commandResult{exitCode: -1}
}

type controller interface {
	reload() error
	enable(string) error
	tryRestart() error
	disableNow() error
	start() error
	stop() error
	status() (bool, State, error)
}

type systemdController struct{ runner commandRunner }

func (control systemdController) reload() error            { return control.mutate("daemon-reload") }
func (control systemdController) enable(path string) error { return control.mutate("enable", path) }
func (control systemdController) tryRestart() error        { return control.mutate("try-restart", UnitName) }
func (control systemdController) disableNow() error {
	return control.mutate("disable", "--now", UnitName)
}
func (control systemdController) start() error { return control.mutate("start", UnitName) }
func (control systemdController) stop() error  { return control.mutate("stop", UnitName) }

func (control systemdController) mutate(arguments ...string) error {
	result := control.invoke(arguments...)
	if result.missing {
		return ErrUnavailable
	}
	if result.exitCode != 0 {
		return ErrController
	}
	return nil
}

func (control systemdController) status() (bool, State, error) {
	enabled := control.invoke("--quiet", "is-enabled", UnitName)
	if enabled.missing {
		return false, "", ErrUnavailable
	}
	if enabled.exitCode != 0 && enabled.exitCode != 1 {
		return false, "", ErrController
	}
	failed := control.invoke("--quiet", "is-failed", UnitName)
	if failed.missing {
		return false, "", ErrUnavailable
	}
	if failed.exitCode == 0 {
		return enabled.exitCode == 0, StateFailed, nil
	}
	if failed.exitCode != 1 {
		return false, "", ErrController
	}
	active := control.invoke("--quiet", "is-active", UnitName)
	if active.missing {
		return false, "", ErrUnavailable
	}
	switch active.exitCode {
	case 0:
		return enabled.exitCode == 0, StateActive, nil
	case 3:
		return enabled.exitCode == 0, StateInactive, nil
	default:
		return false, "", ErrController
	}
}

func (control systemdController) invoke(arguments ...string) commandResult {
	prefix := []string{"--user", "--no-pager", "--no-ask-password"}
	return control.runner.run("systemctl", append(prefix, arguments...)...)
}
