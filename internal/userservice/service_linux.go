//go:build linux

// ---
// relationships:
//   implements: linux-user-service
// ---

// Package userservice installs and controls Wyrwood's unprivileged systemd
// user service without constructing shell commands.
package userservice

import (
	"errors"
	"os"
)

type Action string

const (
	ActionInstall Action = "install"
	ActionRemove  Action = "remove"
	ActionStart   Action = "start"
	ActionStop    Action = "stop"
	ActionStatus  Action = "status"
)

type State string

const (
	StateNotInstalled State = "not-installed"
	StateInactive     State = "inactive"
	StateActive       State = "active"
	StateFailed       State = "failed"
)

type Result struct {
	Action    Action `json:"action"`
	Installed bool   `json:"installed"`
	Enabled   bool   `json:"enabled"`
	State     State  `json:"state"`
}

var (
	ErrUnavailable  = errors.New("systemd user manager is unavailable")
	ErrController   = errors.New("systemd user operation failed")
	ErrNotInstalled = errors.New("user service is not installed")
)

type DurabilityError struct{ Err error }

func (failure *DurabilityError) Error() string { return "user unit durability is uncertain" }
func (failure *DurabilityError) Unwrap() error { return failure.Err }

type manager struct {
	paths      func() (paths, error)
	store      unitStore
	controller controller
	locker     operationLocker
	uid        uint32
}

func defaultManager() manager {
	return manager{
		paths: defaultPaths, store: fileUnitStore{}, uid: uint32(os.Geteuid()),
		controller: systemdController{runner: execRunner{}}, locker: fileOperationLocker{},
	}
}

// Manage performs one systemd user-service action and returns a closed,
// path-free projection suitable for command output.
func Manage(action Action) (Result, error) {
	return defaultManager().manage(action)
}

func (service manager) manage(action Action) (Result, error) {
	resolved, err := service.paths()
	if err != nil {
		return Result{}, err
	}
	if action == ActionStatus {
		return service.projectStatus(resolved, action)
	}
	guard, err := service.locker.lock(resolved.unit, service.uid)
	if err != nil {
		return Result{}, err
	}
	result, operationErr := service.manageLocked(action, resolved)
	closeErr := guard.Close()
	if operationErr != nil {
		return Result{}, operationErr
	}
	if closeErr != nil {
		return Result{}, errors.New("release user service operation lock")
	}
	return result, nil
}

func (service manager) manageLocked(action Action, resolved paths) (Result, error) {
	switch action {
	case ActionInstall:
		return service.install(resolved)
	case ActionRemove:
		return service.remove(resolved)
	case ActionStart:
		return service.changeState(resolved, action, StateActive, service.controller.start)
	case ActionStop:
		return service.changeState(resolved, action, StateInactive, service.controller.stop)
	default:
		return Result{}, errors.New("unknown service action")
	}
}

func (service manager) install(resolved paths) (Result, error) {
	contents, err := renderUnit(resolved.executable, resolved.environment)
	if err != nil {
		return Result{}, err
	}
	_, err = service.store.install(resolved.unit, contents, service.uid)
	if err != nil {
		return Result{}, err
	}
	pendingRestart, err := service.store.pending(resolved.unit, service.uid)
	if err != nil {
		return Result{}, err
	}
	// Reload even when the bytes already match. A prior attempt may have
	// committed the atomic file replacement and failed before reloading.
	if err := service.controller.reload(); err != nil {
		return Result{}, err
	}
	if err := service.controller.enable(resolved.unit); err != nil {
		return Result{}, err
	}
	if pendingRestart {
		if err := service.controller.tryRestart(); err != nil {
			return Result{}, err
		}
		if err := service.store.clearPending(resolved.unit, service.uid); err != nil {
			return Result{}, err
		}
	}
	result, err := service.projectStatus(resolved, ActionInstall)
	if err != nil {
		return Result{}, err
	}
	if !result.Installed || !result.Enabled {
		return Result{}, ErrController
	}
	return result, nil
}

func (service manager) remove(resolved paths) (Result, error) {
	installed, err := service.store.inspect(resolved.unit, service.uid)
	if err != nil {
		return Result{}, err
	}
	if installed {
		if err := service.controller.disableNow(); err != nil {
			return Result{}, err
		}
	}
	_, err = service.store.remove(resolved.unit, service.uid)
	if err != nil {
		return Result{}, err
	}
	// Reload even when the unit is already absent. A prior attempt may have
	// unlinked it and failed before the manager observed that removal.
	if err := service.controller.reload(); err != nil {
		return Result{}, err
	}
	return Result{Action: ActionRemove, State: StateNotInstalled}, nil
}

func (service manager) changeState(resolved paths, action Action, expected State, operation func() error) (Result, error) {
	installed, err := service.store.inspect(resolved.unit, service.uid)
	if err != nil {
		return Result{}, err
	}
	if !installed {
		return Result{}, ErrNotInstalled
	}
	if err := operation(); err != nil {
		return Result{}, err
	}
	result, err := service.projectStatus(resolved, action)
	if err != nil {
		return Result{}, err
	}
	if result.State != expected {
		return Result{}, ErrController
	}
	return result, nil
}

func (service manager) projectStatus(resolved paths, action Action) (Result, error) {
	installed, err := service.store.inspect(resolved.unit, service.uid)
	if err != nil {
		return Result{}, err
	}
	if !installed {
		return Result{Action: action, State: StateNotInstalled}, nil
	}
	enabled, state, err := service.controller.status()
	if err != nil {
		return Result{}, err
	}
	return Result{Action: action, Installed: true, Enabled: enabled, State: state}, nil
}
