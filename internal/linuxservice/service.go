// ---
// relationships:
//   implements: linux-service
//   uses: run-the-agent-as-a-system-service
// ---

// Package linuxservice manages the agent's systemd system unit for package
// and release archive installations. Packages install the same unit
// and tmpfiles entry and create the service user in their post-install
// scripts.
package linuxservice

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// UnitName is the agent's system unit.
const UnitName = "wyrwood-agent.service"

// ProxyUnitName is the separately privileged Engine boundary.
const ProxyUnitName = "wyrwood-engine-proxy.service"

// PackagedExecutable is where packages install the executable.
const PackagedExecutable = "/usr/bin/wyrwood"

var (
	// ErrRequiresRoot means the action needs root.
	ErrRequiresRoot = errors.New("requires root")
	// ErrManager means the service manager or a system tool failed.
	ErrManager = errors.New("service manager operation failed")
	// ErrNotInstalled means start or stop was asked of a unit that is not installed.
	ErrNotInstalled = errors.New("unit not installed")
)

// State is the closed status vocabulary.
type State string

const (
	StateNotInstalled State = "not-installed"
	StateInactive     State = "inactive"
	StateActive       State = "active"
	StateFailed       State = "failed"
)

// Unit returns the exact unit bytes for an executable path.
func Unit(executable string) []byte {
	return []byte(`[Unit]
Description=Wyrwood agent
Documentation=https://github.com/wyrd-company/wyrwood
After=docker.service network-online.target wyrwood-engine-proxy.service
Wants=network-online.target wyrwood-engine-proxy.service

[Service]
Type=simple
ExecStart=` + executable + ` agent daemon
User=wyrwood
Group=wyrwood
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/wyrwood /run/wyrwood
RuntimeDirectory=wyrwood
RuntimeDirectoryPreserve=yes
Restart=on-failure
RestartSec=2s
TimeoutStopSec=15s

[Install]
WantedBy=multi-user.target
`)
}

// ProxyUnit runs the authorization boundary under its own UID.
func ProxyUnit(executable string) []byte {
	return []byte(`[Unit]
Description=Wyrwood filtering Engine proxy
Documentation=https://github.com/wyrd-company/wyrwood
After=docker.service
PartOf=wyrwood-agent.service

[Service]
Type=simple
ExecStart=` + executable + ` agent engine-proxy
User=wyrwood-engine
Group=wyrwood
SupplementaryGroups=docker
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=
ReadWritePaths=/run/wyrwood-engine
RuntimeDirectory=wyrwood-engine
RuntimeDirectoryMode=0750
Restart=on-failure
RestartSec=2s
TimeoutStopSec=15s
`)
}

// Tmpfiles retains consumer directories and creates a separate protected proxy root.
func Tmpfiles() []byte {
	return []byte("d /run/wyrwood 0755 wyrwood wyrwood -\nd /run/wyrwood-engine 0750 wyrwood-engine wyrwood -\n")
}

func legacyUnit(executable string) []byte {
	return []byte(`[Unit]
Description=Wyrwood agent
Documentation=https://github.com/wyrd-company/wyrwood
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=` + executable + ` agent daemon
User=wyrwood
Group=wyrwood
SupplementaryGroups=docker
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/wyrwood /run/wyrwood
RuntimeDirectory=wyrwood
RuntimeDirectoryPreserve=yes
Restart=on-failure
RestartSec=2s
TimeoutStopSec=15s

[Install]
WantedBy=multi-user.target
`)
}

// Runner runs one system command without a shell and returns its output.
type Runner func(name string, arguments ...string) (string, error)

// ExecRunner runs commands with os/exec.
func ExecRunner(name string, arguments ...string) (string, error) {
	output, err := exec.Command(name, arguments...).CombinedOutput()
	return string(output), err
}

// Manager manages the unit. Root prefixes every path it writes, for tests.
type Manager struct {
	Root       string
	Executable string
	Run        Runner
	EUID       func() int
}

// NewManager returns a manager for the running executable.
func NewManager() (*Manager, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, ErrManager
	}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}
	return &Manager{Executable: executable, Run: ExecRunner, EUID: os.Geteuid}, nil
}

func (manager *Manager) path(path string) string { return filepath.Join(manager.Root, path) }

func (manager *Manager) unitPath() string {
	return manager.path("/etc/systemd/system/" + UnitName)
}

func (manager *Manager) packagedUnit() string {
	return manager.path("/usr/lib/systemd/system/" + UnitName)
}

// Manage performs one action and returns the resulting state.
func (manager *Manager) Manage(action string) (State, error) {
	if action != "status" && manager.EUID() != 0 {
		return "", ErrRequiresRoot
	}
	switch action {
	case "install":
		return manager.install(false)
	case "package-install":
		return manager.install(true)
	case "remove":
		return manager.remove()
	case "start", "stop":
		if !manager.installed() {
			return "", ErrNotInstalled
		}
		arguments := []string{action, UnitName}
		if action == "start" {
			arguments = []string{"enable", "--now", UnitName}
		}
		if _, err := manager.Run("systemctl", arguments...); err != nil {
			return "", ErrManager
		}
		return manager.status()
	case "status":
		return manager.status()
	}
	return "", ErrManager
}

func (manager *Manager) installed() bool {
	for _, path := range []string{manager.unitPath(), manager.packagedUnit()} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

func (manager *Manager) remove() (State, error) {
	if !manager.installed() {
		return StateNotInstalled, nil
	}
	if _, err := manager.Run("systemctl", "disable", "--now", UnitName); err != nil {
		return "", ErrManager
	}
	for _, location := range []string{"/etc/systemd/system/", "/usr/lib/systemd/system/"} {
		if _, err := os.Stat(manager.path(location + ProxyUnitName)); err == nil {
			if _, err := manager.Run("systemctl", "stop", ProxyUnitName); err != nil {
				return "", ErrManager
			}
			break
		} else if !os.IsNotExist(err) {
			return "", ErrManager
		}
	}
	if err := os.Remove(manager.unitPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", ErrManager
	}
	if err := os.Remove(manager.path("/etc/systemd/system/" + ProxyUnitName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", ErrManager
	}
	if err := os.Remove(manager.path("/etc/systemd/system/" + UnitName + ".d/10-wyrwood-engine-proxy.conf")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", ErrManager
	}
	if err := os.Remove(manager.path("/etc/tmpfiles.d/wyrwood.conf")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", ErrManager
	}
	if _, err := manager.Run("systemctl", "daemon-reload"); err != nil {
		return "", ErrManager
	}
	return manager.status()
}

func (manager *Manager) status() (State, error) {
	if !manager.installed() {
		return StateNotInstalled, nil
	}
	output, err := manager.Run("systemctl", "show", "--property=LoadState,ActiveState", UnitName)
	if err != nil {
		return "", ErrManager
	}
	properties := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			properties[key] = value
		}
	}
	switch {
	case properties["LoadState"] == "not-found":
		return StateNotInstalled, nil
	case properties["ActiveState"] == "active" || properties["ActiveState"] == "reloading" || properties["ActiveState"] == "activating":
		return StateActive, nil
	case properties["ActiveState"] == "failed":
		return StateFailed, nil
	default:
		return StateInactive, nil
	}
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace %s: %w", filepath.Base(path), err)
	}
	return nil
}
