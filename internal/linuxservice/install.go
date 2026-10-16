// ---
// relationships:
//   implements:
//     - linux-service
//     - engine-proxy
// ---

package linuxservice

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ErrUnsafeInstallation requires root to correct an operator override or live
// process retaining raw Engine authority. It never includes a file's contents.
var ErrUnsafeInstallation = errors.New("unsafe service permissions; check local units, drop-ins, and remaining wyrwood processes before running service install")

const dependencyDropIn = "[Unit]\nWants=wyrwood-engine-proxy.service\nAfter=wyrwood-engine-proxy.service\n"

func (manager *Manager) hasSystemd() bool {
	if manager.Root != "" {
		return true
	} // an isolated manager fixture supplies its runner
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

func (manager *Manager) install(packaged bool) (State, error) {
	systemd := manager.hasSystemd()
	existed := manager.installed()
	active := false
	if systemd && existed && !packaged {
		state, err := manager.status()
		if err != nil {
			return "", err
		}
		active = state == StateActive
		if active {
			if _, err := manager.Run("systemctl", "stop", UnitName); err != nil {
				return "", ErrManager
			}
		}
	}
	marker := manager.path("/run/wyrwood-upgrade/active")
	if packaged {
		if _, err := os.Stat(marker); err == nil {
			active = true
		} else if !os.IsNotExist(err) {
			return "", ErrManager
		}
	}
	if err := manager.rejectPrivilegedProcesses(); err != nil {
		return "", err
	}
	if err := manager.ensureUsers(); err != nil {
		return "", err
	}
	if err := manager.reconcileAgentUnit(packaged); err != nil {
		return "", err
	}
	if !packaged {
		if err := writeAtomic(manager.path("/etc/systemd/system/"+ProxyUnitName), ProxyUnit(manager.Executable), 0644); err != nil {
			return "", ErrManager
		}
		if err := writeAtomic(manager.path("/etc/tmpfiles.d/wyrwood.conf"), Tmpfiles(), 0644); err != nil {
			return "", ErrManager
		}
	}
	if err := writeAtomic(manager.path("/etc/systemd/system/"+UnitName+".d/10-wyrwood-engine-proxy.conf"), []byte(dependencyDropIn), 0644); err != nil {
		return "", ErrManager
	}
	if _, err := manager.Run("systemd-tmpfiles", "--create", map[bool]string{false: "/etc/tmpfiles.d/wyrwood.conf", true: "/usr/lib/tmpfiles.d/wyrwood.conf"}[packaged]); err != nil {
		return "", ErrManager
	}
	if !systemd {
		return StateInactive, nil
	}
	if _, err := manager.Run("systemctl", "daemon-reload"); err != nil {
		return "", ErrManager
	}
	if err := manager.verifyEffectiveUnit(); err != nil {
		return "", err
	}
	if !packaged && !existed {
		if _, err := manager.Run("systemctl", "enable", UnitName); err != nil {
			return "", ErrManager
		}
	}
	if active {
		if _, err := manager.Run("systemctl", "start", UnitName); err != nil {
			return "", ErrManager
		}
	}
	if packaged {
		if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
			return "", ErrManager
		}
	}
	return manager.status()
}

func (manager *Manager) ensureUsers() error {
	if _, err := manager.Run("getent", "passwd", "wyrwood"); err != nil {
		if _, err := manager.Run("useradd", "--system", "--user-group", "--home-dir", "/var/lib/wyrwood", "--no-create-home", "--shell", "/usr/sbin/nologin", "wyrwood"); err != nil {
			return ErrManager
		}
	}
	if _, err := manager.Run("getent", "passwd", "wyrwood-engine"); err != nil {
		if _, err := manager.Run("useradd", "--system", "--gid", "wyrwood", "--home-dir", "/nonexistent", "--no-create-home", "--shell", "/usr/sbin/nologin", "wyrwood-engine"); err != nil {
			return ErrManager
		}
	}
	primary, err := manager.Run("id", "-gn", "wyrwood")
	if err != nil {
		return ErrManager
	}
	if strings.TrimSpace(primary) == "docker" {
		return ErrUnsafeInstallation
	}
	groups, err := manager.Run("id", "-nG", "wyrwood")
	if err != nil {
		return ErrManager
	}
	for _, group := range strings.Fields(groups) {
		if group == "docker" {
			if _, err := manager.Run("gpasswd", "--delete", "wyrwood", "docker"); err != nil {
				return ErrManager
			}
		}
	}
	for _, directory := range []struct{ path, mode, owner, group string }{
		{"/etc/wyrwood", "0755", "root", "root"},
		{"/var/lib/wyrwood", "0700", "wyrwood", "wyrwood"},
	} {
		if _, err := manager.Run("install", "-d", "-m", directory.mode, "-o", directory.owner, "-g", directory.group, directory.path); err != nil {
			return ErrManager
		}
	}
	return nil
}

func (manager *Manager) reconcileAgentUnit(packaged bool) error {
	data, err := os.ReadFile(manager.unitPath())
	if os.IsNotExist(err) {
		if packaged {
			return nil
		}
		if writeAtomic(manager.unitPath(), Unit(manager.Executable), 0644) != nil {
			return ErrManager
		}
		return nil
	}
	if err != nil {
		return ErrManager
	}
	// Recognize our own byte-for-byte generated unit, including its old executable
	// path. Operator-authored units remain intact and are checked after reload.
	executable := ""
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ExecStart=") && strings.HasSuffix(line, " agent daemon") {
			executable = strings.TrimSuffix(strings.TrimPrefix(line, "ExecStart="), " agent daemon")
		}
	}
	if executable != "" && (bytes.Equal(data, legacyUnit(executable)) || bytes.Equal(data, Unit(executable))) {
		if writeAtomic(manager.unitPath(), Unit(manager.Executable), 0644) != nil {
			return ErrManager
		}
	}
	return nil
}

func (manager *Manager) verifyEffectiveUnit() error {
	output, err := manager.Run("systemctl", "show", "--property=User,Group,SupplementaryGroups", UnitName)
	if err != nil {
		return ErrManager
	}
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = value
		}
	}
	if values["User"] != "wyrwood" || values["Group"] != "wyrwood" {
		return ErrUnsafeInstallation
	}
	for _, group := range strings.Fields(values["SupplementaryGroups"]) {
		if group == "docker" {
			return ErrUnsafeInstallation
		}
	}
	return nil
}

func (manager *Manager) rejectPrivilegedProcesses() error {
	account, err := manager.Run("getent", "passwd", "wyrwood")
	if err != nil {
		return nil
	} // the account does not yet exist on a fresh install
	fields := strings.Split(strings.TrimSpace(account), ":")
	if len(fields) < 4 {
		return nil
	}
	group, err := manager.Run("getent", "group", "docker")
	if err != nil {
		return nil
	}
	groupFields := strings.Split(strings.TrimSpace(group), ":")
	if len(groupFields) < 3 {
		return ErrManager
	}
	processes, err := os.ReadDir(manager.path("/proc"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return ErrManager
	}
	for _, process := range processes {
		if !process.IsDir() {
			continue
		}
		status, err := os.ReadFile(filepath.Join(manager.path("/proc"), process.Name(), "status"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return ErrManager
		}
		uidMatch, gidMatch := false, false
		for _, line := range strings.Split(string(status), "\n") {
			key, value, _ := strings.Cut(line, ":")
			for _, id := range strings.Fields(value) {
				if key == "Uid" && id == fields[2] {
					uidMatch = true
				}
				if (key == "Gid" || key == "Groups") && id == groupFields[2] {
					gidMatch = true
				}
			}
		}
		if uidMatch && gidMatch {
			return ErrUnsafeInstallation
		}
	}
	return nil
}
