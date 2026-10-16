// ---
// relationships:
//   verifies:
//     - linux-service
//     - engine-proxy
// ---

package linuxservice

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func calls(r *recorder) []string {
	values := make([]string, 0, len(r.calls))
	for _, call := range r.calls {
		values = append(values, strings.Join(call, " "))
	}
	return values
}

func TestUpgradeDropsStoredAndLiveDockerMembership(t *testing.T) {
	manager, runner := newManager(t, 0)
	if err := writeAtomic(manager.unitPath(), legacyUnit("/old/bin/wyrwood"), 0644); err != nil {
		t.Fatal(err)
	}
	runner.outputs["systemctl show --property=LoadState,ActiveState wyrwood-agent.service"] = "LoadState=loaded\nActiveState=active\n"
	runner.outputs["id -nG wyrwood"] = "wyrwood docker consumer-a consumer-b\n"
	runner.outputs["id -gn wyrwood"] = "wyrwood\n"
	_, err := manager.Manage("install")
	if err != nil {
		t.Fatal(err)
	}
	sequence := calls(runner)
	for _, must := range []string{"systemctl stop wyrwood-agent.service", "gpasswd --delete wyrwood docker", "systemctl daemon-reload", "systemctl start wyrwood-agent.service"} {
		if !slices.Contains(sequence, must) {
			t.Fatalf("missing %s: %v", must, sequence)
		}
	}
	stop := slices.Index(sequence, "systemctl stop wyrwood-agent.service")
	remove := slices.Index(sequence, "gpasswd --delete wyrwood docker")
	reload := slices.Index(sequence, "systemctl daemon-reload")
	start := slices.Index(sequence, "systemctl start wyrwood-agent.service")
	if !(stop < remove && remove < reload && reload < start) {
		t.Fatal("unsafe upgrade order", sequence)
	}
	for _, call := range sequence {
		if strings.HasPrefix(call, "usermod ") || strings.Contains(call, "gpasswd --delete wyrwood consumer") || strings.HasPrefix(call, "systemctl enable ") {
			t.Fatal("changed unrelated memberships or boot enablement", call)
		}
	}
	data, _ := os.ReadFile(manager.unitPath())
	if string(data) != string(Unit(manager.Executable)) || strings.Contains(string(data), "SupplementaryGroups=docker") {
		t.Fatal("legacy /etc unit shadows packaged privileges")
	}
	proxy, _ := os.ReadFile(manager.path("/etc/systemd/system/" + ProxyUnitName))
	if string(proxy) != string(ProxyUnit(manager.Executable)) {
		t.Fatal("proxy unit missing")
	}
}

func TestUpgradeInactiveServiceStaysInactive(t *testing.T) {
	manager, runner := newManager(t, 0)
	_ = writeAtomic(manager.unitPath(), legacyUnit(manager.Executable), 0644)
	runner.outputs["systemctl show --property=LoadState,ActiveState wyrwood-agent.service"] = "LoadState=loaded\nActiveState=inactive\n"
	if _, err := manager.Manage("install"); err != nil {
		t.Fatal(err)
	}
	for _, call := range calls(runner) {
		if strings.HasPrefix(call, "systemctl start ") || strings.HasPrefix(call, "systemctl stop ") || strings.HasPrefix(call, "systemctl enable ") || strings.HasPrefix(call, "gpasswd ") {
			t.Fatal("changed inactive state or absent membership", call)
		}
	}
}

func TestUnsafeOverridesAndFailuresNeverRestart(t *testing.T) {
	for _, failure := range []string{"systemctl stop wyrwood-agent.service", "gpasswd --delete wyrwood docker", "systemctl daemon-reload", "unsafe override", "systemctl start wyrwood-agent.service"} {
		t.Run(failure, func(t *testing.T) {
			manager, runner := newManager(t, 0)
			custom := string(legacyUnit(manager.Executable)) + "\n# operator customization\n"
			_ = writeAtomic(manager.unitPath(), []byte(custom), 0644)
			runner.outputs["systemctl show --property=LoadState,ActiveState wyrwood-agent.service"] = "LoadState=loaded\nActiveState=active\n"
			runner.outputs["id -nG wyrwood"] = "wyrwood docker other\n"
			if failure == "unsafe override" {
				runner.outputs["systemctl show --property=User,Group,SupplementaryGroups wyrwood-agent.service"] = "User=wyrwood\nGroup=wyrwood\nSupplementaryGroups=docker\n"
			} else {
				runner.failures[failure] = errors.New("failure")
			}
			if _, err := manager.Manage("install"); err == nil {
				t.Fatal("upgrade falsely reported success")
			}
			sequence := calls(runner)
			if failure != "systemctl start wyrwood-agent.service" && slices.Contains(sequence, "systemctl start wyrwood-agent.service") {
				t.Fatal("restarted unsafe installation", sequence)
			}
			data, _ := os.ReadFile(manager.unitPath())
			if string(data) != custom {
				t.Fatal("overwrote operator customization")
			}
		})
	}
}

func TestPackageUpgradeConsumesRootMarkerAndPreservesUnitEnablement(t *testing.T) {
	for _, active := range []bool{false, true} {
		manager, runner := newManager(t, 0)
		_ = writeAtomic(manager.packagedUnit(), Unit(PackagedExecutable), 0644)
		marker := manager.path("/run/wyrwood-upgrade/active")
		if active {
			_ = writeAtomic(marker, []byte{}, 0600)
		}
		if _, err := manager.Manage("package-install"); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(calls(runner), "systemctl start wyrwood-agent.service") != active {
			t.Fatal("package lost active state", calls(runner))
		}
		for _, call := range calls(runner) {
			if strings.HasPrefix(call, "systemctl enable ") {
				t.Fatal("package changed enablement")
			}
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatal("active marker retained after success")
		}
		if _, err := os.Stat(manager.unitPath()); !os.IsNotExist(err) {
			t.Fatal("package unnecessarily creates shadow unit")
		}
	}
}

func TestRemainingPrivilegedProcessBlocksUpgrade(t *testing.T) {
	manager, runner := newManager(t, 0)
	runner.outputs["getent passwd wyrwood"] = "wyrwood:x:51001:51002::/var/lib/wyrwood:/usr/sbin/nologin\n"
	runner.outputs["getent group docker"] = "docker:x:51003:\n"
	status := manager.path("/proc/123/status")
	if err := writeAtomic(status, []byte("Uid:\t51001\t51001\t51001\t51001\nGid:\t51002\t51002\t51002\t51002\nGroups:\t51003 51004\n"), 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Manage("install"); !errors.Is(err, ErrUnsafeInstallation) {
		t.Fatal("accepted privileged process", err)
	}
	if _, err := os.Stat(manager.unitPath()); !os.IsNotExist(err) {
		t.Fatal("modified installation before denying live process")
	}
	_ = os.RemoveAll(filepath.Dir(status))
	if _, err := manager.Manage("install"); err != nil {
		t.Fatal("did not recover after operator correction", err)
	}
}
