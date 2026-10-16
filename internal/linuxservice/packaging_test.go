// ---
// relationships:
//   verifies:
//     - linux-service
//     - engine-proxy
// ---

package linuxservice

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRootPackagePreinstallStopsBeforeReplacement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("run task test:engine-proxy:root for package hook ownership checks")
	}
	for _, sample := range []struct {
		name, state                         string
		stopFailure, showFailure, installed bool
	}{
		{name: "active", state: "active", installed: true},
		{name: "inactive", state: "inactive", installed: true},
		{name: "fresh", state: "inactive"},
		{name: "failed-stop", state: "active", stopFailure: true, installed: true},
		{name: "failed-inspection", state: "active", showFailure: true, installed: true},
	} {
		t.Run(sample.name, func(t *testing.T) {
			root := t.TempDir()
			for _, directory := range []string{"bin", "run/systemd/system", "usr/lib/systemd/system"} {
				if err := os.MkdirAll(filepath.Join(root, directory), 0755); err != nil {
					t.Fatal(err)
				}
			}
			if sample.installed {
				_ = os.WriteFile(filepath.Join(root, "usr/lib/systemd/system/"+UnitName), []byte("fixture"), 0644)
			}
			controller := `#!/bin/sh
printf '%s\n' "$*" >> "$FIXTURE_ROOT/commands"
case "$1" in
show)
 [ "$FIXTURE_SHOW_FAILURE" != true ] || exit 9
 printf 'LoadState=loaded\nActiveState=%s\n' "$FIXTURE_STATE"
 ;;
stop) [ "$FIXTURE_STOP_FAILURE" != true ] ;;
esac
`
			if err := os.WriteFile(filepath.Join(root, "bin/systemctl"), []byte(controller), 0755); err != nil {
				t.Fatal(err)
			}
			// Only relocate fixture filesystem roots; run the actual packaged script
			// with the real root-owned install(1), and a recording systemd boundary.
			script := repositoryFile(t, "packaging/preinstall.sh")
			for _, prefix := range []string{"/run/", "/etc/", "/usr/lib/"} {
				script = strings.ReplaceAll(script, prefix, root+prefix)
			}
			scriptPath := filepath.Join(root, "preinstall.sh")
			_ = os.WriteFile(scriptPath, []byte(script), 0700)
			command := exec.Command("/bin/sh", scriptPath)
			command.Env = []string{"PATH=" + filepath.Join(root, "bin") + ":/usr/bin:/bin", "FIXTURE_ROOT=" + root, "FIXTURE_STATE=" + sample.state, "FIXTURE_STOP_FAILURE=" + map[bool]string{false: "false", true: "true"}[sample.stopFailure], "FIXTURE_SHOW_FAILURE=" + map[bool]string{false: "false", true: "true"}[sample.showFailure]}
			output, err := command.CombinedOutput()
			if (err != nil) != (sample.stopFailure || sample.showFailure) {
				t.Fatalf("pre-install = %v %s", err, output)
			}
			calls, _ := os.ReadFile(filepath.Join(root, "commands"))
			if strings.Contains(string(calls), "stop "+UnitName) != (sample.installed && !sample.showFailure) {
				t.Fatal("old cgroup not stopped", string(calls))
			}
			marker := filepath.Join(root, "run/wyrwood-upgrade/active")
			_, err = os.Stat(marker)
			wantMarker := sample.installed && sample.state == "active" && !sample.showFailure
			if (err == nil) != wantMarker {
				t.Fatal("active state not preserved", err)
			}
			if sample.installed {
				info, err := os.Stat(filepath.Dir(marker))
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != 0 {
					t.Fatal("upgrade marker directory is not root-only")
				}
			}
		})
	}
}
