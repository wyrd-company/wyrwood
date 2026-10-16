// ---
// relationships:
//   verifies: linux-service
// ---

package linuxservice

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const expectedUnit = `[Unit]
Description=Wyrwood agent
Documentation=https://github.com/wyrd-company/wyrwood
After=docker.service network-online.target wyrwood-engine-proxy.service
Wants=network-online.target wyrwood-engine-proxy.service

[Service]
Type=simple
ExecStart=/usr/bin/wyrwood agent daemon
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
`

func repositoryFile(t *testing.T, path string) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", path))
	if err != nil {
		t.Fatal(err)
	}
	// Drop the leading relationship header comment.
	text := string(data)
	if strings.HasPrefix(text, "# ---\n") {
		end := strings.Index(text[5:], "# ---\n")
		text = text[5+end+6:]
	}
	return text
}

func TestUnitAndPackagedFilesMatchExactly(t *testing.T) {
	if string(Unit(PackagedExecutable)) != expectedUnit {
		t.Fatalf("Unit() =\n%s", Unit(PackagedExecutable))
	}
	if packaged := repositoryFile(t, "packaging/wyrwood-agent.service"); packaged != expectedUnit {
		t.Fatalf("packaged unit differs:\n%s", packaged)
	}
	if packaged := repositoryFile(t, "packaging/wyrwood.tmpfiles"); packaged != string(Tmpfiles()) {
		t.Fatalf("packaged tmpfiles differs:\n%s", packaged)
	}
	if got := repositoryFile(t, "packaging/wyrwood-engine-proxy.service"); got != string(ProxyUnit(PackagedExecutable)) {
		t.Fatalf("packaged proxy unit differs:\n%s", got)
	}
	postinstall := repositoryFile(t, "packaging/postinstall.sh")
	if !strings.Contains(postinstall, "/usr/bin/wyrwood agent service package-install") {
		t.Fatal("package does not use shared upgrade transition")
	}

}

type recorder struct {
	calls    [][]string
	failures map[string]error
	outputs  map[string]string
}

func (recorder *recorder) run(name string, arguments ...string) (string, error) {
	call := append([]string{name}, arguments...)
	recorder.calls = append(recorder.calls, call)
	key := strings.Join(call, " ")
	return recorder.outputs[key], recorder.failures[key]
}

func newManager(t *testing.T, euid int) (*Manager, *recorder) {
	t.Helper()
	runner := &recorder{failures: map[string]error{}, outputs: map[string]string{"systemctl show --property=User,Group,SupplementaryGroups wyrwood-agent.service": "User=wyrwood\nGroup=wyrwood\nSupplementaryGroups=\n"}}
	return &Manager{Root: t.TempDir(), Executable: "/opt/wyrwood/bin/wyrwood", Run: runner.run, EUID: func() int { return euid }}, runner
}

func TestInstallIsIdempotentAndUsesArgvWithoutAShell(t *testing.T) {
	manager, runner := newManager(t, 0)
	runner.outputs["systemctl show --property=LoadState,ActiveState wyrwood-agent.service"] = "LoadState=loaded\nActiveState=inactive\n"
	runner.failures["getent passwd wyrwood"] = errors.New("absent")
	for range 2 {
		state, err := manager.Manage("install")
		if err != nil || state != StateInactive {
			t.Fatalf("install = %s, %v", state, err)
		}
	}
	data, err := os.ReadFile(filepath.Join(manager.Root, "etc/systemd/system", UnitName))
	if err != nil || !strings.Contains(string(data), "ExecStart=/opt/wyrwood/bin/wyrwood agent daemon\n") {
		t.Fatalf("installed unit = %s, %v", data, err)
	}
	info, _ := os.Stat(filepath.Join(manager.Root, "etc/systemd/system", UnitName))
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("unit mode = %v", info.Mode())
	}
	var sawEnable, sawUseradd bool
	for _, call := range runner.calls {
		for _, argument := range call {
			if strings.ContainsAny(argument, ";|&$`") {
				t.Fatalf("argument %q looks like shell syntax", argument)
			}
		}
		joined := strings.Join(call, " ")
		sawEnable = sawEnable || joined == "systemctl enable wyrwood-agent.service"
		sawUseradd = sawUseradd || strings.HasPrefix(joined, "useradd --system")
		if call[0] == "sh" || call[0] == "bash" {
			t.Fatalf("command ran through a shell: %v", call)
		}
	}
	if !sawEnable || !sawUseradd {
		t.Fatalf("calls = %v", runner.calls)
	}
}

func TestStatusVocabularyAndRemove(t *testing.T) {
	manager, runner := newManager(t, 1000)
	if state, err := manager.Manage("status"); err != nil || state != StateNotInstalled {
		t.Fatalf("status before install = %s, %v", state, err)
	}
	if _, err := manager.Manage("install"); !errors.Is(err, ErrRequiresRoot) {
		t.Fatalf("install without root = %v", err)
	}
	manager.EUID = func() int { return 0 }
	if _, err := manager.Manage("start"); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("start before install = %v", err)
	}
	if _, err := manager.Manage("install"); err != nil {
		t.Fatal(err)
	}
	for output, want := range map[string]State{
		"LoadState=loaded\nActiveState=active\n":      StateActive,
		"LoadState=loaded\nActiveState=failed\n":      StateFailed,
		"LoadState=loaded\nActiveState=inactive\n":    StateInactive,
		"LoadState=not-found\nActiveState=inactive\n": StateNotInstalled,
	} {
		runner.outputs["systemctl show --property=LoadState,ActiveState wyrwood-agent.service"] = output
		if state, err := manager.Manage("status"); err != nil || state != want {
			t.Errorf("status for %q = %s, %v", output, state, err)
		}
	}
	runner.failures["systemctl enable --now wyrwood-agent.service"] = errors.New("raw manager text")
	if _, err := manager.Manage("start"); !errors.Is(err, ErrManager) || strings.Contains(err.Error(), "raw") {
		t.Fatalf("start failure = %v", err)
	}
	if state, err := manager.Manage("remove"); err != nil || state != StateNotInstalled {
		t.Fatalf("remove = %s, %v", state, err)
	}
	if state, err := manager.Manage("remove"); err != nil || state != StateNotInstalled {
		t.Fatalf("second remove = %s, %v", state, err)
	}
}

func TestStartEnablesInstalledServiceAndStopPreservesEnablement(t *testing.T) {
	for _, source := range []string{"archive", "package"} {
		t.Run(source, func(t *testing.T) {
			manager, runner := newManager(t, 0)
			unitPath := manager.unitPath()
			if source == "package" {
				unitPath = manager.packagedUnit()
			}
			if err := writeAtomic(unitPath, Unit(PackagedExecutable), 0o644); err != nil {
				t.Fatal(err)
			}
			runner.outputs["systemctl show --property=LoadState,ActiveState wyrwood-agent.service"] = "LoadState=loaded\nActiveState=active\n"
			for range 2 {
				runner.calls = nil
				state, err := manager.Manage("start")
				if err != nil || state != StateActive {
					t.Fatalf("start = %s, %v", state, err)
				}
				if got := runner.calls; len(got) != 2 || strings.Join(got[0], " ") != "systemctl enable --now wyrwood-agent.service" ||
					strings.Join(got[1], " ") != "systemctl show --property=LoadState,ActiveState wyrwood-agent.service" {
					t.Fatalf("start calls = %v", got)
				}
			}
			runner.calls = nil
			runner.outputs["systemctl show --property=LoadState,ActiveState wyrwood-agent.service"] = "LoadState=loaded\nActiveState=inactive\n"
			if state, err := manager.Manage("stop"); err != nil || state != StateInactive {
				t.Fatalf("stop = %s, %v", state, err)
			}
			if got := runner.calls; len(got) != 2 || strings.Join(got[0], " ") != "systemctl stop wyrwood-agent.service" ||
				strings.Join(got[1], " ") != "systemctl show --property=LoadState,ActiveState wyrwood-agent.service" {
				t.Fatalf("stop calls = %v", got)
			}
		})
	}
}

func TestServiceActionFailureDoesNotQueryStatus(t *testing.T) {
	for action, command := range map[string]string{
		"start": "systemctl enable --now wyrwood-agent.service",
		"stop":  "systemctl stop wyrwood-agent.service",
	} {
		t.Run(action, func(t *testing.T) {
			manager, runner := newManager(t, 0)
			if err := writeAtomic(manager.packagedUnit(), Unit(PackagedExecutable), 0o644); err != nil {
				t.Fatal(err)
			}
			runner.failures[command] = errors.New("raw manager text")
			state, err := manager.Manage(action)
			if state != "" || err != ErrManager {
				t.Fatalf("%s failure = %s, %v", action, state, err)
			}
			if len(runner.calls) != 1 || strings.Join(runner.calls[0], " ") != command {
				t.Fatalf("failure calls = %v", runner.calls)
			}
		})
	}
}
