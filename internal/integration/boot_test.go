//go:build integration

// ---
// relationships:
//   verifies:
//     - agent
//     - engine-proxy
// ---

package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/agent"
	"github.com/wyrd-company/wyrwood/internal/controller/controllertest"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// TestBootStartsBoundContainers follows a host reboot on a real Engine, with
// the host's recreate permission off. The daemon restarts while the consumer
// directories are absent, as they are when /run is empty at boot.
func TestBootStartsBoundContainers(t *testing.T) {
	if os.Getenv("WYRWOOD_GATE_RESTART_ENGINE") == "" {
		t.Skip("set WYRWOOD_GATE_RESTART_ENGINE on a disposable host: this restarts Docker Engine and stops every container")
	}
	if os.Geteuid() != 0 {
		t.Skip("the gate runs as root: it binds sockets the engine mounts and restarts the engine")
	}
	baotest.Executable(t)
	ctx := context.Background()
	image := gateImage(t)

	bao := baotest.Start(t)
	controller := controllertest.StartIn(t, bao, t.TempDir(), controllertest.FreeAddress(t))
	base := t.TempDir()
	paths := agent.Paths{Config: filepath.Join(base, "etc", "agent.yml"), State: filepath.Join(base, "state"), Runtime: filepath.Join(base, "run")}
	root := filepath.Join(base, "run", "containers")
	hostname := func() (string, error) { return "gate-host", nil }
	login, err := agent.Login(ctx, agent.LoginOptions{Paths: paths, ControllerURL: controller.URL, AcceptFingerprint: controller.Fingerprint, Hostname: hostname})
	if err != nil || login.Approved {
		t.Fatalf("first login = %#v, %v", login, err)
	}
	if err := controller.DecideAgent(ctx, login.AgentFingerprint, true, "gate-operator"); err != nil {
		t.Fatal(err)
	}
	if login, err = agent.Login(ctx, agent.LoginOptions{Paths: paths, ControllerURL: controller.URL, AcceptFingerprint: controller.Fingerprint, Hostname: hostname}); err != nil || !login.Approved {
		t.Fatalf("second login = %#v, %v", login, err)
	}
	if _, err := controller.SavePolicy(ctx, policy.New("teal", gateHCL), "gate-operator"); err != nil {
		t.Fatal(err)
	}

	// restarted is expected back. The others are bound and have the same
	// mount, and must stay stopped.
	const restarted, stoppedOnPurpose, noPolicy = "boot-restarted", "boot-stopped", "boot-no-policy"
	names := []string{restarted, stoppedOnPurpose, noPolicy}
	t.Cleanup(func() {
		for _, name := range names {
			_ = exec.Command("docker", "rm", "--force", name).Run()
		}
	})
	running := startAgentWith(t, paths, root, false)
	eventually(t, "agent session", 30*time.Second, func() bool {
		var status agent.Status
		return agent.Query(ctx, paths, agent.ControlRequest{Operation: "status"}, &status) == nil && status.Session != "" && status.Session != "disconnected"
	})
	state := func(name string) string {
		return strings.TrimSpace(run(t, "docker", "inspect", "--format", "{{.State.Status}}|{{.State.Error}}", name))
	}
	for _, name := range names {
		if err := os.MkdirAll(filepath.Join(root, name), 0o750); err != nil {
			t.Fatal(err)
		}
		restart := "unless-stopped"
		if name == noPolicy {
			restart = "no"
		}
		run(t, "docker", "run", "--detach", "--name", name, "--restart", restart,
			"--mount", "type=bind,source="+filepath.Join(root, name)+",target=/run/wyrwood",
			"--env", "VAULT_ADDR=unix:///run/wyrwood/vault.sock", "--env", "SSH_AUTH_SOCK=/run/wyrwood/ssh-agent.sock",
			image, "sleep", "3600")
		if _, err := controller.CreateBinding(ctx, "gate-host", protocol.Key{Kind: protocol.KeyName, Value: name},
			policy.Selection{Policies: []string{"teal"}, Settings: policy.Settings{Enforcement: policy.EnforcementReport}}, "gate-operator"); err != nil {
			t.Fatal(err)
		}
		eventually(t, "sockets for "+name, time.Minute, func() bool {
			return exec.Command("docker", "exec", name, "test", "-S", "/run/wyrwood/vault.sock").Run() == nil
		})
	}
	run(t, "docker", "stop", "--time", "0", stoppedOnPurpose)

	running.stop()
	run(t, "systemctl", "stop", "docker.service", "docker.socket")
	for _, name := range names {
		if err := os.RemoveAll(filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	run(t, "systemctl", "start", "docker.service")
	eventually(t, "the engine", time.Minute, func() bool { return exec.Command("docker", "ps").Run() == nil })
	eventually(t, "the failed boot start", time.Minute, func() bool {
		return strings.Contains(state(restarted), "no such file or directory")
	})
	if got := state(restarted); !strings.HasPrefix(got, "exited|") {
		t.Fatalf("after the daemon restart %s = %q", restarted, got)
	}
	t.Logf("after the daemon restart: %s", state(restarted))

	startAgentWith(t, paths, root, false)
	began := time.Now()
	eventually(t, "the bound container to run", time.Minute, func() bool { return strings.HasPrefix(state(restarted), "running|") })
	t.Logf("running %v after the agent started", time.Since(began))
	if err := exec.Command("docker", "exec", restarted, "test", "-S", "/run/wyrwood/vault.sock").Run(); err != nil {
		t.Fatalf("vault socket on first start: %v", err)
	}
	if err := exec.Command("docker", "exec", restarted, "test", "-S", "/run/wyrwood/ssh-agent.sock").Run(); err != nil {
		t.Fatalf("ssh-agent socket on first start: %v", err)
	}
	eventually(t, "the container-started event", 30*time.Second, func() bool {
		var history agent.Events
		if err := agent.Query(ctx, paths, agent.ControlRequest{Operation: "events", Limit: 100}, &history); err != nil {
			return false
		}
		for _, event := range history.Events {
			if event.Operation == events.OperationContainerStarted && event.Outcome == events.OutcomeOK {
				return true
			}
		}
		return false
	})
	// One more full reconcile would have happened by now through the event stream.
	time.Sleep(3 * time.Second)
	for _, name := range []string{stoppedOnPurpose, noPolicy} {
		if got := state(name); !strings.HasPrefix(got, "exited|") {
			t.Errorf("%s = %q, want exited", name, got)
		}
	}
}
