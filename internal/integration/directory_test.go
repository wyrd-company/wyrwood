//go:build integration

// ---
// relationships:
//   verifies:
//     - agent
//     - agent-controller-protocol
//     - composable-policy-bindings
// ---

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/agent"
	wyrwoodcontroller "github.com/wyrd-company/wyrwood/internal/controller"
	"github.com/wyrd-company/wyrwood/internal/controller/controllertest"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// TestDirectoryBindingBeforeContainer binds a Compose key with a directory name
// before its container exists. The container then mounts that directory, which
// is not named after the container, and reads a secret through vault.sock.
func TestDirectoryBindingBeforeContainer(t *testing.T) {
	if exec.Command("docker", "version").Run() != nil {
		t.Skip("Docker Engine is unavailable")
	}
	baotest.Executable(t)
	ctx := context.Background()
	image := gateImage(t)

	bao := baotest.Start(t)
	bao.WriteKV(t, "teams/teal/example", map[string]any{"value": gateSecret})
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
	_ = startAgent(t, paths, root)
	status := func() agent.Status {
		var current agent.Status
		if err := agent.Query(ctx, paths, agent.ControlRequest{Operation: "status"}, &current); err != nil {
			t.Fatal(err)
		}
		return current
	}
	eventually(t, "agent session", 30*time.Second, func() bool {
		var current agent.Status
		return agent.Query(ctx, paths, agent.ControlRequest{Operation: "status"}, &current) == nil && current.Session == "connected"
	})

	group := uint32(4242)
	if os.Geteuid() != 0 {
		group = uint32(os.Getgid())
	}
	const name, directoryName = "shop-web-1", "shop-web"
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "--force", name).Run() })
	key := protocol.Key{Kind: protocol.KeyCompose, Value: "shop/web"}
	selection := policy.Selection{Policies: []string{"teal"}, Settings: policy.Settings{Enforcement: policy.EnforcementReport, AccessGroup: &group}}
	// No agent reports the key, so the binding needs its directory name.
	if _, err := controller.CreateBindingFor(ctx, wyrwoodcontroller.BindingTarget{Agent: "gate-host", Key: key}, selection, "gate-operator"); err == nil {
		t.Fatal("a binding with no directory name was accepted for an unreported key")
	}
	bound, err := controller.CreateBindingFor(ctx, wyrwoodcontroller.BindingTarget{Agent: "gate-host", Key: key, Directory: directoryName}, selection, "gate-operator")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := controller.Store().Binding(ctx, bound.ID)
	if err != nil || stored.Directory != directoryName {
		t.Fatalf("stored binding = %+v, %v", stored, err)
	}

	// The stored directory and its sockets exist with no container, and no token does.
	directory := filepath.Join(root, directoryName)
	vaultSocket := filepath.Join(directory, "vault.sock")
	eventually(t, "the stored directory before the container", 30*time.Second, func() bool {
		info, err := os.Lstat(vaultSocket)
		return err == nil && info.Mode()&os.ModeSocket != 0
	})
	eventually(t, "the prepared directory in the status", time.Minute, func() bool {
		got, err := controller.BindingStatus(ctx, bound.ID)
		return err == nil && got.Readiness == wyrwoodcontroller.ReadinessWaiting && len(got.Consumers) == 1 && got.Consumers[0].Directory == directory
	})
	if current := status(); current.Tokens != 0 || bindingTokens(t, bao, "wyrwood-teal") != 0 {
		t.Fatalf("tokens with no container: agent %d, OpenBao %d", current.Tokens, bindingTokens(t, bao, "wyrwood-teal"))
	}

	// docker create a container that carries the key and mounts the directory.
	run(t, "docker", "create", "--name", name, "--user", "12345:12345", "--group-add", fmt.Sprint(group), "--entrypoint", "sleep",
		"--label", "com.docker.compose.project=shop", "--label", "com.docker.compose.service=web",
		"--mount", "type=bind,source="+directory+",target=/run/wyrwood",
		"--env", "HOME=/tmp", "--env", "VAULT_ADDR=unix:///run/wyrwood/vault.sock", "--env", "SSH_AUTH_SOCK=/run/wyrwood/ssh-agent.sock",
		image, "3600")
	eventually(t, "a token for the created container", time.Minute, func() bool {
		return status().Tokens == 1 && bindingTokens(t, bao, "wyrwood-teal") == 1
	})
	identifier := strings.TrimSpace(run(t, "docker", "inspect", "--format", "{{.Id}}", name))
	eventually(t, "a ready status for the created container", time.Minute, func() bool {
		got, err := controller.BindingStatus(ctx, bound.ID)
		return err == nil && got.Readiness == wyrwoodcontroller.ReadinessReady && len(got.Consumers) == 1 &&
			got.Consumers[0].ContainerID == identifier && got.Consumers[0].Directory == directory && got.Outcome == protocol.OutcomeConforming
	})
	if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
		t.Fatalf("a directory named after the container: %v", err)
	}

	// Start it: the container reads its secret through vault.sock in the stored directory.
	run(t, "docker", "start", name)
	if secret := strings.TrimSpace(run(t, "docker", "exec", name, "bao", "kv", "get", "-field=value", "kv/teams/teal/example")); secret != gateSecret {
		t.Fatal("bao kv get through vault.sock returned another value")
	}

	// Removal revokes the token and keeps the stored directory's sockets.
	run(t, "docker", "rm", "--force", name)
	eventually(t, "the token revoked with the container", time.Minute, func() bool {
		return status().Tokens == 0 && bindingTokens(t, bao, "wyrwood-teal") == 0
	})
	if info, err := os.Lstat(vaultSocket); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket after removal: %v", err)
	}
}
