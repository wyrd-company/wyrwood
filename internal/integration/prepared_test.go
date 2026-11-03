//go:build integration

// ---
// relationships:
//   verifies:
//     - agent
//     - agent-controller-protocol
// ---

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/agent"
	wyrwoodcontroller "github.com/wyrd-company/wyrwood/internal/controller"
	"github.com/wyrd-company/wyrwood/internal/controller/controllertest"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// TestNameBindingBeforeContainer binds a name before its container exists. It
// runs as root or as a user in the docker group, so the agent's user need not
// be root, and the workload uses neither the agent's user nor its group.
func TestNameBindingBeforeContainer(t *testing.T) {
	if exec.Command("docker", "version").Run() != nil {
		t.Skip("Docker Engine is unavailable")
	}
	baotest.Executable(t)
	ctx := context.Background()
	image := gateImage(t)

	bao := baotest.Start(t)
	bao.WriteKV(t, "teams/teal/example", map[string]any{"value": gateSecret})
	bao.CreateTransitKey(t, "teal-signing", "ed25519")
	bao.CreateSSHRole(t, "teal-hosts", "root", "30m")
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
	document := policy.New("teal", gateHCL)
	document.SSH = &policy.SSH{TransitKeys: []string{"teal-signing"}, CARoles: []string{"teal-hosts"}}
	if _, err := controller.SavePolicy(ctx, document, "gate-operator"); err != nil {
		t.Fatal(err)
	}
	running := startAgent(t, paths, root)
	eventually(t, "agent session", 30*time.Second, func() bool {
		var status agent.Status
		return agent.Query(ctx, paths, agent.ControlRequest{Operation: "status"}, &status) == nil && status.Session == "connected"
	})
	status := func() agent.Status {
		var current agent.Status
		if err := agent.Query(ctx, paths, agent.ControlRequest{Operation: "status"}, &current); err != nil {
			t.Fatal(err)
		}
		return current
	}

	group := uint32(4242)
	if os.Geteuid() != 0 {
		group = uint32(os.Getgid())
	}
	const name = "prepared-consumer"
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "--force", name).Run() })
	selection := policy.Selection{Policies: []string{"teal"}, Settings: policy.Settings{Enforcement: policy.EnforcementReport, AccessGroup: &group}}
	bound, err := controller.CreateBinding(ctx, "gate-host", protocol.Key{Kind: protocol.KeyName, Value: name}, selection, "gate-operator")
	if err != nil {
		t.Fatal(err)
	}

	// The directory and sockets exist with no container, and no token does.
	directory := filepath.Join(root, name)
	vaultSocket := filepath.Join(directory, "vault.sock")
	sshSocket := filepath.Join(directory, "ssh-agent.sock")
	socketsExist := func() bool {
		for _, path := range []string{vaultSocket, sshSocket} {
			if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSocket == 0 {
				return false
			}
		}
		return true
	}
	eventually(t, "a consumer directory before the container", 30*time.Second, socketsExist)
	assertDirectory := func() os.FileInfo {
		t.Helper()
		info, err := os.Stat(directory)
		if err != nil {
			t.Fatal(err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		if info.Mode().Perm() != 0o750 || stat.Gid != group || int(stat.Uid) != os.Geteuid() {
			t.Fatalf("consumer directory: mode %v uid %d gid %d", info.Mode().Perm(), stat.Uid, stat.Gid)
		}
		return info
	}
	before := assertDirectory()
	// readiness waits for the state the agent reports, and reads no host path.
	readiness := func(what string, want wyrwoodcontroller.Readiness, reason wyrwoodcontroller.NotReadyReason) wyrwoodcontroller.BindingStatus {
		t.Helper()
		var current wyrwoodcontroller.BindingStatus
		eventually(t, what, time.Minute, func() bool {
			got, err := controller.BindingStatus(ctx, bound.ID)
			current = got
			return err == nil && got.Readiness == want && (reason == "" || slices.Contains(got.Reasons, reason))
		})
		return current
	}
	prepared := readiness("a prepared directory in the status", wyrwoodcontroller.ReadinessWaiting, wyrwoodcontroller.ReasonNoContainer)
	if len(prepared.Consumers) != 1 || prepared.Consumers[0].Directory != directory || prepared.Consumers[0].AccessGroup == nil || *prepared.Consumers[0].AccessGroup != group ||
		!slices.Equal(prepared.Consumers[0].Sockets, protocol.Sockets) || prepared.Token != protocol.TokenNone || prepared.Outcome != "" {
		t.Fatalf("prepared status = %#v", prepared)
	}
	if current := status(); current.Tokens != 0 || bindingTokens(t, bao, "wyrwood-teal") != 0 {
		t.Fatalf("tokens with no container: agent %d, OpenBao %d", current.Tokens, bindingTokens(t, bao, "wyrwood-teal"))
	}

	// An agent restart with the directory gone, as after a reboot, restores it.
	running.stop()
	if err := os.RemoveAll(directory); err != nil {
		t.Fatal(err)
	}
	_ = startAgent(t, paths, root)
	eventually(t, "a restored consumer directory", 30*time.Second, socketsExist)
	before = assertDirectory()

	create := func() {
		t.Helper()
		run(t, "docker", "create", "--name", name, "--user", "12345:12345", "--group-add", fmt.Sprint(group), "--entrypoint", "sleep",
			"--mount", "type=bind,source="+directory+",target=/run/wyrwood",
			"--env", "HOME=/tmp", "--env", "VAULT_ADDR=unix:///run/wyrwood/vault.sock", "--env", "SSH_AUTH_SOCK=/run/wyrwood/ssh-agent.sock",
			image, "3600")
	}
	state := func() string {
		return strings.TrimSpace(run(t, "docker", "inspect", "--format", "{{.State.Status}}", name))
	}
	// A token follows the create, and no start is needed for it.
	create()
	eventually(t, "a token for the created container", time.Minute, func() bool {
		return status().Tokens == 1 && bindingTokens(t, bao, "wyrwood-teal") == 1
	})
	if got := state(); got != "created" {
		t.Fatalf("container state = %q", got)
	}
	assertDirectory()
	// Readiness names this container while it has not started.
	identifier := strings.TrimSpace(run(t, "docker", "inspect", "--format", "{{.Id}}", name))
	created := readiness("a ready status for the created container", wyrwoodcontroller.ReadinessReady, "")
	if len(created.Containers) != 1 || created.Containers[0].ID != identifier || created.Containers[0].State != protocol.StateCreated || created.Consumers[0].ContainerID != identifier || created.Token != protocol.TokenValid || created.Outcome != protocol.OutcomeConforming {
		t.Fatalf("created status = %#v", created)
	}

	// The first start finds working sockets: this exec is its first process.
	run(t, "docker", "start", name)
	if count := strings.TrimSpace(run(t, "docker", "inspect", "--format", "{{.RestartCount}}", name)); count != "0" {
		t.Fatalf("restart count = %s", count)
	}
	secret := strings.TrimSpace(run(t, "docker", "exec", name, "bao", "kv", "get", "-field=value", "kv/teams/teal/example"))
	if secret != gateSecret {
		t.Fatal("bao kv get through vault.sock returned another value")
	}
	if listing := run(t, "docker", "exec", name, "ssh-add", "-L"); !strings.Contains(listing, "teal-signing") {
		t.Fatalf("ssh-add -L through ssh-agent.sock = %s", listing)
	}

	// Removal revokes the token and keeps the directory and sockets on one inode.
	run(t, "docker", "rm", "--force", name)
	eventually(t, "the token revoked with the container", time.Minute, func() bool {
		return status().Tokens == 0 && bindingTokens(t, bao, "wyrwood-teal") == 0
	})
	if !socketsExist() {
		t.Fatal("sockets removed with the container")
	}
	if after := assertDirectory(); !os.SameFile(before, after) {
		t.Fatal("consumer directory replaced at removal")
	}
	// The stored contract result says conforming; readiness does not read it.
	removed := readiness("no ready status after removal", wyrwoodcontroller.ReadinessWaiting, wyrwoodcontroller.ReasonNoContainer)
	if len(removed.Containers) != 0 || removed.Outcome != "" || removed.Token != protocol.TokenNone || removed.Consumers[0].ContainerID != "" {
		t.Fatalf("removed status = %#v", removed)
	}

	// A replacement with the name has working sockets on its first start.
	create()
	eventually(t, "a token for the replacement", time.Minute, func() bool { return status().Tokens == 1 })
	replacement := strings.TrimSpace(run(t, "docker", "inspect", "--format", "{{.Id}}", name))
	if rebuilt := readiness("a ready status for the replacement", wyrwoodcontroller.ReadinessReady, ""); rebuilt.Containers[0].ID != replacement || replacement == identifier {
		t.Fatalf("replacement status = %#v, id %s", rebuilt, replacement)
	}
	run(t, "docker", "start", name)
	if secret := strings.TrimSpace(run(t, "docker", "exec", name, "bao", "kv", "get", "-field=value", "kv/teams/teal/example")); secret != gateSecret {
		t.Fatal("bao kv get through vault.sock in the replacement returned another value")
	}
}
