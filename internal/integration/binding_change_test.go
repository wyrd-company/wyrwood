//go:build integration

// ---
// relationships:
//   verifies:
//     - operator-interface
//     - agent
//     - vault-socket-proxy
// ---

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wyrd-company/wyrwood/internal/agent"
	"github.com/wyrd-company/wyrwood/internal/controller/controllertest"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/operator"
)

const (
	amberHCL    = `path "kv/data/teams/amber/*" { capabilities = ["read"] }`
	amberSecret = "amber-secret-value"
)

// TestOperatorClientChangesARunningContainersBinding changes the binding of a
// running container from one policy to two with the public operator client. The
// container reads with the added policy's access with no restart, and its
// consumer directory and sockets stay in place throughout.
func TestOperatorClientChangesARunningContainersBinding(t *testing.T) {
	if exec.Command("docker", "version").Run() != nil {
		t.Skip("Docker Engine is unavailable")
	}
	baotest.Executable(t)
	ctx := context.Background()
	image := gateImage(t)

	bao := baotest.Start(t)
	bao.WriteKV(t, "teams/teal/example", map[string]any{"value": gateSecret})
	bao.WriteKV(t, "teams/amber/example", map[string]any{"value": amberSecret})
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
	for name, hcl := range map[string]string{"teal": gateHCL, "amber": amberHCL} {
		if _, err := controller.SavePolicy(ctx, policy.New(name, hcl), "gate-operator"); err != nil {
			t.Fatal(err)
		}
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

	// An operator key that an operator approved for this agent and both policies.
	signer, _, err := operator.LoadOrCreateKey(filepath.Join(base, "operator", "key"))
	if err != nil {
		t.Fatal(err)
	}
	settings := operator.Config{URL: controller.URL, Signer: signer, HostKey: controller.Fingerprint, Label: "gate-script", Timeout: 10 * time.Second}
	if result, err := operator.Login(ctx, settings, nil); err != nil || result.Approved {
		t.Fatalf("operator login = %+v, %v", result, err)
	}
	grant := operator.Grant{Agents: []string{"gate-host"}, Policies: []string{"teal", "amber"}, Actions: []operator.Action{operator.ActionRead, operator.ActionBind}}
	if err := controller.ApproveOperatorKey(ctx, ssh.FingerprintSHA256(signer.PublicKey()), "gate-script", grant, "gate-operator"); err != nil {
		t.Fatal(err)
	}
	client, err := operator.Dial(ctx, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	group := uint32(4242)
	if os.Geteuid() != 0 {
		group = uint32(os.Getgid())
	}
	const name = "changed-consumer"
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "--force", name).Run() })
	bound, err := client.Bind(ctx, operator.BindRequest{Agent: "gate-host", Key: operator.Key{Kind: operator.KeyName, Value: name},
		Policies: []string{"teal"}, Settings: operator.Settings{AccessGroup: &group}})
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, name)
	sockets := []string{filepath.Join(directory, "vault.sock"), filepath.Join(directory, "ssh-agent.sock")}
	eventually(t, "the consumer directory and its sockets", 30*time.Second, func() bool {
		for _, path := range sockets {
			if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSocket == 0 {
				return false
			}
		}
		return true
	})
	run(t, "docker", "run", "--detach", "--name", name, "--user", "12345:12345", "--group-add", fmt.Sprint(group), "--entrypoint", "sleep",
		"--mount", "type=bind,source="+directory+",target=/run/wyrwood",
		"--env", "HOME=/tmp", "--env", "VAULT_ADDR=unix:///run/wyrwood/vault.sock", "--env", "SSH_AUTH_SOCK=/run/wyrwood/ssh-agent.sock",
		image, "3600")
	read := func(path string) (string, error) {
		output, err := exec.Command("docker", "exec", name, "bao", "kv", "get", "-field=value", path).CombinedOutput()
		return strings.TrimSpace(string(output)), err
	}
	eventually(t, "a read with the teal policy", time.Minute, func() bool {
		secret, err := read("kv/teams/teal/example")
		return err == nil && secret == gateSecret
	})
	if _, err := read("kv/teams/amber/example"); err == nil {
		t.Fatal("the container read the amber secret before the change")
	}
	started := strings.TrimSpace(run(t, "docker", "inspect", "--format", "{{.Id}} {{.State.StartedAt}} {{.RestartCount}}", name))

	// The directory and both sockets keep their inodes from here to the end.
	stat := func(path string) os.FileInfo {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
	watched := append([]string{directory}, sockets...)
	before := make([]os.FileInfo, len(watched))
	for index, path := range watched {
		before[index] = stat(path)
	}
	var (
		watchMu   sync.Mutex
		moved     []string
		checks    int
		stopWatch = make(chan struct{})
		watchDone = make(chan struct{})
	)
	go func() {
		defer close(watchDone)
		for {
			for index, path := range watched {
				info, err := os.Lstat(path)
				watchMu.Lock()
				if err != nil || !os.SameFile(before[index], info) {
					moved = append(moved, path)
				}
				watchMu.Unlock()
			}
			watchMu.Lock()
			checks++
			watchMu.Unlock()
			select {
			case <-stopWatch:
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}()

	changed, err := client.ChangeBinding(ctx, operator.BindingChange{ID: bound.ID, Revision: bound.Revision, Policies: []string{"amber", "teal"}, Settings: bound.Settings})
	if err != nil {
		t.Fatal(err)
	}
	if changed.ID != bound.ID || !changed.Applied || !slices.Equal(changed.Policies, []string{"amber", "teal"}) {
		t.Fatalf("ChangeBinding() = %+v", changed)
	}
	eventually(t, "a read with the amber policy", time.Minute, func() bool {
		secret, err := read("kv/teams/amber/example")
		return err == nil && secret == amberSecret
	})
	if secret, err := read("kv/teams/teal/example"); err != nil || secret != gateSecret {
		t.Fatalf("the teal read after the change = %q, %v", secret, err)
	}
	// One token, of the new assignment: the old one was revoked.
	eventually(t, "the old token revoked", time.Minute, func() bool {
		return status().Tokens == 1 && bindingTokens(t, bao, "wyrwood-teal") == 1 && bindingTokens(t, bao, "wyrwood-amber") == 1
	})
	close(stopWatch)
	<-watchDone
	if len(moved) != 0 || checks < 2 {
		t.Fatalf("paths replaced or missing during the change: %v (%d checks)", moved, checks)
	}
	if after := strings.TrimSpace(run(t, "docker", "inspect", "--format", "{{.Id}} {{.State.StartedAt}} {{.RestartCount}}", name)); after != started {
		t.Fatalf("the container restarted: %s, then %s", started, after)
	}

	// The event history names the key and both selections.
	var got [][2]string
	for _, event := range controller.Events().Recent(1000) {
		if event.Operation == events.OperationBindingChanged && event.Binding == bound.ID {
			if event.Operator != "key:gate-script" || event.Outcome != events.OutcomeOK {
				t.Fatalf("binding-changed event = %#v", event)
			}
			got = append(got, [2]string{event.Policy, event.NewPolicy})
		}
	}
	if want := [][2]string{{"", "amber"}, {"teal", "teal"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("binding-changed policy and new policy = %v; want %v", got, want)
	}
}
