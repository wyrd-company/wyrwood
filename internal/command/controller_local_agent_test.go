// ---
// relationships:
//   verifies:
//     - controller
//     - agent
//     - agent-controller-protocol
// ---

package command

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/agent"
	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/controller"
	"github.com/wyrd-company/wyrwood/internal/controller/controllertest"
	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/engine/enginetest"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// Exercise both real libraries under the combined lifetime, with real SSH and
// OpenBao. Only Engine observation is substituted; existing agent tests cover
// the full credential and consumer endpoint contract.
func TestControllerLocalAgentInventoryAndBinding(t *testing.T) {
	bao := baotest.Start(t)
	role, secret := bao.ControllerCredentials(t)
	address := controllertest.FreeAddress(t)
	state := t.TempDir()
	c, err := controller.New(config.Controller{
		StateDirectory: state, SSHListen: address,
		OpenBao: config.ControllerOpenBao{Address: bao.Address, Namespace: bao.Namespace, AppRoleMount: "approle", RoleID: role, SecretIDFile: secret, TransitMount: "transit", SSHMount: "ssh"},
	}, controller.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	base := t.TempDir()
	paths := agent.Paths{Config: filepath.Join(base, "agent.yml"), State: filepath.Join(base, "state"), Runtime: filepath.Join(base, "run")}
	settings, err := config.ParseAgent([]byte("controller:\n  url: ssh://" + address + "\nconsumers:\n  root: " + filepath.Join(base, "consumers") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	fake := enginetest.New()
	container := engine.Container{Name: "/sample", ID: enginetest.NewID()}
	container.State.Status = "running"
	container.Config.Image = "alpine:3.22"
	fake.Add(container)
	if err := os.MkdirAll(paths.State, 0o700); err != nil {
		t.Fatal(err)
	}
	local, err := agent.New(agent.Options{Config: settings, Paths: paths, Engine: fake, Hostname: "host-a"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runControllerServices(ctx, true, func(ctx context.Context) error { return c.Run(ctx, nil) }, local.Run)
	}()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("shutdown: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("combined service did not stop")
		}
	}()
	await := func(what string, test func() bool) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for !test() {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	await("controller listener", func() bool {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	})
	fingerprint, err := controller.HostKeyFingerprint(state)
	if err != nil {
		t.Fatal(err)
	}
	login, err := agent.Login(ctx, agent.LoginOptions{Paths: paths, ControllerURL: settings.ControllerURL, AcceptFingerprint: fingerprint, Hostname: func() (string, error) { return "host-a", nil }})
	if err != nil || login.Approved {
		t.Fatalf("pending login: %+v, %v", login, err)
	}
	if err := c.DecideAgent(ctx, login.AgentFingerprint, true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	await("local inventory", func() bool {
		inventory, _, err := c.Store().Inventory(ctx, "host-a")
		return err == nil && len(inventory) == 1 && inventory[0].ID == container.ID
	})
	if _, err := c.SavePolicy(ctx, policy.New("teal", policy.StarterHCL), "operator-1"); err != nil {
		t.Fatal(err)
	}
	group := uint32(os.Getgid())
	if _, err := c.CreateBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "sample"}, policy.Selection{Policies: []string{"teal"}, Settings: policy.Settings{TokenTTL: "20m", TokenMaxTTL: "2h", AccessGroup: &group, Enforcement: policy.EnforcementReport}}, "operator-1"); err != nil {
		t.Fatal(err)
	}
	await("local binding and credential", func() bool {
		var status agent.Status
		err := agent.Query(ctx, paths, agent.ControlRequest{Operation: "status"}, &status)
		return err == nil && status.Session == "connected" && status.Containers == 1 && status.Bindings == 1 && status.Tokens == 1
	})
	// Both daemon entrypoints use these same paths. Reject a second writer
	// before it can replace the running control socket or change its inventory.
	if duplicate, err := agent.New(agent.Options{Config: settings, Paths: paths, Engine: fake}); err == nil {
		_ = duplicate
		t.Fatal("duplicate runtime accepted")
	}
	var status agent.Status
	if err := agent.Query(ctx, paths, agent.ControlRequest{Operation: "status"}, &status); err != nil || status.Tokens != 1 {
		t.Fatalf("original runtime after duplicate: %+v %v", status, err)
	}
}
