// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package agent

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/openbao/openbao/api/v2"
	policycontroller "github.com/wyrd-company/wyrwood/internal/controller"
	"github.com/wyrd-company/wyrwood/internal/controller/controllertest"
	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/engine/enginetest"
	"github.com/wyrd-company/wyrwood/internal/openbao"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// A real agent accepts a credential only when the issued token names exactly the
// policies of its assignment. A recreated policy reaches it as the new identity,
// and the same socket then serves a token of that identity.
func TestAgentServesATokenOfARecreatedPolicysIdentity(t *testing.T) {
	ctx := context.Background()
	bao := baotest.Start(t)
	controller := controllertest.Start(t, bao)
	paths := newPaths(t)
	first := login(t, paths, controller.URL, controller.Fingerprint)
	if err := controller.DecideAgent(ctx, first.AgentFingerprint, true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	fake := enginetest.New()
	web := engine.Container{Name: "/web"}
	web.State.Status = "running"
	web.Config.Image = "example/web:1"
	fake.Add(web)
	startAgent(t, paths, fake, false)
	eventually(t, "inventory at the controller", func() bool {
		containers, _, _ := controller.Store().Inventory(ctx, "host-a")
		return len(containers) == 1
	})
	socket := filepath.Join(paths.Runtime, "containers", "web", "vault.sock")
	policies := func(token string) []string {
		reader, err := openbao.NewClient(openbao.Endpoint{Address: bao.Address, Namespace: bao.Namespace})
		if err != nil {
			t.Fatal(err)
		}
		reader.SetToken(token)
		self, err := reader.Auth().Token().LookupSelf()
		if err != nil {
			t.Fatalf("agent token does not work: %v", err)
		}
		names, err := self.TokenPolicies()
		if err != nil {
			t.Fatal(err)
		}
		return names
	}
	key := protocol.Key{Kind: protocol.KeyName, Value: "web"}
	served := func() string {
		var token string
		eventually(t, "a bound socket with a token", func() bool {
			fields := strings.Fields(probe(t, socket))
			if len(fields) == 3 && fields[0] == "sample" && fields[1] == "true" {
				token = fields[2]
				return true
			}
			return false
		})
		return token
	}

	if _, err := controller.SavePolicy(ctx, policy.New("sample", policy.StarterHCL), "operator-1"); err != nil {
		t.Fatal(err)
	}
	binding, err := controller.CreateBinding(ctx, "host-a", key, policy.Selection{Policies: []string{"sample"}}, "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	if got := policies(served()); !reflect.DeepEqual(got, []string{"wyrwood-sample"}) {
		t.Fatalf("first token policies = %v", got)
	}

	if err := controller.DeleteBinding(ctx, binding.ID, "operator-1"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the socket to retire", func() bool { return probe(t, socket) == "unreachable" })
	if err := controller.DeletePolicy(ctx, "sample", "operator-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.SavePolicy(ctx, policy.New("sample", policy.StarterHCL), "operator-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.CreateBinding(ctx, "host-a", key, policy.Selection{Policies: []string{"sample"}}, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if got := policies(served()); !reflect.DeepEqual(got, []string{"wyrwood-sample--2"}) {
		t.Fatalf("second token policies = %v", got)
	}
}

// A real agent with a live token and socket. A rename revokes the old token, and
// the same socket serves a token of exactly the new identity. The controller holds
// that token's accessor only for the new assignment, and the agent reports its
// contract again. An agent offline during a later rename takes the new assignment
// and a fresh credential on reconnect.
func TestAgentTakesAFreshCredentialThroughARename(t *testing.T) {
	ctx := context.Background()
	bao := baotest.Start(t)
	controller := controllertest.Start(t, bao)
	paths := newPaths(t)
	first := login(t, paths, controller.URL, controller.Fingerprint)
	if err := controller.DecideAgent(ctx, first.AgentFingerprint, true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	fake := enginetest.New()
	web := engine.Container{Name: "/web"}
	web.State.Status = "running"
	web.Config.Image = "example/web:1"
	fake.Add(web)
	agent := startAgent(t, paths, fake, false)
	eventually(t, "inventory at the controller", func() bool {
		containers, _, _ := controller.Store().Inventory(ctx, "host-a")
		return len(containers) == 1
	})
	socket := filepath.Join(paths.Runtime, "containers", "web", "vault.sock")
	reader := func(token string) *api.Client {
		client, err := openbao.NewClient(openbao.Endpoint{Address: bao.Address, Namespace: bao.Namespace})
		if err != nil {
			t.Fatal(err)
		}
		client.SetToken(token)
		return client
	}
	servedAs := func(name string) string {
		var token string
		eventually(t, "a socket serving "+name, func() bool {
			fields := strings.Fields(probe(t, socket))
			if len(fields) == 3 && fields[0] == name && fields[1] == "true" {
				token = fields[2]
				return true
			}
			return false
		})
		return token
	}
	policies := func(token string) []string {
		self, err := reader(token).Auth().Token().LookupSelf()
		if err != nil {
			t.Fatalf("agent token does not work: %v", err)
		}
		names, err := self.TokenPolicies()
		if err != nil {
			t.Fatal(err)
		}
		return names
	}
	saved, err := controller.SavePolicy(ctx, policy.New("sample", policy.StarterHCL), "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := controller.CreateBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "web"}, policy.Selection{Policies: []string{"sample"}}, "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	oldToken := servedAs("sample")
	if got := policies(oldToken); !reflect.DeepEqual(got, []string{"wyrwood-sample"}) {
		t.Fatalf("first token policies = %v", got)
	}
	oldAccessor := ""
	eventually(t, "the first token's accessor", func() bool {
		oldAccessor, _ = controller.Store().TokenAccessor(ctx, binding.ID)
		return oldAccessor != ""
	})
	var results map[string]store.ContractResult
	eventually(t, "the first contract result", func() bool {
		results, _ = controller.Store().ContractResults(ctx)
		return results[binding.ID].Outcome != ""
	})

	if _, err := controller.RenamePolicy(ctx, policycontroller.PolicyRename{Name: "sample", NewName: "renamed", Revision: saved.Revision, Generation: saved.Generation}, "operator-1"); err != nil {
		t.Fatal(err)
	}
	newToken := servedAs("renamed")
	if newToken == oldToken {
		t.Fatal("the agent kept the old token")
	}
	if got := policies(newToken); !reflect.DeepEqual(got, []string{"wyrwood-renamed"}) {
		t.Fatalf("token after the rename = %v", got)
	}
	if _, err := reader(oldToken).Auth().Token().LookupSelf(); err == nil {
		t.Fatal("the old token still works")
	}
	current, err := controller.Store().Binding(ctx, binding.ID)
	if err != nil || current.Revision != binding.Revision+1 || !current.Applied || !reflect.DeepEqual(current.Policies, []string{"renamed"}) {
		t.Fatalf("binding = %#v, %v", current, err)
	}
	eventually(t, "the new token's accessor at the new assignment", func() bool {
		accessor, _ := controller.Store().TokenAccessor(ctx, binding.ID)
		return accessor != "" && accessor != oldAccessor
	})
	// The agent evaluates its contract against the new assignment. A connected
	// agent reports a result when it changes, and a rename does not change it, so
	// the controller's row stands until the next session sends it again.
	var listing Containers
	eventually(t, "the agent's contract for the new assignment", func() bool {
		if err := Query(ctx, paths, ControlRequest{Operation: "containers"}, &listing); err != nil {
			t.Fatal(err)
		}
		return len(listing.Containers) == 1 && strings.Join(listing.Containers[0].Policies, ",") == "renamed" && listing.Containers[0].Token == "valid" &&
			listing.Containers[0].Conformance == string(results[binding.ID].Outcome)
	})

	agent.stop()
	eventually(t, "the agent's session to end", func() bool { return !controller.Connected("host-a") })
	stored, err := controller.Store().Policy(ctx, "renamed")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.RenamePolicy(ctx, policycontroller.PolicyRename{Name: "renamed", NewName: "offline", Revision: stored.Policy.Revision, Generation: stored.Policy.Generation}, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := reader(newToken).Auth().Token().LookupSelf(); err == nil {
		t.Fatal("the rename did not revoke the offline agent's token")
	}
	retired, err := bao.Root.Sys().GetPolicy("wyrwood-renamed")
	if err != nil || retired != "" {
		t.Fatalf("old ACL = %q, %v", retired, err)
	}
	startAgent(t, paths, fake, false)
	reconnected := servedAs("offline")
	if got := policies(reconnected); !reflect.DeepEqual(got, []string{"wyrwood-offline"}) {
		t.Fatalf("token after the reconnect = %v", got)
	}
	eventually(t, "a contract result sent after the rename", func() bool {
		latest, _ := controller.Store().ContractResults(ctx)
		return latest[binding.ID].UpdatedAt.After(results[binding.ID].UpdatedAt)
	})
}
