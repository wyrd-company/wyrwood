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

	"github.com/wyrd-company/wyrwood/internal/controller/controllertest"
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
