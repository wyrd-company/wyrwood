// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package controller_test

import (
	"context"
	"errors"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/controller/controllertest"
	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
)

// A controller that stops after the OpenBao delete and before the store delete
// starts again with the policy present in both, and the delete can be retried.
func TestRestartBetweenTheTwoDeletesKeepsThePolicy(t *testing.T) {
	ctx := context.Background()
	bao := baotest.Start(t)
	state, address := t.TempDir(), controllertest.FreeAddress(t)
	running := controllertest.StartIn(t, bao, state, address)
	saved, err := running.SavePolicy(ctx, policy.New("alpha", policy.StarterHCL), "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := bao.Root.Sys().DeletePolicy(saved.OpenBaoPolicyName()); err != nil {
		t.Fatal(err)
	}
	running.Stop()

	restarted := controllertest.StartIn(t, bao, state, address)
	acl, err := bao.Root.Sys().GetPolicy(saved.OpenBaoPolicyName())
	if err != nil || acl != saved.PublishedHCL() {
		t.Fatalf("OpenBao policy after restart = %q, %v", acl, err)
	}
	stored, err := restarted.Store().Policy(ctx, saved.Name)
	if err != nil || stored.Policy.Revision != saved.Revision {
		t.Fatalf("stored policy after restart = %#v, %v", stored, err)
	}
	if err := restarted.DeletePolicy(ctx, saved.Name, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Store().Policy(ctx, saved.Name); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stored policy lookup = %v", err)
	}
	if acl, err := bao.Root.Sys().GetPolicy(saved.OpenBaoPolicyName()); err != nil || acl != "" {
		t.Fatalf("OpenBao policy = %q, %v", acl, err)
	}
}
