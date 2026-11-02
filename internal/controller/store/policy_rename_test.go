// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package store

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

type renameFixture struct {
	store    *Store
	path     string
	saved    policy.Policy
	selected Binding
	other    Binding
	document policy.Policy
	next     Binding
}

func newRenameFixture(t *testing.T) renameFixture {
	t.Helper()
	ctx := context.Background()
	opened, path := openTest(t)
	now := time.Now().UTC()
	saved, err := opened.SavePolicy(ctx, policy.New("alpha", policy.StarterHCL), "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opened.SavePolicy(ctx, policy.New("other", policy.StarterHCL), "operator", now); err != nil {
		t.Fatal(err)
	}
	selected := Binding{ID: "b-selected", Agent: "host-a", Key: protocol.Key{Kind: protocol.KeyName, Value: "one"}, Policies: []string{"alpha", "other"}, Revision: 1, Applied: true, Role: "wyrwood-host-a-b-selected", CreatedAt: now}
	other := Binding{ID: "b-other", Agent: "host-a", Key: protocol.Key{Kind: protocol.KeyName, Value: "two"}, Policies: []string{"other"}, Revision: 1, Applied: true, Role: "wyrwood-host-a-b-other", CreatedAt: now}
	for _, binding := range []Binding{selected, other} {
		if err := opened.CreateBinding(ctx, binding); err != nil {
			t.Fatal(err)
		}
	}
	document := saved.Clone()
	document.Name, document.Generation, document.Revision = "beta", 1, saved.Revision+1
	next := selected
	next.Policies = []string{"beta", "other"}
	next.Revision = 2
	next.Applied = false
	if err := opened.RecordPolicyRetirement(ctx, document.OpenBaoPolicyName(), now); err != nil {
		t.Fatal(err)
	}
	return renameFixture{store: opened, path: path, saved: saved, selected: selected, other: other, document: document, next: next}
}

func (fixture renameFixture) rename(document policy.Policy, bindings ...Binding) (policy.Policy, error) {
	return fixture.store.RenamePolicy(context.Background(), "alpha", document, bindings, "operator-2", time.Now().UTC())
}

// wantUntouched fails unless a refused rename left every durable part of the
// fixture as it was.
func (fixture renameFixture) wantUntouched(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	stored, err := fixture.store.Policy(ctx, "alpha")
	if err != nil || stored.Policy.Revision != fixture.saved.Revision {
		t.Fatalf("alpha = %#v, %v", stored, err)
	}
	if _, err := fixture.store.Policy(ctx, "beta"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("beta = %v", err)
	}
	binding, err := fixture.store.Binding(ctx, fixture.selected.ID)
	if err != nil || !slices.Equal(binding.Policies, []string{"alpha", "other"}) || binding.Revision != 1 || !binding.Applied {
		t.Fatalf("binding = %#v, %v", binding, err)
	}
	if next, err := fixture.store.NextPolicyGeneration(ctx, "beta"); err != nil || next != 1 {
		t.Fatalf("next generation = %d, %v", next, err)
	}
	identities, err := fixture.store.PolicyRetirements(ctx)
	if err != nil || !slices.Equal(identities, []string{"wyrwood-beta"}) {
		t.Fatalf("retirements = %v, %v", identities, err)
	}
}

func TestRenamePolicyMovesEverythingInOneTransaction(t *testing.T) {
	ctx := context.Background()
	fixture := newRenameFixture(t)
	beforeOther, err := fixture.store.Binding(ctx, fixture.other.ID)
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := fixture.rename(fixture.document, fixture.next)
	if err != nil {
		t.Fatal(err)
	}
	if renamed.Name != "beta" {
		t.Fatalf("renamed = %#v", renamed)
	}
	stored, err := fixture.store.Policy(ctx, "beta")
	if err != nil || stored.Policy.Revision != fixture.saved.Revision+1 || stored.Policy.Generation != 1 || stored.SavedBy != "operator-2" || stored.Policy.Name != "beta" {
		t.Fatalf("beta = %#v, %v", stored, err)
	}
	if _, err := fixture.store.Policy(ctx, "alpha"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("alpha = %v", err)
	}
	binding, err := fixture.store.Binding(ctx, fixture.selected.ID)
	if err != nil || !slices.Equal(binding.Policies, []string{"beta", "other"}) || binding.Revision != 2 || binding.Applied {
		t.Fatalf("binding = %#v, %v", binding, err)
	}
	afterOther, err := fixture.store.Binding(ctx, fixture.other.ID)
	if err != nil || afterOther.Assignment() != beforeOther.Assignment() || afterOther.Revision != beforeOther.Revision || !afterOther.Applied {
		t.Fatalf("other binding = %#v, %v", afterOther, err)
	}
	// The record of the published identity ended, and the old identity's began.
	identities, err := fixture.store.PolicyRetirements(ctx)
	if err != nil || !slices.Equal(identities, []string{"wyrwood-alpha"}) {
		t.Fatalf("retirements = %v, %v", identities, err)
	}
	// Both names' generation records stand, so neither identity is issued again.
	for name, want := range map[string]int{"alpha": 2, "beta": 2} {
		if next, err := fixture.store.NextPolicyGeneration(ctx, name); err != nil || next != want {
			t.Fatalf("next generation of %s = %d, %v", name, next, err)
		}
	}
	// The foreign key still holds: the moved row refuses a delete.
	if err := fixture.store.DeletePolicy(ctx, "beta"); err == nil {
		t.Fatal("a selected policy was deleted")
	}
}

// A failure at each later statement rolls back every earlier one.
func TestRenamePolicyRollsBackAsOneTransaction(t *testing.T) {
	for label, trigger := range map[string]string{
		"new row":      `CREATE TRIGGER injected BEFORE INSERT ON policies WHEN NEW.name = 'beta' BEGIN SELECT RAISE(ABORT, 'injected fault'); END`,
		"generation":   `CREATE TRIGGER injected BEFORE INSERT ON policy_generations WHEN NEW.name = 'beta' BEGIN SELECT RAISE(ABORT, 'injected fault'); END`,
		"membership":   `CREATE TRIGGER injected BEFORE UPDATE ON binding_policies BEGIN SELECT RAISE(ABORT, 'injected fault'); END`,
		"assignment":   `CREATE TRIGGER injected BEFORE UPDATE ON bindings BEGIN SELECT RAISE(ABORT, 'injected fault'); END`,
		"old row":      `CREATE TRIGGER injected BEFORE DELETE ON policies BEGIN SELECT RAISE(ABORT, 'injected fault'); END`,
		"attempt ends": `CREATE TRIGGER injected BEFORE DELETE ON policy_retirements BEGIN SELECT RAISE(ABORT, 'injected fault'); END`,
		"old identity": `CREATE TRIGGER injected BEFORE INSERT ON policy_retirements BEGIN SELECT RAISE(ABORT, 'injected fault'); END`,
	} {
		t.Run(label, func(t *testing.T) {
			fixture := newRenameFixture(t)
			exec(t, fixture.store.db, trigger)
			if _, err := fixture.rename(fixture.document, fixture.next); err == nil {
				t.Fatal("the fault did not reach the rename")
			}
			exec(t, fixture.store.db, `DROP TRIGGER injected`)
			fixture.wantUntouched(t)
			if _, err := fixture.rename(fixture.document, fixture.next); err != nil {
				t.Fatalf("retry = %v", err)
			}
		})
	}
}

func TestRenamePolicyRefusesWhatHasMoved(t *testing.T) {
	ctx := context.Background()
	t.Run("old name gone", func(t *testing.T) {
		fixture := newRenameFixture(t)
		_, err := fixture.store.RenamePolicy(ctx, "absent", fixture.document, nil, "operator-2", time.Now())
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("rename = %v", err)
		}
		fixture.wantUntouched(t)
	})
	t.Run("revision", func(t *testing.T) {
		fixture := newRenameFixture(t)
		moved := fixture.document
		moved.Revision++
		if _, err := fixture.rename(moved, fixture.next); !errors.Is(err, ErrConflict) {
			t.Fatalf("rename = %v", err)
		}
		fixture.wantUntouched(t)
	})
	t.Run("generation", func(t *testing.T) {
		fixture := newRenameFixture(t)
		moved := fixture.document
		moved.Generation = 2
		if _, err := fixture.rename(moved, fixture.next); !errors.Is(err, ErrConflict) {
			t.Fatalf("rename = %v", err)
		}
		fixture.wantUntouched(t)
	})
	t.Run("name in use", func(t *testing.T) {
		fixture := newRenameFixture(t)
		moved := fixture.document
		moved.Name = "other"
		moved.Generation = 2
		if _, err := fixture.rename(moved, fixture.next); !errors.Is(err, ErrConflict) {
			t.Fatalf("rename = %v", err)
		}
		fixture.document.Name = "beta"
		fixture.wantUntouched(t)
	})
	t.Run("binding not in the computation", func(t *testing.T) {
		fixture := newRenameFixture(t)
		if _, err := fixture.rename(fixture.document); !errors.Is(err, ErrConflict) {
			t.Fatalf("rename = %v", err)
		}
		fixture.wantUntouched(t)
	})
	t.Run("binding revision", func(t *testing.T) {
		fixture := newRenameFixture(t)
		moved := fixture.next
		moved.Revision = 3
		if _, err := fixture.rename(fixture.document, moved); !errors.Is(err, ErrConflict) {
			t.Fatalf("rename = %v", err)
		}
		fixture.wantUntouched(t)
	})
}

func TestPolicyRetirementRecordsAreExactAndDurable(t *testing.T) {
	ctx := context.Background()
	opened, path := openTest(t)
	now := time.Now()
	for _, identity := range []string{"wyrwood-beta", "wyrwood-alpha", "wyrwood-alpha"} {
		if err := opened.RecordPolicyRetirement(ctx, identity, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	identities, err := opened.PolicyRetirements(ctx)
	if err != nil || !slices.Equal(identities, []string{"wyrwood-alpha", "wyrwood-beta"}) {
		t.Fatalf("retirements = %v, %v", identities, err)
	}
	if err := opened.ForgetPolicyRetirement(ctx, "wyrwood-alpha"); err != nil {
		t.Fatal(err)
	}
	identities, err = opened.PolicyRetirements(ctx)
	if err != nil || !slices.Equal(identities, []string{"wyrwood-beta"}) {
		t.Fatalf("retirements = %v, %v", identities, err)
	}
}
