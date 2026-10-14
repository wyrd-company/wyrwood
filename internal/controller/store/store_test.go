// ---
// relationships:
//   verifies: controller
// ---

package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "controller.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path
}

func TestPendingApprovalAndNameUniqueness(t *testing.T) {
	ctx := context.Background()
	store, path := openTest(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	first, err := store.RecordKey(ctx, "SHA256:first", "host-a", "ssh-ed25519 AAAA", now)
	if err != nil || first.State != AgentPending || first.Name != "host-a" {
		t.Fatalf("RecordKey() = %#v, %v", first, err)
	}
	again, err := store.RecordKey(ctx, "SHA256:first", "renamed", "ssh-ed25519 AAAA", now.Add(time.Hour))
	if err != nil || again.Name != "renamed" || !again.FirstSeen.Equal(now) {
		t.Fatalf("RecordKey(again) = %#v, %v", again, err)
	}
	if _, err := store.RecordKey(ctx, "SHA256:first", "host-a", "ssh-ed25519 AAAA", now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DecideAgent(ctx, "SHA256:first", AgentApproved, "operator-1", now); err != nil {
		t.Fatal(err)
	}
	if renamed, _ := store.RecordKey(ctx, "SHA256:first", "attacker", "ssh-ed25519 AAAA", now); renamed.Name != "host-a" {
		t.Fatalf("approved agent renamed to %q", renamed.Name)
	}
	if _, err := store.DecideAgent(ctx, "SHA256:first", AgentRejected, "operator-1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second decision = %v", err)
	}
	if _, err := store.RecordKey(ctx, "SHA256:second", "host-a", "ssh-ed25519 BBBB", now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DecideAgent(ctx, "SHA256:second", AgentApproved, "operator-1", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate approved name = %v, want ErrConflict", err)
	}
	approved, err := store.ApprovedAgent(ctx, "host-a")
	if err != nil || approved.Fingerprint != "SHA256:first" || approved.DecidedBy != "operator-1" {
		t.Fatalf("ApprovedAgent() = %#v, %v", approved, err)
	}
	agents, err := store.Agents(ctx)
	if err != nil || len(agents) != 2 || agents[0].State != AgentPending {
		t.Fatalf("Agents() = %#v, %v", agents, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode = %v, %v", info.Mode(), err)
	}
}

func TestPoliciesBindingsInventoryAndResults(t *testing.T) {
	ctx := context.Background()
	store, _ := openTest(t)
	now := time.Now().UTC()
	saved, err := store.SavePolicy(ctx, policy.New("teal", `path "kv/*" {}`), "operator-1", now)
	if err != nil || saved.Revision != 1 {
		t.Fatalf("SavePolicy() = %#v, %v", saved, err)
	}
	saved, err = store.SavePolicy(ctx, saved, "operator-2", now)
	if err != nil || saved.Revision != 2 {
		t.Fatalf("SavePolicy(again) = %#v, %v", saved, err)
	}
	stored, err := store.Policy(ctx, "teal")
	if err != nil || stored.Policy.Revision != 2 || stored.SavedBy != "operator-2" {
		t.Fatalf("Policy() = %#v, %v", stored, err)
	}
	binding := Binding{ID: "b-1", Agent: "host-a", Key: protocol.Key{Kind: protocol.KeyName, Value: "web"},
		Policy: "teal", Role: "wyrwood-host-a-b-1", CreatedAt: now, CreatedBy: "operator-1"}
	if err := store.CreateBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	duplicate := binding
	duplicate.ID = "b-2"
	if err := store.CreateBinding(ctx, duplicate); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate binding = %v", err)
	}
	unknownPolicy := binding
	unknownPolicy.ID = "b-3"
	unknownPolicy.Key.Value = "other"
	unknownPolicy.Policy = "missing"
	if err := store.CreateBinding(ctx, unknownPolicy); !errors.Is(err, ErrConflict) {
		t.Fatalf("binding to unknown policy = %v", err)
	}
	containers := []protocol.Container{{ID: strings.Repeat("a", 64), Name: "web", State: protocol.StateRunning, Keys: []protocol.Key{{Kind: protocol.KeyName, Value: "web"}}}}
	if err := store.SaveInventory(ctx, "host-a", "SHA256:none", containers, now); err != nil {
		t.Fatal(err)
	}
	inventory, _, err := store.Inventory(ctx, "host-a")
	if err != nil || len(inventory) != 1 || inventory[0].Name != "web" {
		t.Fatalf("Inventory() = %#v, %v", inventory, err)
	}
	if err := store.SaveContractResult(ctx, protocol.ContractResult{Binding: "b-1", Outcome: protocol.OutcomeNonConforming,
		FailedItems: []protocol.FailedItem{protocol.FailedMount}}, now); err != nil {
		t.Fatal(err)
	}
	results, err := store.ContractResults(ctx)
	if err != nil || results["b-1"].Outcome != protocol.OutcomeNonConforming || len(results["b-1"].FailedItems) != 1 {
		t.Fatalf("ContractResults() = %#v, %v", results, err)
	}
	if _, err := store.TokenAccessor(ctx, "b-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("TokenAccessor(none reported) = %v", err)
	}
	for _, accessor := range []string{"accessor-first", "accessor-second"} {
		if err := store.SaveTokenAccessor(ctx, "b-1", accessor, now); err != nil {
			t.Fatal(err)
		}
	}
	if accessor, err := store.TokenAccessor(ctx, "b-1"); err != nil || accessor != "accessor-second" {
		t.Fatalf("TokenAccessor() = %q, %v; want the latest report", accessor, err)
	}
	if err := store.SaveTokenAccessor(ctx, "b-missing", "accessor", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SaveTokenAccessor(unknown binding) = %v", err)
	}
	if accessor, err := store.RetireBinding(ctx, "b-1", now); err != nil || accessor != "accessor-second" {
		t.Fatalf("RetireBinding() = %q, %v; want the latest accessor", accessor, err)
	}
	if agent, err := store.RetiredBindingAgent(ctx, "b-1"); err != nil || agent != "host-a" {
		t.Fatalf("RetiredBindingAgent() = %q, %v", agent, err)
	}
	if _, err := store.RetiredBindingAgent(ctx, "b-never"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RetiredBindingAgent(never bound) = %v", err)
	}
	if _, err := store.RetireBinding(ctx, "b-1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RetireBinding(again) = %v", err)
	}
	results, _ = store.ContractResults(ctx)
	if len(results) != 0 {
		t.Fatalf("contract results outlived their binding: %#v", results)
	}
	if _, err := store.TokenAccessor(ctx, "b-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("token accessor outlived its binding: %v", err)
	}
}
