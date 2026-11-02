// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package controller

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/policy"
)

// A write refused before it landed changes nothing, the name's next generation
// included.
func TestRenameWriteFailureChangesNothing(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	saved := saveAlpha(t, h, policy.StarterHCL)
	approveAgent(t, h, "host-a")
	binding := bindAlpha(t, h, "host-a", "web")
	bao.set(func(call, name string) error {
		if call == callWrite && name == betaACL {
			return unavailable()
		}
		return nil
	}, nil)
	got, err := h.controller.RenamePolicy(ctx, requestRename(t, h.controller, "alpha", "beta"), deleteOperator)
	if err == nil || got.Name != "" || !strings.Contains(err.Error(), "nothing changed") {
		t.Fatalf("rename = %#v, %v", got, err)
	}
	bao.set(nil, nil)
	assertKept(t, h, saved)
	wantRetirements(t, h.controller)
	if hasACL(t, h, betaACL) {
		t.Fatal("new ACL landed")
	}
	after, err := h.controller.store.Binding(ctx, binding.ID)
	if err != nil || after.Assignment() != binding.Assignment() || !after.Applied {
		t.Fatalf("binding = %#v, %v", after, err)
	}
	if next, err := h.controller.store.NextPolicyGeneration(ctx, "beta"); err != nil || next != 1 {
		t.Fatalf("next generation = %d, %v", next, err)
	}
	event := lastRenameEvent(t, h.controller)
	if event.Outcome != events.OutcomeFailed || event.ErrorCode != events.ErrorOpenBaoUnavailable {
		t.Fatalf("event = %#v", event)
	}
	renamePolicy(t, h.controller, "alpha", "beta")
}

// A lost answer of a write that landed: the attempt's identity is removed, now
// when OpenBao answers, and through the consumer when it does not.
func TestRenameLostWriteAnswerLeavesNoIdentity(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	saved := saveAlpha(t, h, policy.StarterHCL)
	lost := func(call, name string) error {
		if call == callWrite && name == betaACL {
			return unavailable()
		}
		return nil
	}
	bao.set(nil, lost)
	if _, err := h.controller.RenamePolicy(ctx, requestRename(t, h.controller, "alpha", "beta"), deleteOperator); err == nil || !strings.Contains(err.Error(), "nothing changed") {
		t.Fatalf("rename = %v", err)
	}
	assertKept(t, h, saved)
	wantRetirements(t, h.controller)
	if hasACL(t, h, betaACL) {
		t.Fatal("the attempt left its identity")
	}

	bao.set(outage(callDelete), lost)
	if _, err := h.controller.RenamePolicy(ctx, requestRename(t, h.controller, "alpha", "beta"), deleteOperator); err == nil || !strings.Contains(err.Error(), "keeps its name") {
		t.Fatalf("rename = %v", err)
	}
	assertKept(t, h, saved)
	wantRetirements(t, h.controller, betaACL)
	if !hasACL(t, h, betaACL) {
		t.Fatal("the fixture did not leave an identity")
	}
	bao.set(nil, nil)
	waitForRetirements(t, h)
	if hasACL(t, h, betaACL) {
		t.Fatal("the consumer did not remove the attempt's identity")
	}
	if next, err := h.controller.store.NextPolicyGeneration(ctx, "beta"); err != nil || next != 1 {
		t.Fatalf("next generation = %d, %v", next, err)
	}
	if renamed := renamePolicy(t, h.controller, "alpha", "beta"); renamed.OpenBaoPolicyName() != betaACL {
		t.Fatalf("renamed = %#v", renamed)
	}
	if !hasACL(t, h, betaACL) {
		t.Fatal("the rename after the cleanup has no ACL")
	}
}

// A policy created while the cleanup of a failed attempt is pending takes that
// identity, and the record must not remove it.
func TestRenameAttemptRecordDoesNotRemoveAPolicyThatTookTheIdentity(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	saveAlpha(t, h, policy.StarterHCL)
	lost := func(call, name string) error {
		if call == callWrite && name == betaACL {
			return unavailable()
		}
		return nil
	}
	bao.set(outage(callDelete), lost)
	if _, err := h.controller.RenamePolicy(ctx, requestRename(t, h.controller, "alpha", "beta"), deleteOperator); err == nil {
		t.Fatal("rename succeeded")
	}
	bao.set(outage(callDelete), nil)
	beta, err := h.controller.SavePolicy(ctx, policy.New("beta", policy.StarterHCL), deleteOperator)
	if err != nil {
		t.Fatal(err)
	}
	if beta.OpenBaoPolicyName() != betaACL {
		t.Fatalf("beta = %#v", beta)
	}
	calls := bao.count(callDelete + " " + betaACL)
	bao.set(nil, nil)
	h.controller.wakePolicyRetirements()
	waitForRetirements(t, h)
	if !hasACL(t, h, betaACL) || bao.count(callDelete+" "+betaACL) != calls {
		t.Fatalf("held identity removed: %v", bao.recorded())
	}
}

func failRenameCommit(t *testing.T, h *harness) func() {
	t.Helper()
	db := stateDB(t, h.controller)
	runSQL(t, db, `CREATE TRIGGER fail_rename BEFORE INSERT ON policy_generations WHEN NEW.name = 'beta' BEGIN SELECT RAISE(ABORT, 'injected fault'); END`)
	return func() { runSQL(t, db, `DROP TRIGGER fail_rename`) }
}

// A store refusal rolls back everything, and what the attempt published goes.
func TestRenameStoreFailureLeavesTheOldPolicy(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	saved := saveAlpha(t, h, policy.StarterHCL)
	approveAgent(t, h, "host-a")
	binding := bindAlpha(t, h, "host-a", "web")
	heal := failRenameCommit(t, h)
	got, err := h.controller.RenamePolicy(ctx, requestRename(t, h.controller, "alpha", "beta"), deleteOperator)
	if err == nil || got.Name != "" || !strings.Contains(err.Error(), "nothing changed") {
		t.Fatalf("rename = %#v, %v", got, err)
	}
	assertKept(t, h, saved)
	wantRetirements(t, h.controller)
	if hasACL(t, h, betaACL) {
		t.Fatal("the attempt left its identity")
	}
	after, err := h.controller.store.Binding(ctx, binding.ID)
	if err != nil || after.Assignment() != binding.Assignment() || !after.Applied || !slices.Equal(after.Policies, []string{"alpha"}) {
		t.Fatalf("binding = %#v, %v", after, err)
	}
	if bao.count(callDelete+" "+alphaACL) != 0 {
		t.Fatalf("calls = %v", bao.recorded())
	}
	heal()
	renamePolicy(t, h.controller, "alpha", "beta")
}

// The commit happened and its answer did not arrive: the read-back keeps it, and
// the identity it published stays.
func TestRenameLostCommitAnswerIsNotUndone(t *testing.T) {
	ctx := context.Background()
	h, _ := startRenameHarness(t)
	c := h.controller
	saved := saveAlpha(t, h, policy.StarterHCL)
	document := saved.Clone()
	document.Name, document.Generation, document.Revision = "beta", 1, saved.Revision+1
	if err := c.openbao.WritePolicy(ctx, betaACL, document.PublishedHCL()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.RenamePolicy(ctx, "alpha", document, nil, deleteOperator, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := c.settleFailedRename(ctx, document); err != nil {
		t.Fatalf("settle = %v", err)
	}
	if !hasACL(t, h, betaACL) {
		t.Fatal("a committed rename lost its identity")
	}
}

// Not knowing whether the commit happened removes nothing now: the consumer
// finishes whichever way it went, from the records the commit leaves.
func TestRenameUnreadableStoreAfterAFailedCommitRemovesNothing(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	c := h.controller
	saved := saveAlpha(t, h, policy.StarterHCL)
	document := saved.Clone()
	document.Name, document.Generation, document.Revision = "beta", 1, saved.Revision+1
	db := stateDB(t, c)
	if err := c.store.RecordPolicyRetirement(ctx, betaACL, time.Now()); err != nil {
		t.Fatal(err)
	}
	runSQL(t, db, `ALTER TABLE policies RENAME TO policies_unreadable`)
	err := c.settleFailedRename(ctx, document)
	runSQL(t, db, `ALTER TABLE policies_unreadable RENAME TO policies`)
	if err == nil || !strings.Contains(err.Error(), "could not be confirmed") {
		t.Fatalf("settle = %v", err)
	}
	if bao.count(callDelete+" "+betaACL) != 0 {
		t.Fatalf("calls = %v", bao.recorded())
	}
	wantRetirements(t, c, betaACL)
}

// One binding cannot be applied after the commit. The operator sees it pending,
// the old ACL stays, and the server finishes without a client.
func TestRenamePendingTransitionConvergesWithoutAClient(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	c := h.controller
	writeSamples(t, h.bao)
	saveAlpha(t, h, readGrant(firstPath))
	approveAgent(t, h, "host-a")
	first := bindAlpha(t, h, "host-a", "one")
	second := bindAlpha(t, h, "host-a", "two")
	firstToken := reportToken(t, h, first)
	blocked := func(call, name string) error {
		if call == callRole && name == second.Role {
			return unavailable()
		}
		return nil
	}
	bao.set(blocked, nil)
	got, err := c.RenamePolicy(ctx, requestRename(t, c, "alpha", "beta"), deleteOperator)
	var operation *OperationError
	if !errors.As(err, &operation) || got.Name != "beta" || !strings.Contains(operation.Message, "pending") || operation.Code != events.ErrorOpenBaoUnavailable {
		t.Fatalf("rename = %#v, %v", got, err)
	}
	event := lastRenameEvent(t, c)
	if event.Outcome != events.OutcomeFailed || event.NewPolicy != "beta" {
		t.Fatalf("event = %#v", event)
	}
	// The pending binding keeps its old role, so the old ACL must stay; the
	// binding that was applied has already moved.
	if !hasACL(t, h, alphaACL) || !hasACL(t, h, betaACL) {
		t.Fatal("ACL removed while a binding depends on it")
	}
	wantRetirements(t, c, alphaACL)
	if after, err := c.store.Binding(ctx, second.ID); err != nil || after.Applied {
		t.Fatalf("second = %#v, %v", after, err)
	}
	if got := loginPolicies(t, h, second.Role); !slices.Equal(got, []string{alphaACL}) {
		t.Fatalf("pending role = %v", got)
	}
	if got := loginPolicies(t, h, first.Role); !slices.Equal(got, []string{betaACL}) {
		t.Fatalf("applied role = %v", got)
	}
	if tokenValid(t, h.bao, firstToken) {
		t.Fatal("old token of the applied binding stayed valid")
	}
	// Several failed passes run while the outage holds, and none removes the ACL.
	waitFor(t, "a retry", func() bool { return bao.count(callRole+" "+second.Role) >= 4 })
	if bao.count(callDelete+" "+alphaACL) != 0 {
		t.Fatalf("calls = %v", bao.recorded())
	}
	bao.set(nil, nil)
	waitForRetirements(t, h)
	if hasACL(t, h, alphaACL) || !hasACL(t, h, betaACL) {
		t.Fatal("cleanup did not converge")
	}
	if after, err := c.store.Binding(ctx, second.ID); err != nil || !after.Applied {
		t.Fatalf("second = %#v, %v", after, err)
	}
	if got := loginPolicies(t, h, second.Role); !slices.Equal(got, []string{betaACL}) {
		t.Fatalf("pending role after recovery = %v", got)
	}
}

// A revocation that fails holds the binding pending, so the old token stays
// revocable, and the same retries finish it.
func TestRenameRevocationFailureHoldsTheOldACL(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	c := h.controller
	saveAlpha(t, h, policy.StarterHCL)
	approveAgent(t, h, "host-a")
	binding := bindAlpha(t, h, "host-a", "web")
	token := reportToken(t, h, binding)
	bao.set(outage(callRevoke), nil)
	got, err := c.RenamePolicy(ctx, requestRename(t, c, "alpha", "beta"), deleteOperator)
	if got.Name != "beta" || err == nil {
		t.Fatalf("rename = %#v, %v", got, err)
	}
	if !hasACL(t, h, alphaACL) || !tokenValid(t, h.bao, token) {
		t.Fatal("the fixture did not hold the transition")
	}
	wantRetirements(t, c, alphaACL)
	bao.set(nil, nil)
	waitForRetirements(t, h)
	if tokenValid(t, h.bao, token) || hasACL(t, h, alphaACL) {
		t.Fatal("transition did not converge")
	}
	after, err := c.store.Binding(ctx, binding.ID)
	if err != nil || !after.Applied {
		t.Fatalf("binding = %#v, %v", after, err)
	}
}

// A controller that restarts after the commit, before the old ACL goes, removes
// it from durable state alone.
func TestRestartAfterCommitRemovesTheOldACL(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	saveAlpha(t, h, policy.StarterHCL)
	approveAgent(t, h, "host-a")
	binding := bindAlpha(t, h, "host-a", "web")
	bao.set(outage(callRole, callDelete), nil)
	if got, err := h.controller.RenamePolicy(ctx, requestRename(t, h.controller, "alpha", "beta"), deleteOperator); got.Name != "beta" || err == nil {
		t.Fatalf("rename = %#v, %v", got, err)
	}
	h.stop()

	restarted, _ := restartRenameHarness(t, h.bao, h.state)
	waitForRetirements(t, restarted)
	if hasACL(t, restarted, alphaACL) || !hasACL(t, restarted, betaACL) {
		t.Fatal("restart did not converge")
	}
	after, err := restarted.controller.store.Binding(ctx, binding.ID)
	if err != nil || !after.Applied || !slices.Equal(after.Effective.OpenBaoPolicies(), []string{betaACL}) {
		t.Fatalf("binding = %#v, %v", after, err)
	}
	if got := loginPolicies(t, restarted, binding.Role); !slices.Equal(got, []string{betaACL}) {
		t.Fatalf("role = %v", got)
	}
}

// A restart before the commit leaves only the attempt's record, and the name it
// tried stays free at its next generation.
func TestRestartBeforeCommitRemovesTheAttemptsIdentity(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	saved := saveAlpha(t, h, policy.StarterHCL)
	heal := failRenameCommit(t, h)
	bao.set(outage(callDelete), nil)
	if _, err := h.controller.RenamePolicy(ctx, requestRename(t, h.controller, "alpha", "beta"), deleteOperator); err == nil || !strings.Contains(err.Error(), "keeps its name") {
		t.Fatalf("rename = %v", err)
	}
	heal()
	wantRetirements(t, h.controller, betaACL)
	if !hasACL(t, h, betaACL) {
		t.Fatal("the fixture did not leave an identity")
	}
	h.stop()

	restarted, _ := restartRenameHarness(t, h.bao, h.state)
	waitForRetirements(t, restarted)
	if hasACL(t, restarted, betaACL) {
		t.Fatal("restart left the attempt's identity")
	}
	assertKept(t, restarted, saved)
	if next, err := restarted.controller.store.NextPolicyGeneration(ctx, "beta"); err != nil || next != 1 {
		t.Fatalf("next generation = %d, %v", next, err)
	}
}

// The client that started the rename goes away and the server still finishes.
func TestRenameConvergesAfterTheClientIsGone(t *testing.T) {
	h, bao := startRenameHarness(t)
	c := h.controller
	saveAlpha(t, h, policy.StarterHCL)
	approveAgent(t, h, "host-a")
	binding := bindAlpha(t, h, "host-a", "web")
	ctx, cancel := context.WithCancel(context.Background())
	bao.set(func(call, _ string) error {
		if call == callRole {
			cancel()
			return context.Canceled
		}
		return nil
	}, nil)
	got, err := c.RenamePolicy(ctx, requestRename(t, c, "alpha", "beta"), deleteOperator)
	if got.Name != "beta" || err == nil {
		t.Fatalf("rename = %#v, %v", got, err)
	}
	bao.set(nil, nil)
	waitForRetirements(t, h)
	after, err := c.store.Binding(context.Background(), binding.ID)
	if err != nil || !after.Applied || hasACL(t, h, alphaACL) {
		t.Fatalf("binding = %#v, %v", after, err)
	}
}

// With no durable record of the attempt nothing is published.
func TestRenameRefusedWhenTheAttemptCannotBeRecorded(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	saved := saveAlpha(t, h, policy.StarterHCL)
	db := stateDB(t, h.controller)
	runSQL(t, db, `CREATE TRIGGER fail_record BEFORE INSERT ON policy_retirements BEGIN SELECT RAISE(ABORT, 'injected fault'); END`)
	calls := len(bao.recorded())
	if _, err := h.controller.RenamePolicy(ctx, requestRename(t, h.controller, "alpha", "beta"), deleteOperator); err == nil || !strings.Contains(err.Error(), "nothing changed") {
		t.Fatalf("rename = %v", err)
	}
	runSQL(t, db, `DROP TRIGGER fail_record`)
	if len(bao.recorded()) != calls {
		t.Fatalf("calls = %v", bao.recorded()[calls:])
	}
	assertKept(t, h, saved)
}

// The store fails after the commit, at each later write. The record outlives
// the failure, and the consumer finishes.
func TestRenameConvergesWhenTheStoreFailsAfterTheCommit(t *testing.T) {
	ctx := context.Background()
	for label, trigger := range map[string]string{
		"marking the binding applied": `CREATE TRIGGER fail_later BEFORE UPDATE OF applied ON bindings WHEN NEW.applied = 1 BEGIN SELECT RAISE(ABORT, 'injected fault'); END`,
		"ending the record":           `CREATE TRIGGER fail_later BEFORE DELETE ON policy_retirements WHEN OLD.identity = 'wyrwood-alpha' BEGIN SELECT RAISE(ABORT, 'injected fault'); END`,
	} {
		t.Run(label, func(t *testing.T) {
			h, _ := startRenameHarness(t)
			c := h.controller
			saveAlpha(t, h, policy.StarterHCL)
			approveAgent(t, h, "host-a")
			binding := bindAlpha(t, h, "host-a", "web")
			db := stateDB(t, c)
			runSQL(t, db, trigger)
			got, err := c.RenamePolicy(ctx, requestRename(t, c, "alpha", "beta"), deleteOperator)
			if got.Name != "beta" || err == nil {
				t.Fatalf("rename = %#v, %v", got, err)
			}
			wantRetirements(t, c, alphaACL)
			runSQL(t, db, `DROP TRIGGER fail_later`)
			waitForRetirements(t, h)
			after, err := c.store.Binding(ctx, binding.ID)
			if err != nil || !after.Applied || hasACL(t, h, alphaACL) {
				t.Fatalf("binding = %#v, %v", after, err)
			}
		})
	}
}
