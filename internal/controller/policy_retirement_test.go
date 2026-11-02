// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/openbao"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
	gossh "golang.org/x/crypto/ssh"
)

// The record stays until the read-back confirms removal: a refused delete, a lost
// delete answer, a read-back that fails, and an ACL still present.
func TestRetirementRecordStaysUntilReadBackConfirmsRemoval(t *testing.T) {
	ctx := context.Background()
	for _, row := range []struct {
		label  string
		before func(string, string) error
		after  func(string, string) error
	}{
		{label: "refused delete", before: outage(callDelete)},
		{label: "lost delete answer", after: outage(callDelete)},
		{label: "failed read-back", before: outage(callExists)},
		{label: "lost read-back answer", after: outage(callExists)},
	} {
		t.Run(row.label, func(t *testing.T) {
			h, bao := startRenameHarness(t)
			c := h.controller
			saveAlpha(t, h, policy.StarterHCL)
			bao.set(row.before, row.after)
			got, err := c.RenamePolicy(ctx, requestRename(t, c, "alpha", "beta"), deleteOperator)
			var operation *OperationError
			if !errors.As(err, &operation) || got.Name != "beta" || !strings.Contains(operation.Message, "old OpenBao policy") {
				t.Fatalf("rename = %#v, %v", got, err)
			}
			wantRetirements(t, c, alphaACL)
			waitFor(t, "a retry", func() bool { return bao.count(callDelete+" "+alphaACL) >= 3 })
			wantRetirements(t, c, alphaACL)
			bao.set(nil, nil)
			waitForRetirements(t, h)
			if hasACL(t, h, alphaACL) {
				t.Fatal("old ACL stayed")
			}
		})
	}
	t.Run("still present", func(t *testing.T) {
		h, bao := startRenameHarness(t)
		c := h.controller
		saveAlpha(t, h, policy.StarterHCL)
		acl := aclOf(t, h, alphaACL)
		// OpenBao answers the delete, and the policy is written again before the
		// read-back: the record must outlive that answer.
		rewrite := func(call, name string) error {
			if call == callDelete && name == alphaACL {
				return h.bao.Root.Sys().PutPolicy(alphaACL, acl)
			}
			return nil
		}
		bao.set(nil, rewrite)
		got, err := c.RenamePolicy(ctx, requestRename(t, c, "alpha", "beta"), deleteOperator)
		if got.Name != "beta" || err == nil {
			t.Fatalf("rename = %#v, %v", got, err)
		}
		wantRetirements(t, c, alphaACL)
		bao.set(nil, nil)
		waitForRetirements(t, h)
		if hasACL(t, h, alphaACL) {
			t.Fatal("old ACL stayed")
		}
	})
}

// With nothing recorded the consumer leaves OpenBao alone, and an ordinary pending
// save keeps its existing recovery path.
func TestConsumerRunsOnlyWhileARetirementIsPending(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	c := h.controller
	saveAlpha(t, h, policy.StarterHCL)
	approveAgent(t, h, "host-a")
	binding := bindAlpha(t, h, "host-a", "web")
	bao.set(outage(callRole), nil)
	if _, err := c.SavePolicy(ctx, policy.New("alpha", policy.StarterHCL+"# edited\n"), deleteOperator); err == nil {
		t.Fatal("the fixture did not leave a pending transition")
	}
	bao.set(nil, nil)
	roleWrites := bao.count(callRole + " " + binding.Role)
	c.wakePolicyRetirements()
	time.Sleep(20 * testRetry)
	if got := bao.count(callRole + " " + binding.Role); got != roleWrites {
		t.Fatalf("role writes went from %d to %d", roleWrites, got)
	}
	if after, err := c.store.Binding(ctx, binding.ID); err != nil || after.Applied {
		t.Fatalf("binding = %#v, %v", after, err)
	}
	// Once a retirement exists it also finishes the pending save, because no
	// identity may go while a role can still name it.
	renamePolicyPending(t, h, bao)
	waitForRetirements(t, h)
	calls := len(bao.recorded())
	time.Sleep(20 * testRetry)
	if got := bao.recorded()[calls:]; len(got) != 0 {
		t.Fatalf("calls after draining = %v", got)
	}
}

func renamePolicyPending(t *testing.T, h *harness, bao *renameBao) {
	t.Helper()
	c := h.controller
	bao.set(outage(callDelete), nil)
	if got, err := c.RenamePolicy(context.Background(), requestRename(t, c, "alpha", "beta"), deleteOperator); got.Name != "beta" || err == nil {
		t.Fatalf("rename = %#v, %v", got, err)
	}
	bao.set(nil, nil)
}

// A record left by an earlier run wakes the consumer at startup.
func TestConsumerWakesAtStartupForARecordAlreadyThere(t *testing.T) {
	ctx := context.Background()
	h, _ := startRenameHarness(t)
	saveAlpha(t, h, policy.StarterHCL)
	if err := h.bao.Root.Sys().PutPolicy("wyrwood-orphan", readGrant(firstPath)); err != nil {
		t.Fatal(err)
	}
	if err := h.controller.store.RecordPolicyRetirement(ctx, "wyrwood-orphan", time.Now()); err != nil {
		t.Fatal(err)
	}
	h.stop()
	restarted, _ := restartRenameHarness(t, h.bao, h.state)
	waitForRetirements(t, restarted)
	if hasACL(t, restarted, "wyrwood-orphan") {
		t.Fatal("recorded identity stayed")
	}
}

// A publication that is pending is finished first, as a sync publishes every row
// and no identity goes while the rows are not known to be published.
func TestRetirementWaitsForAPendingPolicySync(t *testing.T) {
	h, bao := startRenameHarness(t)
	c := h.controller
	saveAlpha(t, h, policy.StarterHCL)
	bao.set(outage(callDelete), nil)
	if got, err := c.RenamePolicy(context.Background(), requestRename(t, c, "alpha", "beta"), deleteOperator); got.Name != "beta" || err == nil {
		t.Fatalf("rename = %#v, %v", got, err)
	}
	c.mutationMu.Lock()
	c.policySyncPending = true
	c.mutationMu.Unlock()
	bao.set(outage(callWrite), nil)
	deletes := bao.count(callDelete + " " + alphaACL)
	waitFor(t, "a sync attempt", func() bool { return bao.count(callWrite+" "+betaACL) >= 3 })
	if bao.count(callDelete+" "+alphaACL) != deletes {
		t.Fatalf("calls = %v", bao.recorded())
	}
	wantRetirements(t, c, alphaACL)
	bao.set(nil, nil)
	waitForRetirements(t, h)
	c.mutationMu.Lock()
	pending := c.policySyncPending
	c.mutationMu.Unlock()
	if pending {
		t.Fatal("the sync stayed pending")
	}
}

func TestPolicyExistsReadsBackOnlyManagedNames(t *testing.T) {
	ctx := context.Background()
	h, _ := startRenameHarness(t)
	saveAlpha(t, h, policy.StarterHCL)
	for name, want := range map[string]bool{alphaACL: true, "wyrwood-absent": false} {
		if exists, err := h.controller.openbao.PolicyExists(ctx, name); err != nil || exists != want {
			t.Fatalf("PolicyExists(%s) = %v, %v", name, exists, err)
		}
	}
	if _, err := h.controller.openbao.PolicyExists(ctx, "outside"); openbao.CategoryOf(err) != openbao.CategoryInvalid {
		t.Fatalf("PolicyExists(outside) = %v", err)
	}
}

// The consumer applied a binding after an outage, so a connected agent that could
// not get a credential during the outage takes one with no request of its own.
func TestConsumerPushesTheAgentsItApplied(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	c := h.controller
	saveAlpha(t, h, policy.StarterHCL)
	key := newAgentKey(t)
	if _, err := h.dial("host-a", key); err == nil {
		t.Fatal("unapproved key authenticated")
	}
	if err := c.DecideAgent(ctx, gossh.FingerprintSHA256(key.PublicKey()), true, deleteOperator); err != nil {
		t.Fatal(err)
	}
	connection, err := h.dial("host-a", key)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.client.Close()
	if err := connection.conn.Send(protocol.Hello{AgentVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	inventory := protocol.Inventory{Containers: []protocol.Container{{ID: strings.Repeat("c", 64), Name: "web", State: protocol.StateRunning, Keys: []protocol.Key{exampleKey("web")}}}}
	if err := connection.conn.Send(inventory); err != nil {
		t.Fatal(err)
	}
	binding := bindAlpha(t, h, "host-a", "web")
	waitCredential := func(assignment string) {
		t.Helper()
		for {
			if credential, ok := connection.receive(t).(protocol.Credential); ok && credential.Assignment == assignment {
				return
			}
		}
	}
	waitCredential(binding.Assignment())
	bao.set(outage(callRole), nil)
	if got, err := c.RenamePolicy(ctx, requestRename(t, c, "alpha", "beta"), deleteOperator); got.Name != "beta" || err == nil {
		t.Fatalf("rename = %#v, %v", got, err)
	}
	current, err := c.store.Binding(ctx, binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The inventory's own push can still deliver a set of the old assignment, so
	// wait for the new one. Without the push, receive times out and fails.
	for {
		if set, ok := connection.receive(t).(protocol.PolicySet); ok && len(set.Bindings) == 1 && set.Bindings[0].Assignment == current.Assignment() {
			break
		}
	}
	bao.set(nil, nil)
	waitCredential(current.Assignment())
	waitForRetirements(t, h)
}
