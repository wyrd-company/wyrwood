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
	"sync"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/policy"
)

// The old name is reused while its removal is pending. The removal deletes exactly
// the old identity, and the survivor token cannot reach the new policy.
func TestReuseOfAnOldNameWhileItsRemovalIsPending(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	c := h.controller
	writeSamples(t, h.bao)
	saveAlpha(t, h, readGrant(firstPath))
	approveAgent(t, h, "host-a")
	binding := bindAlpha(t, h, "host-a", "web")
	survivor, err := appRoleLogin(t, h.bao, binding.Role)
	if err != nil {
		t.Fatal(err)
	}
	bao.set(outage(callRole, callDelete), nil)
	if got, err := c.RenamePolicy(ctx, requestRename(t, c, "alpha", "beta"), deleteOperator); got.Name != "beta" || err == nil {
		t.Fatalf("rename = %#v, %v", got, err)
	}
	newAlpha, err := c.SavePolicy(ctx, policy.New("alpha", readGrant(secondPath)), deleteOperator)
	if err != nil {
		t.Fatal(err)
	}
	if newAlpha.OpenBaoPolicyName() != secondACL || newAlpha.Revision != 1 {
		t.Fatalf("new alpha = %#v", newAlpha)
	}
	wantRetirements(t, c, alphaACL)
	// The survivor still holds the old ACL here, and that ACL is not the new policy.
	if canRead(t, h.bao, survivor.Value(), secondPath) {
		t.Fatal("survivor reached the new policy while removal was pending")
	}
	bao.set(nil, nil)
	waitForRetirements(t, h)
	for _, call := range bao.recorded() {
		if strings.HasPrefix(call, callDelete+" ") && call != callDelete+" "+alphaACL {
			t.Fatalf("removal touched %s", call)
		}
	}
	if hasACL(t, h, alphaACL) || !hasACL(t, h, secondACL) || !hasACL(t, h, betaACL) {
		t.Fatal("wrong identities after removal")
	}
	if canRead(t, h.bao, survivor.Value(), firstPath) || canRead(t, h.bao, survivor.Value(), secondPath) {
		t.Fatal("survivor kept access")
	}
	// A new binding of the new policy is authorized on exactly that policy.
	fresh := bindAlpha(t, h, "host-a", "other")
	token, err := appRoleLogin(t, h.bao, fresh.Role)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(token.Policies, []string{secondACL}) || !canRead(t, h.bao, token.Value(), secondPath) || canRead(t, h.bao, token.Value(), firstPath) {
		t.Fatalf("new token policies = %v", token.Policies)
	}
	// The renamed policy kept its rights under its new identity.
	renamed, err := appRoleLogin(t, h.bao, binding.Role)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(renamed.Policies, []string{betaACL}) || !canRead(t, h.bao, renamed.Value(), firstPath) || canRead(t, h.bao, renamed.Value(), secondPath) {
		t.Fatalf("renamed token policies = %v", renamed.Policies)
	}
	// Negative control: were the new policy published under the old identity, the
	// survivor would reach it. Only the distinct identity refuses it.
	if err := h.bao.Root.Sys().PutPolicy(alphaACL, readGrant(secondPath)); err != nil {
		t.Fatal(err)
	}
	if !canRead(t, h.bao, survivor.Value(), secondPath) {
		t.Fatal("negative control: the survivor was refused for another reason")
	}
}

// a to b to a gives the row a new identity of a, and the first a's token is refused.
func TestRenameChainBackToTheFirstName(t *testing.T) {
	h, _ := startRenameHarness(t)
	c := h.controller
	writeSamples(t, h.bao)
	saveAlpha(t, h, readGrant(firstPath))
	approveAgent(t, h, "host-a")
	binding := bindAlpha(t, h, "host-a", "web")
	survivor, err := appRoleLogin(t, h.bao, binding.Role)
	if err != nil {
		t.Fatal(err)
	}
	renamePolicy(t, c, "alpha", "beta")
	back := renamePolicy(t, c, "beta", "alpha")
	if back.OpenBaoPolicyName() != secondACL {
		t.Fatalf("identity = %s", back.OpenBaoPolicyName())
	}
	if hasACL(t, h, alphaACL) || hasACL(t, h, betaACL) || !hasACL(t, h, secondACL) {
		t.Fatal("wrong identities after the chain")
	}
	wantRetirements(t, c)
	if canRead(t, h.bao, survivor.Value(), firstPath) {
		t.Fatal("first token kept access")
	}
	token, err := appRoleLogin(t, h.bao, binding.Role)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(token.Policies, []string{secondACL}) || !canRead(t, h.bao, token.Value(), firstPath) {
		t.Fatalf("token = %v", token.Policies)
	}
}

// a to b to c removes both old identities, also when the first is still pending.
func TestRenameChainThroughThreeNamesRemovesBothOldIdentities(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	c := h.controller
	writeSamples(t, h.bao)
	saveAlpha(t, h, readGrant(firstPath))
	approveAgent(t, h, "host-a")
	binding := bindAlpha(t, h, "host-a", "web")
	survivor, err := appRoleLogin(t, h.bao, binding.Role)
	if err != nil {
		t.Fatal(err)
	}
	bao.set(outage(callRole, callDelete), nil)
	if got, err := c.RenamePolicy(ctx, requestRename(t, c, "alpha", "beta"), deleteOperator); got.Name != "beta" || err == nil {
		t.Fatalf("first = %#v, %v", got, err)
	}
	if got, err := c.RenamePolicy(ctx, requestRename(t, c, "beta", "gamma"), deleteOperator); got.Name != "gamma" || err == nil {
		t.Fatalf("second = %#v, %v", got, err)
	}
	wantRetirements(t, c, alphaACL, betaACL)
	bao.set(nil, nil)
	waitForRetirements(t, h)
	if hasACL(t, h, alphaACL) || hasACL(t, h, betaACL) || !hasACL(t, h, gammaACL) {
		t.Fatal("wrong identities after the chain")
	}
	if canRead(t, h.bao, survivor.Value(), firstPath) {
		t.Fatal("first token kept access")
	}
	token, err := appRoleLogin(t, h.bao, binding.Role)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(token.Policies, []string{gammaACL}) || !canRead(t, h.bao, token.Value(), firstPath) {
		t.Fatalf("token = %v", token.Policies)
	}
}

// A rename onto a deleted name takes that name's next generation, so a token of
// the deleted policy has no access.
func TestRenameOntoADeletedNameTakesItsNextGeneration(t *testing.T) {
	ctx := context.Background()
	h, _ := startRenameHarness(t)
	c := h.controller
	writeSamples(t, h.bao)
	approveAgent(t, h, "host-a")
	first, err := c.SavePolicy(ctx, policy.New("beta", readGrant(secondPath)), deleteOperator)
	if err != nil {
		t.Fatal(err)
	}
	old := bindAlpha(t, h, "host-a", "old", "beta")
	survivor, err := appRoleLogin(t, h.bao, old.Role)
	if err != nil {
		t.Fatal(err)
	}
	var live *OperationError
	if err := c.DeleteBinding(ctx, old.ID, deleteOperator); err != nil && !errors.As(err, &live) {
		t.Fatal(err)
	}
	if err := c.DeletePolicy(ctx, first.Name, deleteOperator); err != nil {
		t.Fatal(err)
	}
	saveAlpha(t, h, readGrant(firstPath))
	renamed := renamePolicy(t, c, "alpha", "beta")
	if renamed.OpenBaoPolicyName() != "wyrwood-beta--2" {
		t.Fatalf("identity = %s", renamed.OpenBaoPolicyName())
	}
	if hasACL(t, h, betaACL) || !hasACL(t, h, "wyrwood-beta--2") {
		t.Fatal("wrong identities")
	}
	if canRead(t, h.bao, survivor.Value(), firstPath) || canRead(t, h.bao, survivor.Value(), secondPath) {
		t.Fatal("deleted policy's token reached the renamed policy")
	}
}

// A token whose accessor was never reported cannot be revoked. It is refused once
// the old identity is gone, on the renamed policy and on a new policy of the old
// name, across a restart. A new binding token is authorized.
func TestSurvivorTokenIsRefusedAcrossARestart(t *testing.T) {
	ctx := context.Background()
	h, _ := startRenameHarness(t)
	writeSamples(t, h.bao)
	saveAlpha(t, h, readGrant(firstPath))
	approveAgent(t, h, "host-a")
	binding := bindAlpha(t, h, "host-a", "web")
	survivor, err := appRoleLogin(t, h.bao, binding.Role)
	if err != nil {
		t.Fatal(err)
	}
	renamePolicy(t, h.controller, "alpha", "beta")
	if _, err := h.controller.SavePolicy(ctx, policy.New("alpha", readGrant(secondPath)), deleteOperator); err != nil {
		t.Fatal(err)
	}
	h.stop()
	restarted, _ := restartRenameHarness(t, h.bao, h.state)
	waitForRetirements(t, restarted)
	if canRead(t, h.bao, survivor.Value(), firstPath) || canRead(t, h.bao, survivor.Value(), secondPath) {
		t.Fatal("survivor kept access after the restart")
	}
	if hasACL(t, restarted, alphaACL) || !hasACL(t, restarted, secondACL) {
		t.Fatal("restart republished a retired identity")
	}
	fresh := bindAlpha(t, restarted, "host-a", "other")
	token, err := appRoleLogin(t, h.bao, fresh.Role)
	if err != nil {
		t.Fatal(err)
	}
	if !canRead(t, h.bao, token.Value(), secondPath) || !slices.Equal(token.Policies, []string{secondACL}) {
		t.Fatalf("new token = %v", token.Policies)
	}
}

// Held at OpenBao, a rename excludes every competing mutation.
func TestRenameHeldAtOpenBaoExcludesAConcurrentMutation(t *testing.T) {
	ctx := context.Background()
	for _, row := range []struct {
		label string
		act   func(*harness) error
		check func(*testing.T, *harness, error)
	}{
		{"save of the old name", func(h *harness) error {
			_, err := h.controller.SavePolicy(ctx, policy.New("alpha", policy.StarterHCL+"# edited\n"), deleteOperator)
			return err
		}, func(t *testing.T, h *harness, err error) {
			if err != nil {
				t.Fatalf("save = %v", err)
			}
			stored, err := h.controller.store.Policy(ctx, "alpha")
			if err != nil || stored.Policy.OpenBaoPolicyName() != secondACL || stored.Policy.Revision != 1 {
				t.Fatalf("competing save edited the renamed policy: %#v, %v", stored, err)
			}
			wantBoundToBeta(t, h)
		}},
		{"new binding of the old name", func(h *harness) error {
			_, err := h.controller.CreateBinding(ctx, "host-a", exampleKey("late"), bindRequest("alpha"), deleteOperator)
			return err
		}, func(t *testing.T, h *harness, err error) {
			if err == nil || !strings.Contains(err.Error(), "does not exist") {
				t.Fatalf("bind = %v", err)
			}
			wantBoundToBeta(t, h)
		}},
		{"rename of the same policy", func(h *harness) error {
			_, err := h.controller.RenamePolicy(ctx, PolicyRename{Name: "alpha", NewName: "gamma", Revision: 1, Generation: 1}, deleteOperator)
			return err
		}, func(t *testing.T, h *harness, err error) {
			if err == nil || !strings.Contains(err.Error(), "does not exist") {
				t.Fatalf("rename = %v", err)
			}
			if hasACL(t, h, gammaACL) {
				t.Fatal("competing rename published")
			}
			wantBoundToBeta(t, h)
		}},
	} {
		t.Run(row.label, func(t *testing.T) {
			h, bao := startRenameHarness(t)
			saveAlpha(t, h, policy.StarterHCL)
			approveAgent(t, h, "host-a")
			bindAlpha(t, h, "host-a", "web")
			held, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			bao.set(func(call, _ string) error {
				if call == callRole {
					once.Do(func() { close(held) })
					<-release
				}
				return nil
			}, nil)
			var released sync.Once
			defer released.Do(func() { close(release) })
			renameDone := make(chan error, 1)
			request := requestRename(t, h.controller, "alpha", "beta")
			go func() {
				_, err := h.controller.RenamePolicy(ctx, request, deleteOperator)
				renameDone <- err
			}()
			select {
			case <-held:
			case err := <-renameDone:
				t.Fatalf("rename did not reach the hold: %v", err)
			}
			competitor := make(chan error, 1)
			go func() { competitor <- row.act(h) }()
			select {
			case err := <-competitor:
				t.Fatalf("competitor finished during the hold: %v", err)
			case <-time.After(300 * time.Millisecond):
			}
			// The commit is durable while held, and nothing of the competitor is.
			if _, err := h.controller.store.Policy(ctx, "beta"); err != nil {
				t.Fatalf("held rename not committed: %v", err)
			}
			released.Do(func() { close(release) })
			if err := <-renameDone; err != nil {
				t.Fatalf("rename = %v", err)
			}
			row.check(t, h, <-competitor)
		})
	}
}

func wantBoundToBeta(t *testing.T, h *harness) {
	t.Helper()
	bindings, err := h.controller.store.Bindings(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bindings {
		if !slices.Equal(b.Policies, []string{"beta"}) {
			t.Fatalf("binding = %#v", b)
		}
	}
}

// The consumer held at its delete of the old identity: a save of the old name
// waits, takes the next identity, and is not touched by the removal.
func TestSaveWaitsForAHeldRemovalAndKeepsItsIdentity(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	c := h.controller
	saveAlpha(t, h, policy.StarterHCL)
	bao.set(outage(callDelete), nil)
	if got, err := c.RenamePolicy(ctx, requestRename(t, c, "alpha", "beta"), deleteOperator); got.Name != "beta" || err == nil {
		t.Fatalf("rename = %#v, %v", got, err)
	}
	held, release := make(chan struct{}), make(chan struct{})
	var once, released sync.Once
	defer released.Do(func() { close(release) })
	bao.set(func(call, _ string) error {
		if call == callDelete {
			once.Do(func() { close(held) })
			<-release
		}
		return nil
	}, nil)
	select {
	case <-held:
	case <-time.After(15 * time.Second):
		t.Fatal("the consumer did not reach its delete")
	}
	saved := make(chan error, 1)
	go func() {
		_, err := c.SavePolicy(ctx, policy.New("alpha", policy.StarterHCL), deleteOperator)
		saved <- err
	}()
	select {
	case err := <-saved:
		t.Fatalf("save finished during the hold: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if _, err := c.store.Policy(ctx, "alpha"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("new alpha during the hold = %v", err)
	}
	released.Do(func() { close(release) })
	if err := <-saved; err != nil {
		t.Fatal(err)
	}
	waitForRetirements(t, h)
	if hasACL(t, h, alphaACL) || !hasACL(t, h, secondACL) {
		t.Fatal("wrong identities")
	}
	stored, err := c.store.Policy(ctx, "alpha")
	if err != nil || stored.Policy.OpenBaoPolicyName() != secondACL {
		t.Fatalf("new alpha = %#v, %v", stored, err)
	}
}
