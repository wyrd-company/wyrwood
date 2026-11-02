// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package controller

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
)

const (
	secondACL  = "wyrwood-alpha--2"
	firstPath  = "first"
	secondPath = "second"
)

func readGrant(path string) string {
	return policy.StarterHCL + `path "kv/data/` + path + `" { capabilities = ["read"] }`
}

func canRead(t *testing.T, bao *baotest.Server, token, path string) bool {
	t.Helper()
	client, err := bao.Root.CloneWithHeaders()
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(token)
	secret, err := client.Logical().Read("kv/data/" + path)
	var response *api.ResponseError
	switch {
	case err == nil && secret != nil:
		return true
	case errors.As(err, &response) && response.StatusCode == http.StatusForbidden:
		return false
	}
	t.Fatalf("read %s: secret %v, error %v", path, secret, err)
	return false
}

func writeSamples(t *testing.T, bao *baotest.Server) {
	t.Helper()
	bao.WriteKV(t, firstPath, map[string]any{"value": "one"})
	bao.WriteKV(t, secondPath, map[string]any{"value": "two"})
}

func saveGeneration(t *testing.T, h *harness, hcl string, want int) policy.Policy {
	t.Helper()
	saved, err := h.controller.SavePolicy(context.Background(), policy.New("alpha", hcl), deleteOperator)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Generation != want {
		t.Fatalf("generation = %d, want %d", saved.Generation, want)
	}
	return saved
}

func wantNextGeneration(t *testing.T, c *Controller, want int) {
	t.Helper()
	next, err := c.store.NextPolicyGeneration(context.Background(), "alpha")
	if err != nil || next != want {
		t.Fatalf("next generation = %d, %v, want %d", next, err, want)
	}
}

func recreateAlpha(t *testing.T, h *harness, saved policy.Policy, hcl string) policy.Policy {
	t.Helper()
	if err := h.controller.DeletePolicy(context.Background(), saved.Name, deleteOperator); err != nil {
		t.Fatal(err)
	}
	return saveGeneration(t, h, hcl, saved.Generation+1)
}

// A token that outlives its binding, because no agent ever reported its accessor,
// must not reach a later policy that uses the same name.
func TestReusedNameRefusesASurvivingTokenAndAuthorizesANewBinding(t *testing.T) {
	ctx := context.Background()
	h := startHarness(t)
	c := h.controller
	writeSamples(t, h.bao)
	first := saveGeneration(t, h, readGrant(firstPath), 1)
	approveAgent(t, h, "host-a")
	binding, err := c.CreateBinding(ctx, "host-a", exampleKey("web"), bindRequest("alpha"), deleteOperator)
	if err != nil {
		t.Fatal(err)
	}
	survivor, err := appRoleLogin(t, h.bao, binding.Role)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(survivor.Policies, []string{alphaACL}) {
		t.Fatalf("survivor policies = %v", survivor.Policies)
	}
	var unbound *OperationError
	if err := c.DeleteBinding(ctx, binding.ID, deleteOperator); err != nil && !errors.As(err, &unbound) {
		t.Fatal(err)
	}
	if !canRead(t, h.bao, survivor.Value(), firstPath) {
		t.Fatal("the fixture needs a token that outlives its binding")
	}
	if err := c.DeletePolicy(ctx, "alpha", deleteOperator); err != nil {
		t.Fatal(err)
	}
	if canRead(t, h.bao, survivor.Value(), firstPath) {
		t.Fatal("a deleted policy still authorizes its token")
	}

	second := saveGeneration(t, h, readGrant(secondPath), 2)
	if second.OpenBaoPolicyName() != secondACL || second.Revision != 1 {
		t.Fatalf("second = %s revision %d", second.OpenBaoPolicyName(), second.Revision)
	}
	if acl := aclOf(t, h, secondACL); acl != second.PublishedHCL() {
		t.Fatalf("second ACL = %q", acl)
	}
	if acl := aclOf(t, h, alphaACL); acl != "" {
		t.Fatalf("the first identity came back: %q", acl)
	}
	for _, path := range []string{firstPath, secondPath} {
		if canRead(t, h.bao, survivor.Value(), path) {
			t.Fatalf("the surviving token reads %s through the recreated policy", path)
		}
	}
	rebound, err := c.CreateBinding(ctx, "host-a", exampleKey("web"), bindRequest("alpha"), deleteOperator)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := appRoleLogin(t, h.bao, rebound.Role)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fresh.Policies, []string{secondACL}) {
		t.Fatalf("fresh policies = %v", fresh.Policies)
	}
	if !canRead(t, h.bao, fresh.Value(), secondPath) || canRead(t, h.bao, fresh.Value(), firstPath) {
		t.Fatal("the new binding's token does not have exactly the recreated grant")
	}
	if !reflect.DeepEqual(rebound.Effective.OpenBaoPolicies(), []string{secondACL}) {
		t.Fatalf("assignment names %v", rebound.Effective.OpenBaoPolicies())
	}

	// Negative control: the identity alone refuses the survivor. Publishing the
	// recreated grant under the first identity authorizes the same token.
	if err := h.bao.Root.Sys().PutPolicy(first.OpenBaoPolicyName(), second.PublishedHCL()); err != nil {
		t.Fatal(err)
	}
	if !canRead(t, h.bao, survivor.Value(), secondPath) {
		t.Fatal("negative control: the survivor was not authorized by the reused identity")
	}
}

// An ordinary edit keeps the identity, so it still reaches a live token, at any
// generation.
func TestOrdinaryEditKeepsTheIdentityAndReachesALiveToken(t *testing.T) {
	for _, generation := range []int{1, 2} {
		ctx := context.Background()
		h, _, saved := startDeleteHarness(t)
		c := h.controller
		writeSamples(t, h.bao)
		if generation == 2 {
			saved = recreateAlpha(t, h, saved, policy.StarterHCL)
		}
		approveAgent(t, h, "host-a")
		binding, err := c.CreateBinding(ctx, "host-a", exampleKey("web"), bindRequest("alpha"), deleteOperator)
		if err != nil {
			t.Fatal(err)
		}
		token, err := appRoleLogin(t, h.bao, binding.Role)
		if err != nil {
			t.Fatal(err)
		}
		if canRead(t, h.bao, token.Value(), secondPath) {
			t.Fatal("the token reads before the edit")
		}
		edited, err := c.SavePolicy(ctx, policy.New("alpha", readGrant(secondPath)), deleteOperator)
		if err != nil {
			t.Fatal(err)
		}
		if edited.Generation != saved.Generation || edited.OpenBaoPolicyName() != saved.OpenBaoPolicyName() || edited.Revision != 2 {
			t.Fatalf("edit moved the policy: generation %d, %s, revision %d", edited.Generation, edited.OpenBaoPolicyName(), edited.Revision)
		}
		if !canRead(t, h.bao, token.Value(), secondPath) {
			t.Fatalf("generation %d: the edit did not reach the live token", generation)
		}
		stored, err := c.store.Binding(ctx, binding.ID)
		if err != nil || stored.Revision != 2 || !stored.Applied {
			t.Fatalf("binding = %#v, %v", stored, err)
		}
		if !reflect.DeepEqual(stored.Effective.OpenBaoPolicies(), []string{saved.OpenBaoPolicyName()}) {
			t.Fatalf("assignment names %v", stored.Effective.OpenBaoPolicies())
		}
		// Saving the same document changes nothing.
		same, err := c.SavePolicy(ctx, policy.New("alpha", readGrant(secondPath)), deleteOperator)
		if err != nil || same.Revision != 2 || same.Generation != saved.Generation {
			t.Fatalf("repeat save = revision %d generation %d, %v", same.Revision, same.Generation, err)
		}
	}
}

// A failed save of a recreated policy removes only what it published.
func TestFailedSaveOfARecreatedPolicyRemovesOnlyItsOwnIdentity(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	c := h.controller
	if err := c.DeletePolicy(ctx, saved.Name, deleteOperator); err != nil {
		t.Fatal(err)
	}
	db := stateDB(t, c)
	runSQL(t, db, `CREATE TRIGGER fail_save BEFORE INSERT ON policies BEGIN SELECT RAISE(ABORT, 'injected fault'); END`)
	if _, err := c.SavePolicy(ctx, policy.New("alpha", policy.StarterHCL), deleteOperator); err == nil {
		t.Fatal("SavePolicy() succeeded through the fault")
	}
	if !reflect.DeepEqual(bao.calls(), []string{alphaACL, secondACL}) {
		t.Fatalf("OpenBao deletes = %v", bao.calls())
	}
	if acl := aclOf(t, h, secondACL); acl != "" {
		t.Fatalf("the failed save left its OpenBao policy: %q", acl)
	}
	if c.policySyncPending {
		t.Fatal("a finished rollback left a sync pending")
	}
	wantNextGeneration(t, c, 2)

	// The same save with a failed rollback converges through the sync.
	bao.beforeDelete = func(context.Context) error { return errors.New("injected OpenBao failure") }
	if _, err := c.SavePolicy(ctx, policy.New("alpha", policy.StarterHCL), deleteOperator); err == nil {
		t.Fatal("SavePolicy() succeeded through the fault")
	}
	if !c.policySyncPending {
		t.Fatal("a failed rollback set no sync")
	}
	bao.beforeDelete = nil
	runSQL(t, db, `DROP TRIGGER fail_save`)
	retried := saveGeneration(t, h, policy.StarterHCL, 2)
	assertKept(t, h, retried)
	if err := c.reconcileBindings(ctx); err != nil {
		t.Fatal(err)
	}
	if c.policySyncPending {
		t.Fatal("the sync did not finish")
	}
	assertKept(t, h, retried)
	if acl := aclOf(t, h, alphaACL); acl != "" {
		t.Fatalf("the first identity came back: %q", acl)
	}
}

// Every failed delete of a recreated policy settles on the recreated identity. It
// never brings the first identity back, and the generation never goes back.
func TestFailedDeleteOfARecreatedPolicySettlesOnItsOwnIdentity(t *testing.T) {
	injected := errors.New("injected OpenBao failure")
	for _, row := range []struct {
		name  string
		fault func(*testing.T, *harness, *deleteHookBao, context.CancelFunc) func()
	}{
		{"OpenBao refuses", func(_ *testing.T, _ *harness, bao *deleteHookBao, _ context.CancelFunc) func() {
			bao.beforeDelete = func(context.Context) error { return injected }
			return func() { bao.beforeDelete = nil }
		}},
		{"OpenBao loses its answer", func(_ *testing.T, _ *harness, bao *deleteHookBao, _ context.CancelFunc) func() {
			bao.afterDelete = func(context.Context) error { return injected }
			return func() { bao.afterDelete = nil }
		}},
		{"store refuses", func(t *testing.T, h *harness, _ *deleteHookBao, _ context.CancelFunc) func() {
			db := stateDB(t, h.controller)
			runSQL(t, db, `CREATE TRIGGER fail_delete BEFORE DELETE ON policies BEGIN SELECT RAISE(ABORT, 'injected fault'); END`)
			return func() { runSQL(t, db, `DROP TRIGGER fail_delete`) }
		}},
		{"client drops between the deletes", func(_ *testing.T, _ *harness, bao *deleteHookBao, cancel context.CancelFunc) func() {
			bao.afterDelete = func(context.Context) error { cancel(); return nil }
			return func() { bao.afterDelete = nil }
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			h, bao, saved := startDeleteHarness(t)
			c := h.controller
			second := recreateAlpha(t, h, saved, policy.StarterHCL+`path "kv/data/sample" { capabilities = ["read"] }`)
			bao.mu.Lock()
			bao.deleted = nil
			bao.mu.Unlock()
			request, cancel := context.WithCancel(context.Background())
			defer cancel()
			clear := row.fault(t, h, bao, cancel)
			if err := c.DeletePolicy(request, "alpha", deleteOperator); err == nil {
				t.Fatal("DeletePolicy() succeeded through the fault")
			}
			clear()
			if !reflect.DeepEqual(bao.calls(), []string{secondACL}) {
				t.Fatalf("OpenBao deletes = %v", bao.calls())
			}
			assertKept(t, h, second)
			if acl := aclOf(t, h, alphaACL); acl != "" {
				t.Fatalf("the first identity came back: %q", acl)
			}
			stored, err := c.store.Policy(context.Background(), "alpha")
			if err != nil || stored.Policy.Generation != 2 {
				t.Fatalf("stored = %#v, %v", stored.Policy, err)
			}
			wantNextGeneration(t, c, 3)
			if err := c.DeletePolicy(context.Background(), "alpha", deleteOperator); err != nil {
				t.Fatal(err)
			}
			if acl := aclOf(t, h, secondACL); acl != "" {
				t.Fatalf("the retried delete left %q", acl)
			}
			third := saveGeneration(t, h, policy.StarterHCL, 3)
			assertKept(t, h, third)
		})
	}
}

// A lost store answer of a committed delete of a recreated policy is a success,
// and the next policy takes the next generation.
func TestLostAnswerOfACommittedDeleteKeepsTheGeneration(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	c := h.controller
	recreateAlpha(t, h, saved, policy.StarterHCL)
	bao.mu.Lock()
	bao.deleted = nil
	bao.mu.Unlock()
	db := stateDB(t, c)
	loseDeleteAnswers(t, db, `'alpha'`)
	if err := c.DeletePolicy(ctx, "alpha", deleteOperator); err != nil {
		t.Fatalf("DeletePolicy() = %v", err)
	}
	runSQL(t, db, `DROP TRIGGER lost_delete_answer`)
	if !reflect.DeepEqual(bao.calls(), []string{secondACL}) {
		t.Fatalf("OpenBao deletes = %v", bao.calls())
	}
	if acl := aclOf(t, h, secondACL); acl != "" {
		t.Fatalf("a committed delete was restored: %q", acl)
	}
	wantNextGeneration(t, c, 3)
	assertKept(t, h, saveGeneration(t, h, policy.StarterHCL, 3))
}

// A delete that arrives while a save of a recreated policy is at OpenBao waits
// for it, and then removes the identity that the save published.
func TestDeleteWaitsForAHeldSaveOfARecreatedPolicyAndRemovesItsIdentity(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	c := h.controller
	if err := c.DeletePolicy(ctx, saved.Name, deleteOperator); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var hold sync.Once
	bao.failWrite = func() error {
		hold.Do(func() {
			close(entered)
			<-release
		})
		return nil
	}
	type answer struct {
		saved policy.Policy
		err   error
	}
	savedAnswer := make(chan answer, 1)
	go func() {
		document, err := c.SavePolicy(ctx, policy.New("alpha", policy.StarterHCL), deleteOperator)
		savedAnswer <- answer{document, err}
	}()
	select {
	case <-entered:
	case got := <-savedAnswer:
		t.Fatalf("save ended before OpenBao: %v", got.err)
	}
	deleted := make(chan error, 1)
	go func() { deleted <- c.DeletePolicy(ctx, "alpha", deleteOperator) }()
	select {
	case err := <-deleted:
		close(release)
		<-savedAnswer
		t.Fatalf("delete finished inside the save: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if _, err := c.store.Policy(ctx, "alpha"); err == nil {
		close(release)
		<-savedAnswer
		<-deleted
		t.Fatal("the held save committed before its release")
	}
	close(release)
	got, deleteErr := <-savedAnswer, <-deleted
	if got.err != nil || got.saved.Generation != 2 {
		t.Fatalf("save = %#v, %v", got.saved, got.err)
	}
	if deleteErr != nil {
		t.Fatalf("DeletePolicy() = %v", deleteErr)
	}
	calls := bao.calls()
	if len(calls) != 2 || calls[1] != secondACL {
		t.Fatalf("OpenBao deletes = %v", calls)
	}
	if acl := aclOf(t, h, secondACL); acl != "" {
		t.Fatalf("the delete left %q", acl)
	}
	wantNextGeneration(t, c, 3)
}

// The delete event names the policy, and the reused identity reaches only OpenBao.
func TestDeletingARecreatedPolicyRecordsItsName(t *testing.T) {
	ctx := context.Background()
	h, _, saved := startDeleteHarness(t)
	c := h.controller
	recreateAlpha(t, h, saved, policy.StarterHCL)
	if err := c.DeletePolicy(ctx, "alpha", deleteOperator); err != nil {
		t.Fatal(err)
	}
	wantEvent(t, lastDeleteEvent(t, c), "alpha", events.OutcomeOK, events.ErrorNone)
}
