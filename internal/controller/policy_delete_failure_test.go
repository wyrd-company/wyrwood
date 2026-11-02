// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package controller

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao"
	"github.com/wyrd-company/wyrwood/internal/policy"
)

func TestDeletePolicyKeepsThePolicyWhenOpenBaoFails(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	bao.beforeDelete = func(context.Context) error { return &openbao.Error{Category: openbao.CategoryUnavailable} }
	err := h.controller.DeletePolicy(ctx, saved.Name, deleteOperator)
	var operation *OperationError
	if !errors.As(err, &operation) || operation.Code != events.ErrorOpenBaoUnavailable || operation.PolicyMissing {
		t.Fatalf("DeletePolicy = %#v", err)
	}
	assertKept(t, h, saved)
	if h.controller.policySyncPending {
		t.Fatal("a restored policy left a sync pending")
	}
	wantEvent(t, lastDeleteEvent(t, h.controller), saved.Name, events.OutcomeFailed, events.ErrorOpenBaoUnavailable)
	bao.beforeDelete = nil
	if err := h.controller.DeletePolicy(ctx, saved.Name, deleteOperator); err != nil {
		t.Fatal(err)
	}
	assertGone(t, h, saved.Name)
}

// A response lost after OpenBao deleted the policy must not leave the stored
// policy without its OpenBao policy.
func TestDeletePolicyRestoresAfterALostOpenBaoAnswer(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	bao.afterDelete = func(context.Context) error { return errors.New("test lost response") }
	if err := h.controller.DeletePolicy(ctx, saved.Name, deleteOperator); err == nil {
		t.Fatal("a lost answer reported success")
	}
	assertKept(t, h, saved)
	bao.afterDelete = nil
	if err := h.controller.DeletePolicy(ctx, saved.Name, deleteOperator); err != nil {
		t.Fatal(err)
	}
	assertGone(t, h, saved.Name)
}

func TestDeletePolicyLeavesASyncPendingWhenRestorationFails(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	bao.afterDelete = func(context.Context) error { return errors.New("test lost response") }
	bao.failWrite = func() error { return &openbao.Error{Category: openbao.CategoryUnavailable} }
	if err := h.controller.DeletePolicy(ctx, saved.Name, deleteOperator); err == nil {
		t.Fatal("a lost answer reported success")
	}
	if !h.controller.policySyncPending {
		t.Fatal("failed restoration left no sync pending")
	}
	if acl := aclOf(t, h, alphaACL); acl != "" {
		t.Fatalf("OpenBao policy = %q, the fault did not reach the restoration", acl)
	}
	bao.afterDelete, bao.failWrite = nil, nil
	if err := h.controller.reconcileBindings(ctx); err != nil {
		t.Fatal(err)
	}
	if h.controller.policySyncPending {
		t.Fatal("reconcile left the sync pending")
	}
	assertKept(t, h, saved)
	if err := h.controller.DeletePolicy(ctx, saved.Name, deleteOperator); err != nil {
		t.Fatal(err)
	}
	assertGone(t, h, saved.Name)
}

func TestDeletePolicyRestoresWhenTheStoreDeleteFails(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	db := stateDB(t, h.controller)
	runSQL(t, db, `CREATE TRIGGER refuse_delete BEFORE DELETE ON policies BEGIN SELECT RAISE(ABORT, 'test refusal'); END`)
	err := h.controller.DeletePolicy(ctx, saved.Name, deleteOperator)
	var operation *OperationError
	if !errors.As(err, &operation) || operation.Code != events.ErrorInternal {
		t.Fatalf("DeletePolicy = %#v", err)
	}
	if !reflect.DeepEqual(bao.calls(), []string{alphaACL}) {
		t.Fatalf("OpenBao deletes = %v, the store fault was not reached", bao.calls())
	}
	assertKept(t, h, saved)
	if h.controller.policySyncPending {
		t.Fatal("a restored policy left a sync pending")
	}
	wantEvent(t, lastDeleteEvent(t, h.controller), saved.Name, events.OutcomeFailed, events.ErrorInternal)
	runSQL(t, db, `DROP TRIGGER refuse_delete`)
	if err := h.controller.DeletePolicy(ctx, saved.Name, deleteOperator); err != nil {
		t.Fatal(err)
	}
	assertGone(t, h, saved.Name)
}

// The credential path is the running controller's consumer of a pending sync: no
// operator, browser, or retried delete is needed to restore the OpenBao policy.
func TestPendingRestorationConvergesThroughTheCredentialPath(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	c := h.controller
	approveAgent(t, h, "host-a")
	if _, err := c.SavePolicy(ctx, policy.New("other", policy.StarterHCL), deleteOperator); err != nil {
		t.Fatal(err)
	}
	binding, err := c.CreateBinding(ctx, "host-a", exampleKey("example"), bindRequest("other"), deleteOperator)
	if err != nil {
		t.Fatal(err)
	}
	db := stateDB(t, c)
	runSQL(t, db, `CREATE TRIGGER refuse_delete BEFORE DELETE ON policies BEGIN SELECT RAISE(ABORT, 'test refusal'); END`)
	bao.failWrite = func() error { return &openbao.Error{Category: openbao.CategoryUnavailable} }
	if err := c.DeletePolicy(ctx, saved.Name, deleteOperator); err == nil {
		t.Fatal("failed delete reported success")
	}
	if !c.policySyncPending || aclOf(t, h, alphaACL) != "" {
		t.Fatalf("pending = %v, OpenBao policy = %q", c.policySyncPending, aclOf(t, h, alphaACL))
	}
	session := &agentSession{controller: c, agent: "host-a"}
	// While OpenBao still fails, fresh issuance stays blocked.
	if credential := session.prepareCredential(ctx, binding); credential != nil {
		t.Fatal("issued a credential while a restoration was pending")
	}
	bao.failWrite = nil
	runSQL(t, db, `DROP TRIGGER refuse_delete`)
	if credential := session.prepareCredential(ctx, binding); credential == nil {
		t.Fatal("no credential after OpenBao recovered")
	}
	if c.policySyncPending {
		t.Fatal("the sync stayed pending")
	}
	assertKept(t, h, saved)
	if err := c.DeletePolicy(ctx, saved.Name, deleteOperator); err != nil {
		t.Fatal(err)
	}
	assertGone(t, h, saved.Name)
	again, err := c.SavePolicy(ctx, policy.New(saved.Name, policy.StarterHCL), deleteOperator)
	if err != nil || again.Revision != 1 {
		t.Fatalf("reused name = %#v %v", again, err)
	}
	assertKept(t, h, again)
}

// A closed browser cancels the request between the two deletes.
func TestDeletePolicyRestoresWhenTheRequestEndsBetweenTheDeletes(t *testing.T) {
	h, bao, saved := startDeleteHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bao.afterDelete = func(context.Context) error {
		cancel()
		return nil
	}
	if err := h.controller.DeletePolicy(ctx, saved.Name, deleteOperator); err == nil {
		t.Fatal("a cancelled delete reported success")
	}
	bao.afterDelete = nil
	assertKept(t, h, saved)
	if err := h.controller.DeletePolicy(context.Background(), saved.Name, deleteOperator); err != nil {
		t.Fatal(err)
	}
	assertGone(t, h, saved.Name)
}

// A binding that reaches the store past the controller's own check is refused by
// the foreign key, and the OpenBao policy comes back.
func TestStoreForeignKeyRefusesABindingThatArrivesAfterTheCheck(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	approveAgent(t, h, "host-a")
	bao.afterDelete = func(context.Context) error {
		return h.controller.store.CreateBinding(ctx, store.Binding{ID: "b-late", Agent: "host-a", Key: exampleKey("late"), Policies: []string{saved.Name}, Revision: 1})
	}
	// The hook's nil answer lets the delete continue to the store.
	if err := h.controller.DeletePolicy(ctx, saved.Name, deleteOperator); err == nil {
		t.Fatal("deleted a policy that a binding selects")
	}
	assertKept(t, h, saved)
	if _, err := h.controller.store.Binding(ctx, "b-late"); err != nil {
		t.Fatalf("late binding: %v", err)
	}
}

// The answer of a committed store delete can be lost. A restoration would leave
// an OpenBao policy that nothing removes.
func TestCommittedStoreDeleteIsNotRestored(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	c := h.controller
	stored, err := c.store.Policy(ctx, saved.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := bao.OpenBao.DeletePolicy(ctx, alphaACL); err != nil {
		t.Fatal(err)
	}
	if err := c.store.DeletePolicy(ctx, saved.Name); err != nil {
		t.Fatal(err)
	}
	if err := c.settleFailedPolicyDelete(ctx, stored); err != nil {
		t.Fatalf("settle = %v, want success", err)
	}
	if c.policySyncPending {
		t.Fatal("a committed delete left a sync pending")
	}
	assertGone(t, h, saved.Name)
}

// With the store unreadable, whether the row is gone is unknown. The sync
// publishes exactly the rows that exist, so it is right in both cases.
func TestUnreadableStoreAfterAFailedDeleteConvergesThroughTheSync(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	db := stateDB(t, h.controller)
	bao.afterDelete = func(context.Context) error {
		runSQL(t, db, `ALTER TABLE policies RENAME TO policies_unavailable`)
		return nil
	}
	err := h.controller.DeletePolicy(ctx, saved.Name, deleteOperator)
	var operation *OperationError
	if !errors.As(err, &operation) || operation.Code != events.ErrorInternal {
		t.Fatalf("DeletePolicy = %#v", err)
	}
	if !h.controller.policySyncPending {
		t.Fatal("no sync pending")
	}
	if acl := aclOf(t, h, alphaACL); acl != "" {
		t.Fatalf("restored before the store could be read: %q", acl)
	}
	bao.afterDelete = nil
	runSQL(t, db, `ALTER TABLE policies_unavailable RENAME TO policies`)
	if err := h.controller.reconcileBindings(ctx); err != nil {
		t.Fatal(err)
	}
	assertKept(t, h, saved)
	if err := h.controller.DeletePolicy(ctx, saved.Name, deleteOperator); err != nil {
		t.Fatal(err)
	}
	assertGone(t, h, saved.Name)
}

// The delete holds the mutation lock at its OpenBao call. A bind that selects the
// policy waits, and then finds it gone.
func TestBindWaitsForAHeldDeleteAndThenFindsThePolicyGone(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	c := h.controller
	approveAgent(t, h, "host-a")
	entered, release := make(chan struct{}), make(chan struct{})
	bao.beforeDelete = func(context.Context) error {
		close(entered)
		<-release
		return nil
	}
	deleted := make(chan error, 1)
	go func() { deleted <- c.DeletePolicy(ctx, saved.Name, deleteOperator) }()
	select {
	case <-entered:
	case err := <-deleted:
		t.Fatalf("delete ended before OpenBao: %v", err)
	}
	bound := make(chan error, 1)
	go func() {
		_, err := c.CreateBinding(ctx, "host-a", exampleKey("example"), bindRequest(saved.Name), deleteOperator)
		bound <- err
	}()
	select {
	case err := <-bound:
		close(release)
		<-deleted
		t.Fatalf("bind finished inside the delete: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	if err := <-deleted; err != nil {
		t.Fatal(err)
	}
	if err := <-bound; err == nil {
		t.Fatal("bound a deleted policy")
	}
	assertGone(t, h, saved.Name)
	bindings, err := c.store.Bindings(ctx, "")
	if err != nil || len(bindings) != 0 {
		t.Fatalf("bindings = %v %v", bindings, err)
	}
}

// The bind holds the mutation lock at its OpenBao call. A delete waits, and then
// finds the binding and refuses.
func TestDeleteWaitsForAHeldBindAndThenRefuses(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	c := h.controller
	approveAgent(t, h, "host-a")
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	bao.writeRole = func() {
		once.Do(func() {
			close(entered)
			<-release
		})
	}
	bound := make(chan error, 1)
	go func() {
		_, err := c.CreateBinding(ctx, "host-a", exampleKey("example"), bindRequest(saved.Name), deleteOperator)
		bound <- err
	}()
	select {
	case <-entered:
	case err := <-bound:
		t.Fatalf("bind ended before OpenBao: %v", err)
	}
	deleted := make(chan error, 1)
	go func() { deleted <- c.DeletePolicy(ctx, saved.Name, deleteOperator) }()
	select {
	case err := <-deleted:
		close(release)
		<-bound
		t.Fatalf("delete finished inside the bind: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	if err := <-bound; err != nil {
		t.Fatal(err)
	}
	err := <-deleted
	var operation *OperationError
	if !errors.As(err, &operation) || !operation.PolicyBound {
		t.Fatalf("DeletePolicy = %#v", err)
	}
	if len(bao.calls()) != 0 {
		t.Fatal("a bound policy reached OpenBao")
	}
	assertKept(t, h, saved)
}

// A binding change takes the same lock as a bind.
func TestBindingChangeWaitsForAHeldDeleteAndThenFindsThePolicyGone(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	c := h.controller
	approveAgent(t, h, "host-a")
	if _, err := c.SavePolicy(ctx, policy.New("other", policy.StarterHCL), deleteOperator); err != nil {
		t.Fatal(err)
	}
	binding, err := c.CreateBinding(ctx, "host-a", exampleKey("example"), bindRequest("other"), deleteOperator)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	bao.beforeDelete = func(context.Context) error {
		close(entered)
		<-release
		return nil
	}
	deleted := make(chan error, 1)
	go func() { deleted <- c.DeletePolicy(ctx, saved.Name, deleteOperator) }()
	select {
	case <-entered:
	case err := <-deleted:
		t.Fatalf("delete ended before OpenBao: %v", err)
	}
	changed := make(chan error, 1)
	go func() {
		changed <- c.ChangeBinding(ctx, binding.ID, BindingRequest{Policies: []string{"other", saved.Name}, Revision: binding.Revision}, deleteOperator)
	}()
	select {
	case err := <-changed:
		close(release)
		<-deleted
		t.Fatalf("change finished inside the delete: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	if err := <-deleted; err != nil {
		t.Fatal(err)
	}
	if err := <-changed; err == nil {
		t.Fatal("changed a binding to a deleted policy")
	}
	assertGone(t, h, saved.Name)
	current, err := c.store.Binding(ctx, binding.ID)
	if err != nil || current.HasPolicy(saved.Name) {
		t.Fatalf("binding = %#v, %v", current, err)
	}
}
