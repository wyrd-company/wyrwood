// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package controller

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
	gossh "golang.org/x/crypto/ssh"
)

const (
	deleteOperator = "operator-1"
	alphaACL       = "wyrwood-alpha"
)

// deleteHookBao records every DeletePolicy and runs hooks around the real calls.
type deleteHookBao struct {
	OpenBao
	mu           sync.Mutex
	deleted      []string
	beforeDelete func(context.Context) error
	afterDelete  func(context.Context) error
	writeRole    func()
	failWrite    func() error
}

func (wrapped *deleteHookBao) DeletePolicy(ctx context.Context, name string) error {
	wrapped.mu.Lock()
	wrapped.deleted = append(wrapped.deleted, name)
	wrapped.mu.Unlock()
	if wrapped.beforeDelete != nil {
		if err := wrapped.beforeDelete(ctx); err != nil {
			return err
		}
	}
	if err := wrapped.OpenBao.DeletePolicy(ctx, name); err != nil {
		return err
	}
	if wrapped.afterDelete != nil {
		return wrapped.afterDelete(ctx)
	}
	return nil
}

func (wrapped *deleteHookBao) WritePolicy(ctx context.Context, name, hcl string) error {
	if wrapped.failWrite != nil {
		if err := wrapped.failWrite(); err != nil {
			return err
		}
	}
	return wrapped.OpenBao.WritePolicy(ctx, name, hcl)
}

func (wrapped *deleteHookBao) WriteRole(ctx context.Context, role string, policies []string, ttl, maxTTL time.Duration) error {
	if wrapped.writeRole != nil {
		wrapped.writeRole()
	}
	return wrapped.OpenBao.WriteRole(ctx, role, policies, ttl, maxTTL)
}

func (wrapped *deleteHookBao) calls() []string {
	wrapped.mu.Lock()
	defer wrapped.mu.Unlock()
	return append([]string(nil), wrapped.deleted...)
}

func startDeleteHarness(t *testing.T) (*harness, *deleteHookBao, policy.Policy) {
	t.Helper()
	bao := &deleteHookBao{}
	h := startHarnessWith(t, func(real OpenBao) OpenBao {
		bao.OpenBao = real
		return bao
	})
	document := policy.New("alpha", policy.StarterHCL)
	saved, err := h.controller.SavePolicy(context.Background(), document, deleteOperator)
	if err != nil {
		t.Fatal(err)
	}
	return h, bao, saved
}

func aclOf(t *testing.T, h *harness, name string) string {
	t.Helper()
	acl, err := h.bao.Root.Sys().GetPolicy(name)
	if err != nil {
		t.Fatal(err)
	}
	return acl
}

func stateDB(t *testing.T, c *Controller) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(c.config.StateDirectory, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func runSQL(t *testing.T, db *sql.DB, statement string) {
	t.Helper()
	if _, err := db.Exec(statement); err != nil {
		t.Fatal(err)
	}
}

// assertKept fails unless the policy and its OpenBao policy are both as saved.
func assertKept(t *testing.T, h *harness, saved policy.Policy) {
	t.Helper()
	stored, err := h.controller.store.Policy(context.Background(), saved.Name)
	if err != nil {
		t.Fatalf("stored policy: %v", err)
	}
	if stored.Policy.Revision != saved.Revision {
		t.Fatalf("revision = %d, want %d", stored.Policy.Revision, saved.Revision)
	}
	if acl := aclOf(t, h, saved.OpenBaoPolicyName()); acl != saved.PublishedHCL() {
		t.Fatalf("OpenBao policy = %q, want the stored HCL", acl)
	}
}

// assertGone fails unless the policy and its OpenBao policy are both gone.
func assertGone(t *testing.T, h *harness, name string) {
	t.Helper()
	if _, err := h.controller.store.Policy(context.Background(), name); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stored policy lookup = %v, want not found", err)
	}
	if acl := aclOf(t, h, "wyrwood-"+name); acl != "" {
		t.Fatalf("OpenBao policy remains: %q", acl)
	}
}

func lastDeleteEvent(t *testing.T, c *Controller) events.Event {
	t.Helper()
	var last *events.Event
	recent := c.Events().Recent(1000)
	for index := range recent {
		if recent[index].Operation == events.OperationPolicyDeleted {
			last = &recent[index]
		}
	}
	if last == nil {
		t.Fatal("no policy-deleted event")
	}
	return *last
}

func wantEvent(t *testing.T, event events.Event, name string, outcome events.Outcome, code events.ErrorCode) {
	t.Helper()
	if event.Policy != name || event.Outcome != outcome || event.ErrorCode != code || event.Operator != deleteOperator {
		t.Fatalf("event = %#v, want policy %q, outcome %s, code %q, operator %s", event, name, outcome, code, deleteOperator)
	}
}

func approveAgent(t *testing.T, h *harness, name string) {
	t.Helper()
	key := newAgentKey(t)
	_, _ = h.dial(name, key)
	if err := h.controller.DecideAgent(context.Background(), gossh.FingerprintSHA256(key.PublicKey()), true, deleteOperator); err != nil {
		t.Fatal(err)
	}
}

func bindRequest(names ...string) BindingRequest { return BindingRequest{Policies: names} }

func exampleKey(value string) protocol.Key { return protocol.Key{Kind: protocol.KeyName, Value: value} }

func TestDeletePolicyRemovesExactlyItsOpenBaoPolicyAndRow(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	c := h.controller
	other, err := c.SavePolicy(ctx, policy.New("alpha-two", policy.StarterHCL+`path "kv/data/other" { capabilities = ["read"] }`), deleteOperator)
	if err != nil {
		t.Fatal(err)
	}
	controllerACL := aclOf(t, h, baotest.ControllerName)
	if err := c.DeletePolicy(ctx, saved.Name, deleteOperator); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bao.calls(), []string{alphaACL}) {
		t.Fatalf("OpenBao deletes = %v", bao.calls())
	}
	assertGone(t, h, saved.Name)
	assertKept(t, h, other)
	if acl := aclOf(t, h, baotest.ControllerName); acl == "" || acl != controllerACL {
		t.Fatal("the controller's policy changed")
	}
	wantEvent(t, lastDeleteEvent(t, c), saved.Name, events.OutcomeOK, events.ErrorNone)
}

func TestDeletePolicyAcceptsAnAbsentOpenBaoPolicy(t *testing.T) {
	ctx := context.Background()
	h, _, saved := startDeleteHarness(t)
	if err := h.bao.Root.Sys().DeletePolicy(alphaACL); err != nil {
		t.Fatal(err)
	}
	if err := h.controller.DeletePolicy(ctx, saved.Name, deleteOperator); err != nil {
		t.Fatal(err)
	}
	assertGone(t, h, saved.Name)
}

func TestNewPolicyWithADeletedNameStartsAtRevisionOneAndWorks(t *testing.T) {
	ctx := context.Background()
	h, _, saved := startDeleteHarness(t)
	c := h.controller
	edited := saved.Clone()
	edited.OpenBao.Policy += `path "kv/data/sample" { capabilities = ["read"] }`
	if _, err := c.SavePolicy(ctx, edited, deleteOperator); err != nil {
		t.Fatal(err)
	}
	if err := c.DeletePolicy(ctx, saved.Name, deleteOperator); err != nil {
		t.Fatal(err)
	}
	again, err := c.SavePolicy(ctx, policy.New(saved.Name, policy.StarterHCL), deleteOperator)
	if err != nil {
		t.Fatal(err)
	}
	if again.Revision != 1 {
		t.Fatalf("revision = %d, want 1", again.Revision)
	}
	assertKept(t, h, again)
	approveAgent(t, h, "host-a")
	binding, err := c.CreateBinding(ctx, "host-a", exampleKey("example"), bindRequest(saved.Name), deleteOperator)
	if err != nil {
		t.Fatal(err)
	}
	token, err := appRoleLogin(t, h.bao, binding.Role)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(token.Policies, []string{alphaACL}) {
		t.Fatalf("token policies = %v", token.Policies)
	}
}

func TestDeletePolicyRefusedWhileABindingSelectsIt(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	c := h.controller
	approveAgent(t, h, "host-a")
	// The agent reports no inventory: the binding's container is not reported.
	binding, err := c.CreateBinding(ctx, "host-a", exampleKey("not-reported"), bindRequest(saved.Name), deleteOperator)
	if err != nil {
		t.Fatal(err)
	}
	err = c.DeletePolicy(ctx, saved.Name, deleteOperator)
	var operation *OperationError
	if !errors.As(err, &operation) || !operation.PolicyBound || operation.Code != events.ErrorPolicyDenied {
		t.Fatalf("DeletePolicy(bound) = %#v", err)
	}
	if calls := bao.calls(); len(calls) != 0 {
		t.Fatalf("a bound policy reached OpenBao: %v", calls)
	}
	assertKept(t, h, saved)
	current, err := c.store.Binding(ctx, binding.ID)
	if err != nil || current.Revision != binding.Revision || !current.HasPolicy(saved.Name) {
		t.Fatalf("binding changed: %#v %v", current, err)
	}
	wantEvent(t, lastDeleteEvent(t, c), saved.Name, events.OutcomeDenied, events.ErrorPolicyDenied)
	if err := c.DeleteBinding(ctx, binding.ID, deleteOperator); err != nil {
		var unbound *OperationError
		if !errors.As(err, &unbound) || !unbound.TokenLive {
			t.Fatal(err)
		}
	}
	if err := c.DeletePolicy(ctx, saved.Name, deleteOperator); err != nil {
		t.Fatal(err)
	}
	assertGone(t, h, saved.Name)
}

func TestDeletePolicyRefusedForABindingOnAnAgentThatIsNotApproved(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	now := time.Now().UTC()
	if _, err := h.controller.store.RecordKey(ctx, "pending-agent", "pending-agent", "ssh-ed25519 AAAA", now); err != nil {
		t.Fatal(err)
	}
	if err := h.controller.store.CreateBinding(ctx, store.Binding{ID: "b-pending", Agent: "pending-agent", Key: exampleKey("pending"), Policies: []string{saved.Name}, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	err := h.controller.DeletePolicy(ctx, saved.Name, deleteOperator)
	var operation *OperationError
	if !errors.As(err, &operation) || !operation.PolicyBound {
		t.Fatalf("DeletePolicy(unapproved binding) = %#v", err)
	}
	if len(bao.calls()) != 0 {
		t.Fatal("a bound policy reached OpenBao")
	}
	assertKept(t, h, saved)
}

func TestDeletePolicyRefusedWhenBindingsCannotBeRead(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	approveAgent(t, h, "host-a")
	binding, err := h.controller.CreateBinding(ctx, "host-a", exampleKey("example"), bindRequest(saved.Name), deleteOperator)
	if err != nil {
		t.Fatal(err)
	}
	db := stateDB(t, h.controller)
	runSQL(t, db, `UPDATE bindings SET effective = 'not json' WHERE id = '`+binding.ID+`'`)
	err = h.controller.DeletePolicy(ctx, saved.Name, deleteOperator)
	var operation *OperationError
	if !errors.As(err, &operation) || operation.Code != events.ErrorInternal || operation.PolicyBound {
		t.Fatalf("DeletePolicy(unreadable bindings) = %#v", err)
	}
	if len(bao.calls()) != 0 {
		t.Fatal("an unconfirmed policy reached OpenBao")
	}
	assertKept(t, h, saved)
	wantEvent(t, lastDeleteEvent(t, h.controller), saved.Name, events.OutcomeFailed, events.ErrorInternal)
}

func TestDeletePolicyOfACraftedNameReachesNothing(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	controllerACL := aclOf(t, h, baotest.ControllerName)
	for _, name := range []string{"", "../controller", "wyrwood-alpha/../controller", "ALPHA", "alpha/", "alpha\n", "-alpha", "alpha--two", string(make([]byte, 65))} {
		err := h.controller.DeletePolicy(ctx, name, deleteOperator)
		var operation *OperationError
		if !errors.As(err, &operation) || !operation.PolicyMissing {
			t.Fatalf("DeletePolicy(%q) = %#v", name, err)
		}
		wantEvent(t, lastDeleteEvent(t, h.controller), "", events.OutcomeDenied, events.ErrorPolicyDenied)
	}
	// A row that a crafted name selects is not read: only name validation stands
	// between such a row and the delete.
	runSQL(t, stateDB(t, h.controller), `INSERT INTO policies (name, revision, document, saved_at, saved_by) VALUES ('../controller', 1, '{}', 0, '')`)
	err := h.controller.DeletePolicy(ctx, "../controller", deleteOperator)
	var crafted *OperationError
	if !errors.As(err, &crafted) || !crafted.PolicyMissing {
		t.Fatalf("DeletePolicy(stored crafted name) = %#v", err)
	}
	// A valid name reaches only its own managed OpenBao policy, and only when stored.
	for _, name := range []string{"controller", "namespace-admin"} {
		err := h.controller.DeletePolicy(ctx, name, deleteOperator)
		var operation *OperationError
		if !errors.As(err, &operation) || !operation.PolicyMissing {
			t.Fatalf("DeletePolicy(%q) = %#v", name, err)
		}
	}
	if len(bao.calls()) != 0 {
		t.Fatalf("OpenBao deletes = %v", bao.calls())
	}
	if aclOf(t, h, baotest.ControllerName) != controllerACL {
		t.Fatal("the controller's policy changed")
	}
	assertKept(t, h, saved)
}

func TestDeletePolicyTwiceSaysItIsAlreadyGone(t *testing.T) {
	ctx := context.Background()
	h, bao, saved := startDeleteHarness(t)
	if err := h.controller.DeletePolicy(ctx, saved.Name, deleteOperator); err != nil {
		t.Fatal(err)
	}
	err := h.controller.DeletePolicy(ctx, saved.Name, deleteOperator)
	var operation *OperationError
	if !errors.As(err, &operation) || !operation.PolicyMissing || operation.Code != events.ErrorPolicyDenied {
		t.Fatalf("second delete = %#v", err)
	}
	if len(bao.calls()) != 1 {
		t.Fatalf("OpenBao deletes = %v", bao.calls())
	}
	wantEvent(t, lastDeleteEvent(t, h.controller), saved.Name, events.OutcomeDenied, events.ErrorPolicyDenied)
}
