// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package controller

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
	gossh "golang.org/x/crypto/ssh"
)

const (
	betaACL    = "wyrwood-beta"
	gammaACL   = "wyrwood-gamma"
	callWrite  = "write-policy"
	callDelete = "delete-policy"
	callExists = "policy-exists"
	callRole   = "write-role"
	callRevoke = "revoke"
	testRetry  = 20 * time.Millisecond
)

// renameBao records every managed call against real OpenBao and runs hooks around
// it. A before hook that answers an error stops the call. An after hook that
// answers an error loses the answer of a call that happened.
type renameBao struct {
	OpenBao
	mu     sync.Mutex
	calls  []string
	before func(call, name string) error
	after  func(call, name string) error
}

func unavailable() error { return &openbao.Error{Category: openbao.CategoryUnavailable} }

func (wrapped *renameBao) set(before, after func(call, name string) error) {
	wrapped.mu.Lock()
	defer wrapped.mu.Unlock()
	wrapped.before, wrapped.after = before, after
}

func (wrapped *renameBao) enter(call, name string) (func(call, name string) error, error) {
	wrapped.mu.Lock()
	wrapped.calls = append(wrapped.calls, call+" "+name)
	before, after := wrapped.before, wrapped.after
	wrapped.mu.Unlock()
	if before != nil {
		if err := before(call, name); err != nil {
			return nil, err
		}
	}
	return after, nil
}

func leave(after func(call, name string) error, call, name string, err error) error {
	if err == nil && after != nil {
		return after(call, name)
	}
	return err
}

func (wrapped *renameBao) WritePolicy(ctx context.Context, name, hcl string) error {
	after, err := wrapped.enter(callWrite, name)
	if err != nil {
		return err
	}
	return leave(after, callWrite, name, wrapped.OpenBao.WritePolicy(ctx, name, hcl))
}

func (wrapped *renameBao) DeletePolicy(ctx context.Context, name string) error {
	after, err := wrapped.enter(callDelete, name)
	if err != nil {
		return err
	}
	return leave(after, callDelete, name, wrapped.OpenBao.DeletePolicy(ctx, name))
}

func (wrapped *renameBao) PolicyExists(ctx context.Context, name string) (bool, error) {
	after, err := wrapped.enter(callExists, name)
	if err != nil {
		return false, err
	}
	exists, err := wrapped.OpenBao.PolicyExists(ctx, name)
	return exists, leave(after, callExists, name, err)
}

func (wrapped *renameBao) WriteRole(ctx context.Context, role string, policies []string, ttl, maxTTL time.Duration) error {
	after, err := wrapped.enter(callRole, role)
	if err != nil {
		return err
	}
	return leave(after, callRole, role, wrapped.OpenBao.WriteRole(ctx, role, policies, ttl, maxTTL))
}

func (wrapped *renameBao) RevokeAccessor(ctx context.Context, accessor string) error {
	after, err := wrapped.enter(callRevoke, accessor)
	if err != nil {
		return err
	}
	return leave(after, callRevoke, accessor, wrapped.OpenBao.RevokeAccessor(ctx, accessor))
}

func (wrapped *renameBao) recorded() []string {
	wrapped.mu.Lock()
	defer wrapped.mu.Unlock()
	return slices.Clone(wrapped.calls)
}

func (wrapped *renameBao) count(call string) int {
	total := 0
	for _, recorded := range wrapped.recorded() {
		if recorded == call {
			total++
		}
	}
	return total
}

func outage(calls ...string) func(string, string) error {
	return func(call, _ string) error {
		if slices.Contains(calls, call) {
			return unavailable()
		}
		return nil
	}
}

func startRenameHarness(t *testing.T) (*harness, *renameBao) {
	t.Helper()
	return restartRenameHarness(t, baotest.Start(t), t.TempDir())
}

func restartRenameHarness(t *testing.T, bao *baotest.Server, state string) (*harness, *renameBao) {
	t.Helper()
	wrapped := &renameBao{}
	h := runHarness(t, bao, state, func(real OpenBao) OpenBao {
		wrapped.OpenBao = real
		return wrapped
	}, testRetry)
	return h, wrapped
}

func requestRename(t *testing.T, c *Controller, name, newName string) PolicyRename {
	t.Helper()
	stored, err := c.store.Policy(context.Background(), name)
	if err != nil {
		t.Fatalf("policy %s: %v", name, err)
	}
	return PolicyRename{Name: name, NewName: newName, Revision: stored.Policy.Revision, Generation: stored.Policy.Generation}
}

func renamePolicy(t *testing.T, c *Controller, name, newName string) policy.Policy {
	t.Helper()
	renamed, err := c.RenamePolicy(context.Background(), requestRename(t, c, name, newName), deleteOperator)
	if err != nil {
		t.Fatalf("rename %s to %s: %v", name, newName, err)
	}
	return renamed
}

func wantRetirements(t *testing.T, c *Controller, want ...string) {
	t.Helper()
	got, err := c.store.PolicyRetirements(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, want) && !(len(got) == 0 && len(want) == 0) {
		t.Fatalf("retirements = %v, want %v", got, want)
	}
}

func hasACL(t *testing.T, h *harness, identity string) bool {
	t.Helper()
	return aclOf(t, h, identity) != ""
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitForRetirements(t *testing.T, h *harness) {
	t.Helper()
	waitFor(t, "retirements to drain", func() bool {
		identities, err := h.controller.store.PolicyRetirements(context.Background())
		return err == nil && len(identities) == 0
	})
}

func lastRenameEvent(t *testing.T, c *Controller) events.Event {
	t.Helper()
	recent := c.events.Recent(100)
	for index := len(recent) - 1; index >= 0; index-- {
		if recent[index].Operation == events.OperationPolicyRenamed {
			return recent[index]
		}
	}
	t.Fatal("no policy-renamed event")
	return events.Event{}
}

func renameEvents(c *Controller) int {
	total := 0
	for _, event := range c.events.Recent(1000) {
		if event.Operation == events.OperationPolicyRenamed {
			total++
		}
	}
	return total
}

func saveAlpha(t *testing.T, h *harness, hcl string) policy.Policy {
	t.Helper()
	saved, err := h.controller.SavePolicy(context.Background(), policy.New("alpha", hcl), deleteOperator)
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

func bindAlpha(t *testing.T, h *harness, agent, container string, names ...string) store.Binding {
	t.Helper()
	if len(names) == 0 {
		names = []string{"alpha"}
	}
	binding, err := h.controller.CreateBinding(context.Background(), agent, exampleKey(container), bindRequest(names...), deleteOperator)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := h.controller.store.Binding(context.Background(), binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// reportToken logs in as the binding and records the token's accessor, as a
// connected agent reports it.
func reportToken(t *testing.T, h *harness, binding store.Binding) openbao.Token {
	t.Helper()
	token, err := appRoleLogin(t, h.bao, binding.Role)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.controller.store.SaveAssignmentAccessor(context.Background(), binding, token.Accessor, time.Now()); err != nil {
		t.Fatal(err)
	}
	return token
}

func loginPolicies(t *testing.T, h *harness, role string) []string {
	t.Helper()
	token, err := appRoleLogin(t, h.bao, role)
	if err != nil {
		t.Fatal(err)
	}
	return token.Policies
}

// An unbound rename keeps the document and ACL text, and takes the next identity.
func TestRenameMovesAnUnboundPolicyToTheNewNamesIdentity(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	saved := saveAlpha(t, h, readGrant(firstPath))
	acl := aclOf(t, h, alphaACL)
	renamed := renamePolicy(t, h.controller, "alpha", "beta")
	if renamed.Name != "beta" || renamed.Generation != 1 || renamed.Revision != saved.Revision+1 || renamed.OpenBao.Policy != saved.OpenBao.Policy {
		t.Fatalf("renamed = %#v", renamed)
	}
	stored, err := h.controller.store.Policy(ctx, "beta")
	if err != nil || stored.Policy.Revision != renamed.Revision || stored.Policy.Generation != 1 || stored.SavedBy != deleteOperator {
		t.Fatalf("stored = %#v, %v", stored, err)
	}
	if _, err := h.controller.store.Policy(ctx, "alpha"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old row = %v", err)
	}
	if aclOf(t, h, betaACL) != acl {
		t.Fatalf("new ACL text = %q, want %q", aclOf(t, h, betaACL), acl)
	}
	if hasACL(t, h, alphaACL) {
		t.Fatal("old ACL stayed")
	}
	wantRetirements(t, h.controller)
	if bao.count(callDelete+" "+alphaACL) != 1 || bao.count(callExists+" "+alphaACL) != 1 {
		t.Fatalf("calls = %v", bao.recorded())
	}
	event := lastRenameEvent(t, h.controller)
	if event.Policy != "alpha" || event.NewPolicy != "beta" || event.Outcome != events.OutcomeOK || event.Operator != deleteOperator {
		t.Fatalf("event = %#v", event)
	}
	// The old name's record stays, so a later alpha has its own identity.
	wantNextGeneration(t, h.controller, 2)
}

func TestRenameToTheSameNameChangesNothing(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	saved := saveAlpha(t, h, policy.StarterHCL)
	binding := bindAlpha(t, h, approvedHostA(t, h), "web")
	calls := len(bao.recorded())
	got, err := h.controller.RenamePolicy(ctx, PolicyRename{Name: "alpha", NewName: "alpha"}, deleteOperator)
	if err != nil || got.Revision != saved.Revision {
		t.Fatalf("rename = %#v, %v", got, err)
	}
	stored, err := h.controller.store.Policy(ctx, "alpha")
	if err != nil || stored.Policy.Revision != saved.Revision {
		t.Fatalf("stored = %#v, %v", stored, err)
	}
	after, err := h.controller.store.Binding(ctx, binding.ID)
	if err != nil || after.Assignment() != binding.Assignment() {
		t.Fatalf("binding changed: %v", err)
	}
	if len(bao.recorded()) != calls || renameEvents(h.controller) != 0 {
		t.Fatalf("calls = %v, events = %d", bao.recorded()[calls:], renameEvents(h.controller))
	}
	wantRetirements(t, h.controller)
}

func approvedHostA(t *testing.T, h *harness) string {
	t.Helper()
	approveAgent(t, h, "host-a")
	return "host-a"
}

// Each refusal has its own valid fixture, so that no other guard answers it.
func TestRenameRefusals(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	saved := saveAlpha(t, h, policy.StarterHCL)
	if _, err := h.controller.SavePolicy(ctx, policy.New("taken", policy.StarterHCL), deleteOperator); err != nil {
		t.Fatal(err)
	}
	current := requestRename(t, h.controller, "alpha", "beta")
	for _, row := range []struct {
		label       string
		request     PolicyRename
		want        string
		missing     bool
		wantNew     string
		wantOld     string
		wantOutcome events.Outcome
	}{
		{label: "invalid", request: PolicyRename{Name: "alpha", NewName: "Not Valid", Revision: current.Revision, Generation: current.Generation}, want: "lower-kebab-case", wantOld: "alpha", wantOutcome: events.OutcomeDenied},
		{label: "generation spelling", request: PolicyRename{Name: "alpha", NewName: "alpha--2", Revision: current.Revision, Generation: current.Generation}, want: "lower-kebab-case", wantOld: "alpha", wantOutcome: events.OutcomeDenied},
		{label: "too long", request: PolicyRename{Name: "alpha", NewName: strings.Repeat("a", 65), Revision: current.Revision, Generation: current.Generation}, want: "lower-kebab-case", wantOld: "alpha", wantOutcome: events.OutcomeDenied},
		{label: "in use", request: PolicyRename{Name: "alpha", NewName: "taken", Revision: current.Revision, Generation: current.Generation}, want: "already in use", wantNew: "taken", wantOld: "alpha", wantOutcome: events.OutcomeDenied},
		{label: "stale revision", request: PolicyRename{Name: "alpha", NewName: "beta", Revision: current.Revision + 1, Generation: current.Generation}, want: "reload", wantNew: "beta", wantOld: "alpha", wantOutcome: events.OutcomeDenied},
		{label: "stale generation", request: PolicyRename{Name: "alpha", NewName: "beta", Revision: current.Revision, Generation: current.Generation + 1}, want: "reload", wantNew: "beta", wantOld: "alpha", wantOutcome: events.OutcomeDenied},
		{label: "missing", request: PolicyRename{Name: "absent", NewName: "beta", Revision: 1, Generation: 1}, want: "does not exist", missing: true, wantNew: "beta", wantOld: "absent", wantOutcome: events.OutcomeDenied},
		{label: "crafted", request: PolicyRename{Name: "../alpha", NewName: "beta", Revision: 1, Generation: 1}, want: "does not exist", missing: true, wantNew: "beta", wantOutcome: events.OutcomeDenied},
	} {
		t.Run(row.label, func(t *testing.T) {
			calls := len(bao.recorded())
			got, err := h.controller.RenamePolicy(ctx, row.request, deleteOperator)
			var operation *OperationError
			if !errors.As(err, &operation) || !strings.Contains(operation.Message, row.want) || operation.PolicyMissing != row.missing || got.Name != "" {
				t.Fatalf("rename = %#v, %v", got, err)
			}
			if len(bao.recorded()) != calls {
				t.Fatalf("OpenBao calls = %v", bao.recorded()[calls:])
			}
			assertKept(t, h, saved)
			wantRetirements(t, h.controller)
			event := lastRenameEvent(t, h.controller)
			if event.Policy != row.wantOld || event.NewPolicy != row.wantNew || event.Outcome != row.wantOutcome {
				t.Fatalf("event = %#v", event)
			}
		})
	}
}

// Other policies and the selection of a multi-policy binding are untouched, and
// the sort order of the new name does not disturb composition.
func TestRenameMovesEveryAffectedBindingOnEveryAgent(t *testing.T) {
	ctx := context.Background()
	h, _ := startRenameHarness(t)
	c := h.controller
	writeSamples(t, h.bao)
	saveAlpha(t, h, readGrant(firstPath))
	selector := policy.New("selector", policy.StarterHCL)
	selector.SSH = &policy.SSH{TransitKeys: []string{"sample-key"}}
	if err := c.openbao.CreateTransitKey(ctx, "sample-key", "ed25519"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SavePolicy(ctx, selector, deleteOperator); err != nil {
		t.Fatal(err)
	}
	approveAgent(t, h, "host-a")
	approveAgent(t, h, "host-b")
	one := bindAlpha(t, h, "host-a", "one")
	two := bindAlpha(t, h, "host-a", "two", "alpha", "selector")
	three := bindAlpha(t, h, "host-b", "three")
	other := bindAlpha(t, h, "host-b", "other", "selector")
	selectorBefore, err := c.store.Policy(ctx, "selector")
	if err != nil {
		t.Fatal(err)
	}
	selectorACL := aclOf(t, h, "wyrwood-selector")
	tokens := map[string]openbao.Token{}
	for _, binding := range []store.Binding{one, two, three} {
		tokens[binding.ID] = reportToken(t, h, binding)
	}

	renamePolicy(t, c, "alpha", "zeta")

	for _, row := range []struct {
		binding store.Binding
		names   []string
		acls    []string
	}{
		{one, []string{"zeta"}, []string{"wyrwood-zeta"}},
		{two, []string{"selector", "zeta"}, []string{"wyrwood-selector", "wyrwood-zeta"}},
		{three, []string{"zeta"}, []string{"wyrwood-zeta"}},
	} {
		after, err := c.store.Binding(ctx, row.binding.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(after.Policies, row.names) || after.Revision != row.binding.Revision+1 || !after.Applied || after.Assignment() == row.binding.Assignment() {
			t.Fatalf("binding = %#v", after)
		}
		if got := after.Effective.OpenBaoPolicies(); !slices.Equal(got, row.acls) {
			t.Fatalf("effective = %v, want %v", got, row.acls)
		}
		if got := loginPolicies(t, h, row.binding.Role); !slices.Equal(got, row.acls) {
			t.Fatalf("token policies = %v, want %v", got, row.acls)
		}
		if tokenValid(t, h.bao, tokens[row.binding.ID]) {
			t.Fatalf("old token of %s stayed valid", row.binding.ID)
		}
	}
	unrelated, err := c.store.Binding(ctx, other.ID)
	if err != nil || unrelated.Assignment() != other.Assignment() || unrelated.Revision != other.Revision {
		t.Fatalf("unrelated binding changed: %#v, %v", unrelated, err)
	}
	selectorAfter, err := c.store.Policy(ctx, "selector")
	if err != nil || !reflect.DeepEqual(selectorAfter.Policy, selectorBefore.Policy) || aclOf(t, h, "wyrwood-selector") != selectorACL {
		t.Fatalf("selector policy changed: %#v, %v", selectorAfter, err)
	}
	if hasACL(t, h, alphaACL) {
		t.Fatal("old ACL stayed")
	}
}

// The order the design states, read from the authority at each boundary.
func TestRenameOrderIsPublishCommitRoleRevokeRemove(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	c := h.controller
	saveAlpha(t, h, policy.StarterHCL)
	approveAgent(t, h, "host-a")
	binding := bindAlpha(t, h, "host-a", "web")
	token := reportToken(t, h, binding)
	var order []string
	bao.set(func(call, name string) error {
		_, oldErr := c.store.Policy(ctx, "alpha")
		_, newErr := c.store.Policy(ctx, "beta")
		current, err := c.store.Binding(ctx, binding.ID)
		if err != nil {
			return err
		}
		switch call {
		case callWrite:
			if name != betaACL || oldErr != nil || !errors.Is(newErr, store.ErrNotFound) {
				t.Errorf("publish of %s: old %v, new %v", name, oldErr, newErr)
			}
		case callRole, callRevoke:
			if !errors.Is(oldErr, store.ErrNotFound) || newErr != nil || current.Applied || !hasACL(t, h, alphaACL) || !hasACL(t, h, betaACL) {
				t.Errorf("%s: old %v, new %v, applied %v", call, oldErr, newErr, current.Applied)
			}
		case callDelete:
			if name != alphaACL || !current.Applied || tokenValid(t, h.bao, token) {
				t.Errorf("remove of %s: applied %v", name, current.Applied)
			}
		}
		order = append(order, call)
		return nil
	}, nil)
	renamePolicy(t, c, "alpha", "beta")
	bao.set(nil, nil)
	if want := []string{callWrite, callRole, callRevoke, callDelete, callExists}; !slices.Equal(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
}

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
	<-held
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

func TestRenameReplayAndStalePagesAreRefused(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	c := h.controller
	saved := saveAlpha(t, h, policy.StarterHCL)
	stale := requestRename(t, c, "alpha", "gamma")
	edited, err := c.SavePolicy(ctx, policy.New("alpha", policy.StarterHCL+"# edited\n"), deleteOperator)
	if err != nil {
		t.Fatal(err)
	}
	if edited.Revision != saved.Revision+1 {
		t.Fatalf("edit = %#v", edited)
	}
	_, err = c.RenamePolicy(ctx, stale, deleteOperator)
	if err == nil || !strings.Contains(err.Error(), "reload") {
		t.Fatalf("stale page = %v", err)
	}
	request := requestRename(t, c, "alpha", "beta")
	if _, err := c.RenamePolicy(ctx, request, deleteOperator); err != nil {
		t.Fatal(err)
	}
	transitions := bao.count(callWrite + " " + betaACL)
	var operation *OperationError
	if _, err := c.RenamePolicy(ctx, request, deleteOperator); !errors.As(err, &operation) || !operation.PolicyMissing {
		t.Fatalf("replay = %v", err)
	}
	if bao.count(callWrite+" "+betaACL) != transitions {
		t.Fatalf("replay published: %v", bao.recorded())
	}
	stored, err := c.store.Policy(ctx, "beta")
	if err != nil || stored.Policy.Revision != request.Revision+1 {
		t.Fatalf("replay changed beta: %#v, %v", stored, err)
	}
	// A page of the first alpha cannot rename a later policy of that name, even at
	// the same revision.
	later, err := c.SavePolicy(ctx, policy.New("alpha", policy.StarterHCL), deleteOperator)
	if err != nil {
		t.Fatal(err)
	}
	request.Revision, request.NewName = later.Revision, "gamma"
	if _, err := c.RenamePolicy(ctx, request, deleteOperator); err == nil || !strings.Contains(err.Error(), "reload") {
		t.Fatalf("page of the earlier policy = %v", err)
	}
	if hasACL(t, h, gammaACL) {
		t.Fatal("the earlier page renamed the later policy")
	}
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

// A selection whose complete policy set the agent protocol refuses is refused
// before anything is published, whatever the renamed policy's own size.
func TestRenamePreflightsEveryAffectedAgent(t *testing.T) {
	ctx := context.Background()
	h, bao := startRenameHarness(t)
	c := h.controller
	saved := saveAlpha(t, h, policy.StarterHCL)
	approveAgent(t, h, "host-a")
	bindAlpha(t, h, "host-a", "web")
	if err := c.store.SaveInventory(ctx, "host-a", "SHA256:host-a", []protocol.Container{
		{ID: "c-web", Name: "web", Image: "example/web:1", State: protocol.StateRunning, Keys: []protocol.Key{exampleKey("web")}},
		{ID: "c-bad", Name: "bad", Image: "example/bad:1", State: protocol.StateRunning, Keys: []protocol.Key{exampleKey("bad")}},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SavePolicy(ctx, policy.New("other", policy.StarterHCL), deleteOperator); err != nil {
		t.Fatal(err)
	}
	if err := c.store.CreateBinding(ctx, store.Binding{ID: "b-bad", Agent: "host-a", Key: exampleKey("bad"), Policies: []string{"other"}, Revision: 1, Role: "wyrwood-host-a-b-bad"}); err != nil {
		t.Fatal(err)
	}
	calls := len(bao.recorded())
	_, err := c.RenamePolicy(ctx, requestRename(t, c, "alpha", "beta"), deleteOperator)
	if err == nil || !strings.Contains(err.Error(), "exceeds the agent protocol limits") {
		t.Fatalf("rename = %v", err)
	}
	if len(bao.recorded()) != calls {
		t.Fatalf("calls = %v", bao.recorded()[calls:])
	}
	assertKept(t, h, saved)
	wantRetirements(t, c)
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
	if set, ok := connection.receive(t).(protocol.PolicySet); !ok || len(set.Bindings) != 1 || set.Bindings[0].Assignment != current.Assignment() {
		t.Fatalf("policy set = %#v", set)
	}
	bao.set(nil, nil)
	waitCredential(current.Assignment())
	waitForRetirements(t, h)
}
