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
	var refused *OperationError
	if !errors.As(err, &refused) || refused.Part != "" {
		t.Fatalf("part of %v", err)
	}
	if len(bao.recorded()) != calls {
		t.Fatalf("calls = %v", bao.recorded()[calls:])
	}
	assertKept(t, h, saved)
	wantRetirements(t, c)
}

// A row that a crafted name selects is not read: only name validation stands
// between such a row and the rename.
func TestRenameOfACraftedStoredNameReachesNothing(t *testing.T) {
	h, bao := startRenameHarness(t)
	runSQL(t, stateDB(t, h.controller), `INSERT INTO policies (name, revision, document, saved_at, saved_by) VALUES ('../controller', 1, '{}', 0, '')`)
	calls := len(bao.recorded())
	_, err := h.controller.RenamePolicy(context.Background(), PolicyRename{Name: "../controller", NewName: "beta", Revision: 1, Generation: 1}, deleteOperator)
	var operation *OperationError
	if !errors.As(err, &operation) || !operation.PolicyMissing {
		t.Fatalf("rename = %#v", err)
	}
	if len(bao.recorded()) != calls {
		t.Fatalf("calls = %v", bao.recorded()[calls:])
	}
}
