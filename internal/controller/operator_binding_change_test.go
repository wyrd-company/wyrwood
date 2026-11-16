// ---
// relationships:
//   verifies:
//     - controller
//     - operator-interface
// ---

package controller

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/operator"
)

// changeEvents returns the policy and new policy of each binding-changed event
// of a binding that the key with subject made, oldest first.
func changeEvents(harness *harness, binding, subject string, outcome events.Outcome) [][2]string {
	var result [][2]string
	for _, event := range harness.controller.Events().Recent(1000) {
		if event.Operation == events.OperationBindingChanged && event.Binding == binding && event.Operator == subject && event.Outcome == outcome {
			result = append(result, [2]string{event.Policy, event.NewPolicy})
		}
	}
	return result
}

func TestOperatorChangeBindingAppliesAtOnce(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	harness.approveAgent(t, "sample-host")
	harness.savePolicy(t, "alpha")
	harness.savePolicy(t, "beta")
	client, _ := harness.approvedOperator(t, "sample-operator", fullGrant)
	group := uint32(1000)
	request := operator.BindRequest{Agent: "sample-host", Key: operator.Key{Kind: operator.KeyName, Value: "app"},
		Policies: []string{"alpha"}, Settings: operator.Settings{AccessGroup: &group, Values: map[string]string{"team": "teal"}}}
	bound, err := client.Bind(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := harness.controller.Store().Binding(ctx, bound.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The container's token, as its agent reported it.
	old, err := appRoleLogin(t, harness.bao, stored.Role)
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.controller.Store().SaveAssignmentAccessor(ctx, stored, old.Accessor, harness.controller.now()); err != nil {
		t.Fatal(err)
	}

	settings := bound.Settings
	settings.Values = map[string]string{"team": "amber"}
	changed, err := client.ChangeBinding(ctx, operator.BindingChange{ID: bound.ID, Revision: bound.Revision, Policies: []string{"alpha", "beta"}, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	if changed.ID != bound.ID || changed.Revision != bound.Revision+1 || !changed.Applied || !slices.Equal(changed.Policies, []string{"alpha", "beta"}) ||
		changed.Settings.AccessGroup == nil || *changed.Settings.AccessGroup != group || changed.Settings.Values["team"] != "amber" || changed.Status.Binding != bound.ID {
		t.Fatalf("ChangeBinding() = %+v", changed)
	}
	if tokenValid(t, harness.bao, old) {
		t.Fatal("the container's old token is still valid after the change")
	}
	current, err := harness.controller.Store().Binding(ctx, bound.ID)
	if err != nil || current.Role != stored.Role || current.Directory != stored.Directory || current.Key != stored.Key || current.CreatedBy != stored.CreatedBy {
		t.Fatalf("the change replaced the binding: %+v, %v", current, err)
	}
	fresh, err := appRoleLogin(t, harness.bao, current.Role)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fresh.Policies, []string{"wyrwood-alpha", "wyrwood-beta"}) {
		t.Fatalf("a new token holds %v", fresh.Policies)
	}
	read, err := client.GetBinding(ctx, bound.ID)
	if err != nil || read.Revision != changed.Revision || !slices.Equal(read.Policies, changed.Policies) {
		t.Fatalf("GetBinding() = %+v, %v", read, err)
	}

	// The event history names the key and both selections.
	if got, want := changeEvents(harness, bound.ID, "key:sample-operator", events.OutcomeOK), [][2]string{{"alpha", "alpha"}, {"", "beta"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("binding-changed events = %v; want %v", got, want)
	}

	// A change of a value alone is a change.
	settings.Values = map[string]string{"team": "violet"}
	revalued, err := client.ChangeBinding(ctx, operator.BindingChange{ID: bound.ID, Revision: changed.Revision, Policies: changed.Policies, Settings: settings})
	if err != nil || revalued.Revision != changed.Revision+1 || !revalued.Applied || revalued.Settings.Values["team"] != "violet" {
		t.Fatalf("ChangeBinding() of a value = %+v, %v", revalued, err)
	}
	changed = revalued

	// bind keeps its behavior: another selection is refused and changes nothing.
	if _, err := client.Bind(ctx, request); !errors.Is(err, operator.ErrBindingDiffers) {
		t.Fatalf("Bind() with the selection before the change = %v", err)
	}
	same := request
	same.Policies = changed.Policies
	same.Settings = changed.Settings
	if again, err := client.Bind(ctx, same); err != nil || again.ID != bound.ID || again.Revision != changed.Revision {
		t.Fatalf("Bind() with the selection after the change = %+v, %v", again, err)
	}
}

func TestOperatorChangeBindingStaysInsideTheGrant(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	harness.approveAgent(t, "inside-host")
	harness.approveAgent(t, "outside-host")
	harness.savePolicy(t, "allowed")
	harness.savePolicy(t, "also-allowed")
	harness.savePolicy(t, "forbidden")
	grant := operator.Grant{Agents: []string{"inside-host"}, Policies: []string{"allowed", "also-allowed"},
		Actions: []operator.Action{operator.ActionRead, operator.ActionBind}}
	client, _ := harness.approvedOperator(t, "scoped-key", grant)
	everything := operator.Grant{Agents: []string{operator.AllNames}, Policies: []string{operator.AllNames}}
	readOnly, _ := harness.approvedOperator(t, "read-key", operator.Grant{Agents: everything.Agents, Policies: everything.Policies, Actions: []operator.Action{operator.ActionRead}})
	writeOnly, _ := harness.approvedOperator(t, "write-key", operator.Grant{Agents: everything.Agents, Policies: everything.Policies, Actions: []operator.Action{operator.ActionPolicyWrite}})
	wide, _ := harness.approvedOperator(t, "wide-key", fullGrant)
	name := func(value string) operator.Key { return operator.Key{Kind: operator.KeyName, Value: value} }
	mine, err := wide.Bind(ctx, operator.BindRequest{Agent: "inside-host", Key: name("app-a"), Policies: []string{"allowed"}})
	if err != nil {
		t.Fatal(err)
	}
	heldForbidden, err := wide.Bind(ctx, operator.BindRequest{Agent: "inside-host", Key: name("app-b"), Policies: []string{"allowed", "forbidden"}})
	if err != nil {
		t.Fatal(err)
	}
	onOutsideAgent, err := wide.Bind(ctx, operator.BindRequest{Agent: "outside-host", Key: name("app-c"), Policies: []string{"allowed"}})
	if err != nil {
		t.Fatal(err)
	}

	unchanged := func(t *testing.T, before operator.Binding) {
		t.Helper()
		stored, err := harness.controller.Store().Binding(ctx, before.ID)
		if err != nil || stored.Revision != before.Revision || !slices.Equal(stored.Policies, before.Policies) || !stored.Applied {
			t.Fatalf("the refused change changed the binding: %+v, %v", stored, err)
		}
	}
	for name, attempt := range map[string]struct {
		client *operator.Client
		before operator.Binding
		change operator.BindingChange
	}{
		"a policy outside the grant": {client, mine,
			operator.BindingChange{ID: mine.ID, Revision: mine.Revision, Policies: []string{"allowed", "forbidden"}}},
		"a binding that holds a policy outside the grant": {client, heldForbidden,
			operator.BindingChange{ID: heldForbidden.ID, Revision: heldForbidden.Revision, Policies: []string{"allowed"}}},
		"a binding on another agent": {client, onOutsideAgent,
			operator.BindingChange{ID: onOutsideAgent.ID, Revision: onOutsideAgent.Revision, Policies: []string{"allowed", "also-allowed"}}},
		"a key that cannot bind": {readOnly, mine,
			operator.BindingChange{ID: mine.ID, Revision: mine.Revision, Policies: []string{"allowed", "also-allowed"}}},
		"a key that can only write policies": {writeOnly, mine,
			operator.BindingChange{ID: mine.ID, Revision: mine.Revision, Policies: []string{"allowed", "also-allowed"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := attempt.client.ChangeBinding(ctx, attempt.change); !errors.Is(err, operator.ErrOutsideGrant) {
				t.Fatalf("ChangeBinding() = %v; want outside the grant", err)
			}
			unchanged(t, attempt.before)
		})
	}
	if !hasEvent(t, harness, events.Event{Operation: events.OperationBindingChanged, Operator: "key:scoped-key", ErrorCode: events.ErrorOutsideGrant, Agent: "inside-host"}) {
		t.Fatal("the refused change has no audit event naming the key")
	}
	if !hasEvent(t, harness, events.Event{Operation: events.OperationBindingChanged, Operator: "key:read-key", ErrorCode: events.ErrorOutsideGrant}) {
		t.Fatal("the refused change of a key that cannot bind has no audit event")
	}
	// The action is checked before the lookup, so that a key cannot learn what exists.
	if _, err := readOnly.ChangeBinding(ctx, operator.BindingChange{ID: "b-missing", Revision: 1, Policies: []string{"allowed"}}); !errors.Is(err, operator.ErrOutsideGrant) {
		t.Fatalf("ChangeBinding() of a missing binding without bind = %v", err)
	}
	if _, err := client.ChangeBinding(ctx, operator.BindingChange{ID: "b-missing", Revision: 1, Policies: []string{"allowed"}}); !errors.Is(err, operator.ErrNotFound) {
		t.Fatalf("ChangeBinding() of a missing binding = %v", err)
	}

	// Inside the grant, the same key changes the binding.
	changed, err := client.ChangeBinding(ctx, operator.BindingChange{ID: mine.ID, Revision: mine.Revision, Policies: []string{"allowed", "also-allowed"}})
	if err != nil || !slices.Equal(changed.Policies, []string{"allowed", "also-allowed"}) {
		t.Fatalf("ChangeBinding() inside the grant = %+v, %v", changed, err)
	}
}

func TestOperatorChangeBindingRefusesAStaleRevision(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	harness.approveAgent(t, "sample-host")
	harness.savePolicy(t, "alpha")
	harness.savePolicy(t, "beta")
	harness.savePolicy(t, "gamma")
	client, _ := harness.approvedOperator(t, "sample-operator", fullGrant)
	bound, err := client.Bind(ctx, operator.BindRequest{Agent: "sample-host", Key: operator.Key{Kind: operator.KeyName, Value: "app"}, Policies: []string{"alpha"}})
	if err != nil {
		t.Fatal(err)
	}
	first := operator.BindingChange{ID: bound.ID, Revision: bound.Revision, Policies: []string{"alpha", "beta"}, Settings: bound.Settings}
	changed, err := client.ChangeBinding(ctx, first)
	if err != nil || changed.Revision != 2 {
		t.Fatalf("ChangeBinding() = %+v, %v", changed, err)
	}
	afterFirst, err := harness.controller.Store().Binding(ctx, bound.ID)
	if err != nil {
		t.Fatal(err)
	}

	// A change that read revision 1 lost the race to the first one.
	racing := first
	racing.Policies = []string{"alpha", "gamma"}
	if _, err := client.ChangeBinding(ctx, racing); !errors.Is(err, operator.ErrRevisionDiffers) {
		t.Fatalf("ChangeBinding() with a stale revision = %v", err)
	}
	stored, err := harness.controller.Store().Binding(ctx, bound.ID)
	if err != nil || stored.Revision != 2 || !slices.Equal(stored.Policies, []string{"alpha", "beta"}) {
		t.Fatalf("the stale change changed the binding: %+v, %v", stored, err)
	}

	// A change that read revision 1 is stale even when it selects what the binding
	// now holds, as the same edit is in the web interface.
	if _, err := client.ChangeBinding(ctx, first); !errors.Is(err, operator.ErrRevisionDiffers) {
		t.Fatalf("ChangeBinding() of the held selection with a stale revision = %v", err)
	}
	web := BindingRequest{Policies: first.Policies, Settings: policySettings(first.Settings), Revision: first.Revision}
	if err := harness.controller.ChangeBinding(ctx, bound.ID, web, "sample-approver"); !errors.Is(err, errRevisionDiffers) {
		t.Fatalf("the web edit of the held selection with a stale revision = %v", err)
	}
	// At the current revision, the held selection changes nothing.
	current := first
	current.Revision = changed.Revision
	again, err := client.ChangeBinding(ctx, current)
	if err != nil || again.Revision != 2 || !slices.Equal(again.Policies, []string{"alpha", "beta"}) {
		t.Fatalf("ChangeBinding() of the held selection at the current revision = %+v, %v", again, err)
	}
	if stored, err := harness.controller.Store().Binding(ctx, bound.ID); err != nil || stored.Revision != 2 || stored.Assignment() != afterFirst.Assignment() {
		t.Fatalf("a refused or repeated change changed the binding: %+v, %v", stored, err)
	}

	for name, change := range map[string]operator.BindingChange{
		"no revision":      {ID: bound.ID, Policies: []string{"gamma"}},
		"a missing policy": {ID: bound.ID, Revision: 2, Policies: []string{"absent"}},
		"no policy":        {ID: bound.ID, Revision: 2},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := client.ChangeBinding(ctx, change); !errors.Is(err, operator.ErrInvalid) {
				t.Fatalf("ChangeBinding() = %v; want invalid", err)
			}
		})
	}
	if stored, err := harness.controller.Store().Binding(ctx, bound.ID); err != nil || stored.Revision != 2 {
		t.Fatalf("an invalid change changed the binding: %+v, %v", stored, err)
	}
}

func TestARepeatedChangeFinishesAPendingAssignment(t *testing.T) {
	ctx := context.Background()
	failing := false
	harness := startHarnessWith(t, func(inner OpenBao) OpenBao { return failingRoleOpenBao{inner, &failing} })
	harness.approveAgent(t, "sample-host")
	harness.savePolicy(t, "alpha")
	harness.savePolicy(t, "beta")
	client, _ := harness.approvedOperator(t, "sample-operator", fullGrant)
	bound, err := client.Bind(ctx, operator.BindRequest{Agent: "sample-host", Key: operator.Key{Kind: operator.KeyName, Value: "app"}, Policies: []string{"alpha"}})
	if err != nil {
		t.Fatal(err)
	}
	change := operator.BindingChange{ID: bound.ID, Revision: bound.Revision, Policies: []string{"alpha", "beta"}}
	failing = true
	if _, err := client.ChangeBinding(ctx, change); !errors.Is(err, operator.ErrPending) {
		t.Fatalf("ChangeBinding() while OpenBao fails = %v", err)
	}
	pending, err := harness.controller.Store().Binding(ctx, bound.ID)
	if err != nil || pending.Applied || pending.Revision != 2 || !slices.Equal(pending.Policies, change.Policies) {
		t.Fatalf("the saved change = %+v, %v", pending, err)
	}
	// The saved change moved the revision, so the request as it was sent is stale.
	if _, err := client.ChangeBinding(ctx, change); !errors.Is(err, operator.ErrRevisionDiffers) {
		t.Fatalf("ChangeBinding() again with the revision read before it = %v", err)
	}
	// Sent again with the revision read after it, the change finishes.
	read, err := client.GetBinding(ctx, bound.ID)
	if err != nil || read.Applied || read.Revision != 2 {
		t.Fatalf("GetBinding() of the saved change = %+v, %v", read, err)
	}
	change.Revision = read.Revision
	if _, err := client.ChangeBinding(ctx, change); !errors.Is(err, operator.ErrPending) {
		t.Fatalf("ChangeBinding() at the new revision while OpenBao fails = %v", err)
	}
	failing = false
	finished, err := client.ChangeBinding(ctx, change)
	if err != nil || !finished.Applied || finished.Revision != 2 {
		t.Fatalf("ChangeBinding() after recovery = %+v, %v", finished, err)
	}
	if stored, err := harness.controller.Store().Binding(ctx, bound.ID); err != nil || !stored.Applied || stored.Revision != 2 {
		t.Fatalf("Binding() = %+v, %v", stored, err)
	}
}

func TestEveryRefusedChangeRecordsTheKey(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	harness.approveAgent(t, "inside-host")
	harness.savePolicy(t, "allowed")
	harness.savePolicy(t, "forbidden")
	client, _ := harness.approvedOperator(t, "sample-operator", operator.Grant{Agents: []string{"inside-host"}, Policies: []string{"allowed"},
		Actions: []operator.Action{operator.ActionRead, operator.ActionBind}})
	readOnly, _ := harness.approvedOperator(t, "read-key", operator.Grant{Agents: []string{operator.AllNames}, Policies: []string{operator.AllNames},
		Actions: []operator.Action{operator.ActionRead}})
	bound, err := client.Bind(ctx, operator.BindRequest{Agent: "inside-host", Key: operator.Key{Kind: operator.KeyName, Value: "app"}, Policies: []string{"allowed"}})
	if err != nil {
		t.Fatal(err)
	}
	// refusals returns the binding-changed events that name subject and no policy.
	refusals := func(subject string) []events.Event {
		var result []events.Event
		for _, event := range harness.controller.Events().Recent(1000) {
			if event.Operation == events.OperationBindingChanged && event.Operator == subject {
				if event.Policy != "" || event.NewPolicy != "" || event.Outcome == events.OutcomeOK {
					t.Fatalf("a refusal event names a policy or succeeded: %#v", event)
				}
				result = append(result, event)
			}
		}
		return result
	}
	for _, attempt := range []struct {
		name    string
		client  *operator.Client
		subject string
		change  operator.BindingChange
		want    error
		code    events.ErrorCode
		binding string
		agent   string
	}{
		{"no revision", client, "key:sample-operator", operator.BindingChange{ID: bound.ID, Policies: []string{"allowed"}},
			operator.ErrInvalid, events.ErrorPolicyDenied, bound.ID, ""},
		{"a binding that does not exist", client, "key:sample-operator", operator.BindingChange{ID: "b-missing", Revision: 1, Policies: []string{"allowed"}},
			operator.ErrNotFound, events.ErrorNotBound, "b-missing", ""},
		{"an identifier that cannot be a binding", client, "key:sample-operator", operator.BindingChange{ID: "../B", Revision: 1, Policies: []string{"allowed"}},
			operator.ErrNotFound, events.ErrorNotBound, "", ""},
		{"a stale revision", client, "key:sample-operator", operator.BindingChange{ID: bound.ID, Revision: 7, Policies: []string{"allowed"}},
			operator.ErrRevisionDiffers, events.ErrorPolicyDenied, bound.ID, "inside-host"},
		{"a policy outside the grant", client, "key:sample-operator", operator.BindingChange{ID: bound.ID, Revision: 1, Policies: []string{"allowed", "forbidden"}},
			operator.ErrOutsideGrant, events.ErrorOutsideGrant, bound.ID, "inside-host"},
		{"a key that cannot bind", readOnly, "key:read-key", operator.BindingChange{ID: bound.ID, Revision: 1, Policies: []string{"allowed"}},
			operator.ErrOutsideGrant, events.ErrorOutsideGrant, bound.ID, ""},
	} {
		t.Run(attempt.name, func(t *testing.T) {
			before := len(refusals(attempt.subject))
			if _, err := attempt.client.ChangeBinding(ctx, attempt.change); !errors.Is(err, attempt.want) {
				t.Fatalf("ChangeBinding() = %v; want %v", err, attempt.want)
			}
			recorded := refusals(attempt.subject)
			if len(recorded) != before+1 {
				t.Fatalf("binding-changed events naming %s: %d, then %d; want one more", attempt.subject, before, len(recorded))
			}
			event := recorded[len(recorded)-1]
			if event.ErrorCode != attempt.code || event.Binding != attempt.binding || event.Agent != attempt.agent {
				t.Fatalf("event = %#v; want error %s, binding %q, agent %q", event, attempt.code, attempt.binding, attempt.agent)
			}
		})
	}
	if stored, err := harness.controller.Store().Binding(ctx, bound.ID); err != nil || stored.Revision != bound.Revision || !stored.Applied {
		t.Fatalf("a refused change changed the binding: %+v, %v", stored, err)
	}
}
