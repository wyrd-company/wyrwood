// ---
// relationships:
//   implements: controller
//   uses: authenticate-operator-keys-over-ssh
// ---

package controller

import (
	"context"
	"errors"
	"slices"
	"time"

	"charm.land/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/operator"
)

type operatorContextKey struct{}

// OperatorSubject is the audit subject of a key with this label. Its prefix
// cannot be mistaken for the subject of an operator who signed in through OIDC.
func OperatorSubject(label string) string { return subjectPrefix + label }

// authenticateOperator accepts only approved operator keys. An unknown key is
// recorded as pending; pending, rejected, revoked, and unknown keys all receive
// the same authentication failure. An agent key is refused and not recorded.
func (controller *Controller) authenticateOperator(ctx ssh.Context, key ssh.PublicKey, label string) bool {
	fingerprint := gossh.FingerprintSHA256(key)
	lookup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	found, err := controller.store.OperatorKey(lookup, fingerprint)
	if errors.Is(err, store.ErrNotFound) {
		count, countErr := controller.store.PendingOperatorKeyCount(lookup)
		if countErr != nil || count >= maximumPendingKeys {
			return false
		}
		authorized := string(gossh.MarshalAuthorizedKey(key))
		if _, err := controller.store.RecordOperatorKey(lookup, fingerprint, label, authorized, controller.now()); err != nil && !errors.Is(err, store.ErrNotFound) {
			controller.logf("pending operator key not recorded")
		}
		return false
	}
	if err != nil || found.State != store.OperatorKeyApproved {
		return false
	}
	ctx.SetValue(operatorContextKey{}, fingerprint)
	return true
}

// ApproveOperatorKey approves a pending key with a label and a grant.
func (controller *Controller) ApproveOperatorKey(ctx context.Context, fingerprint, label string, grant operator.Grant, by string) error {
	if !operator.ValidLabel(label) {
		return operationError(events.ErrorPolicyDenied, "a label holds 1 to 64 letters, digits, dots, underscores, and hyphens, and starts with a letter or digit")
	}
	if err := grant.Validate(ValidAgentName, policy.ValidName); err != nil {
		return operationError(events.ErrorPolicyDenied, "the grant is invalid: %v", err)
	}
	_, err := controller.store.ApproveOperatorKey(ctx, fingerprint, label, grant, by, controller.now())
	return controller.operatorKeyDecision(err, events.OperationOperatorKeyApproved, fingerprint, by)
}

// RejectOperatorKey rejects a pending key.
func (controller *Controller) RejectOperatorKey(ctx context.Context, fingerprint, by string) error {
	_, err := controller.store.RejectOperatorKey(ctx, fingerprint, by, controller.now())
	return controller.operatorKeyDecision(err, events.OperationOperatorKeyRejected, fingerprint, by)
}

// RevokeOperatorKey ends an approved key. A session it holds fails its next
// request, since each request reads the key's state again.
func (controller *Controller) RevokeOperatorKey(ctx context.Context, fingerprint, by string) error {
	_, err := controller.store.RevokeOperatorKey(ctx, fingerprint, by, controller.now())
	return controller.operatorKeyDecision(err, events.OperationOperatorKeyRevoked, fingerprint, by)
}

func (controller *Controller) operatorKeyDecision(err error, operation events.Operation, fingerprint, by string) error {
	switch {
	case errors.Is(err, store.ErrConflict):
		return operationError(events.ErrorPolicyDenied, "another key already has this label")
	case errors.Is(err, store.ErrNotFound):
		return operationError(events.ErrorNotBound, "no key in the right state has this fingerprint")
	case err != nil:
		return operationError(events.ErrorInternal, "the decision could not be recorded")
	}
	controller.record(events.Event{Operation: operation, Outcome: events.OutcomeOK, Fingerprint: fingerprint, Operator: by})
	return nil
}

// ChangeOperatorKeyGrant replaces an approved key's grant with to. from is the
// grant the edit started from, so that an edit made after another one fails
// and changes nothing. The key keeps its fingerprint, label, and approval, and
// its next request reads the new grant, so its client needs no change or
// restart. Only the web interface calls this: no operator request changes a
// grant.
func (controller *Controller) ChangeOperatorKeyGrant(ctx context.Context, fingerprint string, from, to operator.Grant, by string) error {
	if err := to.Validate(ValidAgentName, policy.ValidName); err != nil {
		return operationError(events.ErrorPolicyDenied, "the grant is invalid: %v", err)
	}
	controller.grantMu.Lock()
	defer controller.grantMu.Unlock()
	change := store.OperatorKeyGrantChange{Fingerprint: fingerprint, From: from, To: to}
	if err := controller.changeGrants(ctx, []store.OperatorKeyGrantChange{change}, by); err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			return operationError(events.ErrorPolicyDenied, "this key's grant changed after you opened it. Reload to see the grant it holds now")
		case errors.Is(err, store.ErrNotFound):
			return operationError(events.ErrorNotBound, "no approved key has this fingerprint")
		}
		return err
	}
	return nil
}

// ChangePolicyOperatorKeys adds the policy name to the grant of each approved
// key in add and removes it from each key in remove, in one change. Only the
// keys' policy lists change: each key keeps its actions, which then apply to
// the policy too. A key whose grant holds all policies already covers the
// policy, so adding it changes nothing, and removing it is refused, since a
// grant cannot hold all policies but one.
func (controller *Controller) ChangePolicyOperatorKeys(ctx context.Context, name string, add, remove []string, by string) error {
	if !policy.ValidName(name) {
		return operationError(events.ErrorPolicyDenied, "the policy name is invalid")
	}
	controller.grantMu.Lock()
	defer controller.grantMu.Unlock()
	var changes []store.OperatorKeyGrantChange
	for _, fingerprint := range slices.Compact(slices.Sorted(slices.Values(append(slices.Clone(add), remove...)))) {
		adding, removing := slices.Contains(add, fingerprint), slices.Contains(remove, fingerprint)
		key, err := controller.store.OperatorKey(ctx, fingerprint)
		if errors.Is(err, store.ErrNotFound) || (err == nil && key.State != store.OperatorKeyApproved) {
			return operationError(events.ErrorNotBound, "an operator key you selected is no longer approved. Reload to see the keys")
		}
		if err != nil {
			return operationError(events.ErrorInternal, "operator keys could not be read")
		}
		if adding && removing {
			return operationError(events.ErrorPolicyDenied, "operator key %s is both added and removed", key.Label)
		}
		policies := key.Grant.Policies
		switch {
		case slices.Equal(policies, []string{operator.AllNames}):
			if removing {
				return operationError(events.ErrorPolicyDenied, "operator key %s holds all policies. Edit its grant to remove one", key.Label)
			}
			continue
		case adding && !slices.Contains(policies, name):
			policies = append(slices.Clone(policies), name)
		case removing:
			policies = slices.DeleteFunc(slices.Clone(policies), func(held string) bool { return held == name })
		}
		to := key.Grant
		to.Policies = policies
		if store.SameGrant(to, key.Grant) {
			continue
		}
		if err := to.Validate(ValidAgentName, policy.ValidName); err != nil {
			return operationError(events.ErrorPolicyDenied, "the grant of operator key %s would be invalid: %v", key.Label, err)
		}
		changes = append(changes, store.OperatorKeyGrantChange{Fingerprint: fingerprint, From: key.Grant, To: to})
	}
	if len(changes) == 0 {
		return nil
	}
	if err := controller.changeGrants(ctx, changes, by); err != nil {
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
			return operationError(events.ErrorPolicyDenied, "an operator key changed while this change was made. Reload to see the keys")
		}
		return err
	}
	return nil
}

// changeGrants stores grant changes and records each one. The caller holds
// grantMu.
func (controller *Controller) changeGrants(ctx context.Context, changes []store.OperatorKeyGrantChange, by string) error {
	if err := controller.store.ChangeOperatorKeyGrants(ctx, changes); err != nil {
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
			return err
		}
		return operationError(events.ErrorInternal, "the grant could not be saved")
	}
	now := controller.now()
	for _, change := range changes {
		controller.recordGrantChange(now, change, by)
	}
	return nil
}

// recordGrantChange records one event for each agent, policy, and action that
// the grant held before the change or holds after it, between two events that
// name no entry. Every event of the change has the same time, the key, and the
// operator, so that the events of one change can be read back together as the
// old and the new grant, and a reader knows it has them all when it has both
// bounds: retention drops the oldest events, and a stopped controller can
// leave a change without its newest. A change that leaves the grant as it was
// records nothing.
func (controller *Controller) recordGrantChange(now time.Time, change store.OperatorKeyGrantChange, by string) {
	if store.SameGrant(change.From, change.To) {
		return
	}
	base := events.Event{Time: now, Operation: events.OperationOperatorKeyGrantChanged, Outcome: events.OutcomeOK,
		Fingerprint: change.Fingerprint, Operator: by}
	if err := recordGrantEvents(controller.events.Append, base, grantEntries(base, change)); err != nil {
		controller.logf("grant change not recorded whole")
	}
}

// grantEntries returns one event for each agent, policy, and action of the
// old or the new grant, which holds the entry's old side, its new side, or
// both.
func grantEntries(base events.Event, change store.OperatorKeyGrantChange) []events.Event {
	var entries []events.Event
	add := func(before, after []string, set func(event *events.Event, before, after string)) {
		for _, name := range slices.Compact(slices.Sorted(slices.Values(append(slices.Clone(before), after...)))) {
			event := base
			set(&event, entryIf(before, name), entryIf(after, name))
			entries = append(entries, event)
		}
	}
	add(change.From.Agents, change.To.Agents, func(event *events.Event, before, after string) {
		event.Agent, event.NewAgent = before, after
	})
	add(change.From.Policies, change.To.Policies, func(event *events.Event, before, after string) {
		event.Policy, event.NewPolicy = before, after
	})
	actions := func(list []operator.Action) []string {
		names := make([]string, 0, len(list))
		for _, action := range list {
			names = append(names, string(action))
		}
		return names
	}
	add(actions(change.From.Actions), actions(change.To.Actions), func(event *events.Event, before, after string) {
		event.Action, event.NewAction = events.Action(before), events.Action(after)
	})
	return entries
}

// recordGrantEvents appends the bounds and the entries of one grant change.
// An entry that holds both sides and does not fit one event, as a long agent
// name with a long operator subject does not, is appended as two: its old side
// and its new side, which a reader gathers into the same grants. The closing
// bound is appended only when the opening bound and every entry were, so that
// both bounds mean the change is whole.
func recordGrantEvents(appendEvent func(events.Event) error, base events.Event, entries []events.Event) error {
	if err := appendEvent(base); err != nil {
		return err
	}
	for _, entry := range entries {
		err := appendEvent(entry)
		if err == nil {
			continue
		}
		before, after := entry, entry
		before.NewAgent, before.NewPolicy, before.NewAction = "", "", events.ActionNone
		after.Agent, after.Policy, after.Action = "", "", events.ActionNone
		if before == base || after == base {
			// One side is empty, so the entry has nothing to split.
			return err
		}
		if err := appendEvent(before); err != nil {
			return err
		}
		if err := appendEvent(after); err != nil {
			return err
		}
	}
	return appendEvent(base)
}

// entryIf returns name when list holds it, and nothing otherwise.
func entryIf(list []string, name string) string {
	if slices.Contains(list, name) {
		return name
	}
	return ""
}
