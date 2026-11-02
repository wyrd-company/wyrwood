// ---
// relationships:
//   implements: composable-policy-bindings
//   uses: store
// ---

package controller

import (
	"context"
	"errors"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao"
	"github.com/wyrd-company/wyrwood/internal/policy"
)

// PolicyRename names a policy as the operator saw it. Revision and Generation
// bind the request to that policy, so a page opened before a save or before an
// earlier rename of this name cannot act on what the name means now.
type PolicyRename struct {
	Name       string
	NewName    string
	Revision   int
	Generation int
}

// RenamePolicy moves a policy to a new name and to the next OpenBao identity of
// that name. The new identity is published first, the store commits the rename
// and each affected binding's next assignment in one transaction, each binding
// then takes its new role and revokes its old token, and the old identity is
// removed once no binding can still depend on it.
//
// A returned policy with a non-nil error means the rename committed and its
// transition is pending: the retirement consumer finishes it.
func (controller *Controller) RenamePolicy(ctx context.Context, request PolicyRename, operator string) (policy.Policy, error) {
	started := controller.now()
	controller.mutationMu.Lock()
	renamed, agents, err := controller.renamePolicy(ctx, request, operator)
	controller.mutationMu.Unlock()
	if err == nil && request.Name == request.NewName {
		return renamed, nil
	}
	code := mutationErrorCode(err)
	event := events.Event{Operation: events.OperationPolicyRenamed, Outcome: outcomeFor(code), ErrorCode: code, Operator: operator, Latency: controller.now().Sub(started)}
	if policy.ValidName(request.Name) {
		event.Policy = request.Name
	}
	if policy.ValidName(request.NewName) {
		event.NewPolicy = request.NewName
	}
	controller.record(event)
	for agent := range agents {
		controller.hub.pushAgent(ctx, agent)
	}
	controller.wakePolicyRetirements()
	return renamed, err
}

func (controller *Controller) renamePolicy(ctx context.Context, request PolicyRename, operator string) (policy.Policy, map[string]bool, error) {
	agents := map[string]bool{}
	fail := func(err error) (policy.Policy, map[string]bool, error) { return policy.Policy{}, agents, err }
	missing := &OperationError{Code: events.ErrorPolicyDenied, PolicyMissing: true, Message: "this policy does not exist; another operator may have deleted or renamed it"}
	if !policy.ValidName(request.Name) {
		return fail(missing)
	}
	stored, err := controller.store.Policy(ctx, request.Name)
	if errors.Is(err, store.ErrNotFound) {
		return fail(missing)
	}
	if err != nil {
		return fail(operationError(events.ErrorInternal, "the stored policy could not be read"))
	}
	if !policy.ValidName(request.NewName) {
		return fail(operationError(events.ErrorPolicyDenied, "the new name must be a lower-kebab-case slug of at most 64 bytes"))
	}
	if request.NewName == request.Name {
		return stored.Policy, agents, nil
	}
	if request.Revision != stored.Policy.Revision || request.Generation != stored.Policy.Generation {
		return fail(operationError(events.ErrorPolicyDenied, "this policy changed; reload before renaming it"))
	}
	if _, err := controller.store.Policy(ctx, request.NewName); err == nil {
		return fail(operationError(events.ErrorPolicyDenied, "the name %s is already in use; choose another name, or rename or delete that policy first", request.NewName))
	} else if !errors.Is(err, store.ErrNotFound) {
		return fail(operationError(events.ErrorInternal, "the stored policy could not be read"))
	}
	generation, err := controller.store.NextPolicyGeneration(ctx, request.NewName)
	if err != nil {
		return fail(operationError(events.ErrorInternal, "the stored policy could not be read"))
	}
	document := stored.Policy.Clone()
	document.Name, document.Generation, document.Revision = request.NewName, generation, stored.Policy.Revision+1
	affected, err := controller.renamedBindings(ctx, request.Name, document)
	if err != nil {
		return fail(err)
	}
	if err := controller.preflight(ctx, affected); err != nil {
		return fail(err)
	}
	if err := controller.publishRenamed(ctx, document); err != nil {
		return fail(err)
	}
	renamed, err := controller.store.RenamePolicy(ctx, request.Name, document, affected, operator, controller.now())
	if err != nil {
		if err := controller.settleFailedRename(ctx, document); err != nil {
			return fail(err)
		}
		renamed = document
	}
	var transitionErr error
	for _, b := range affected {
		agents[b.Agent] = true
		if err := controller.applyBinding(ctx, b); err != nil {
			transitionErr = operationError(openBaoError(err), "policy renamed; a binding transition is pending, and the old OpenBao policy stays until the controller finishes it")
		}
	}
	if transitionErr != nil {
		return renamed, agents, transitionErr
	}
	settled, err := controller.settlePolicyRetirements(ctx)
	for agent := range settled {
		agents[agent] = true
	}
	if err != nil {
		return renamed, agents, operationError(openBaoError(err), "policy renamed; the old OpenBao policy stays until the controller can remove it")
	}
	return renamed, agents, nil
}

// renamedBindings computes each affected binding's next assignment.
func (controller *Controller) renamedBindings(ctx context.Context, oldName string, document policy.Policy) ([]store.Binding, error) {
	bindings, err := controller.store.Bindings(ctx, "")
	if err != nil {
		return nil, operationError(events.ErrorInternal, "bindings could not be read")
	}
	var affected []store.Binding
	for _, b := range bindings {
		if !b.HasPolicy(oldName) {
			continue
		}
		names := make([]string, 0, len(b.Policies))
		for _, name := range b.Policies {
			if name == oldName {
				name = document.Name
			}
			names = append(names, name)
		}
		effective, err := controller.compose(ctx, names, b.Settings, &document)
		if err != nil {
			return nil, err
		}
		b.Policies = effective.Names()
		b.Effective = effective
		b.Revision++
		b.Applied = false
		affected = append(affected, b)
	}
	return affected, nil
}

// publishRenamed writes the new identity under a retirement record, so that a
// failure or a restart before the rename commits leaves an identity that the
// consumer removes. The commit ends the record.
func (controller *Controller) publishRenamed(ctx context.Context, document policy.Policy) error {
	identity := document.OpenBaoPolicyName()
	if err := controller.store.RecordPolicyRetirement(ctx, identity, controller.now()); err != nil {
		return operationError(events.ErrorInternal, "the rename could not be recorded; nothing changed")
	}
	err := controller.openbao.WritePolicy(ctx, identity, document.PublishedHCL())
	if err == nil {
		return nil
	}
	code := openBaoError(err)
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), operationTimeout)
	defer cancel()
	if openbao.CategoryOf(err) == openbao.CategoryInvalid {
		if err := controller.store.ForgetPolicyRetirement(cleanupCtx, identity); err != nil {
			controller.logf("policy retirement not ended")
		}
		return operationError(code, "OpenBao rejected the HCL policy; nothing changed")
	}
	// An interrupted response can hide a successful write.
	if err := controller.removePolicyIdentity(cleanupCtx, identity); err != nil {
		return operationError(code, "OpenBao could not store the policy under its new name; the policy keeps its name, and the controller removes what the attempt left")
	}
	return operationError(code, "OpenBao could not store the policy under its new name; nothing changed")
}

// settleFailedRename decides from the store, not from the failed call, whether
// the rename committed. It answers nil when it did. A rename that did not commit
// loses its published identity, and the consumer finishes that if it cannot be
// done now.
func (controller *Controller) settleFailedRename(ctx context.Context, document policy.Policy) error {
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), operationTimeout)
	defer cancel()
	stored, err := controller.store.Policy(readCtx, document.Name)
	switch {
	case err == nil && stored.Policy.Generation == document.Generation:
		return nil
	case err != nil && !errors.Is(err, store.ErrNotFound):
		return operationError(events.ErrorInternal, "the rename could not be confirmed; reload the Policies page, because the controller finishes it whichever way it went")
	}
	if err := controller.removePolicyIdentity(readCtx, document.OpenBaoPolicyName()); err != nil {
		return operationError(events.ErrorInternal, "the rename could not be recorded; the policy keeps its name, and the controller removes what the attempt left")
	}
	return operationError(events.ErrorInternal, "the rename could not be recorded; nothing changed")
}
