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
	"github.com/wyrd-company/wyrwood/internal/policy"
)

// DeletePolicy removes a policy that no binding selects: its OpenBao policy, then
// its stored row. The store stays the authority, so an OpenBao policy never
// outlives its row: a failure or a restart between the two leaves the row, and
// syncPolicies publishes it again.
func (controller *Controller) DeletePolicy(ctx context.Context, name, operator string) error {
	started := controller.now()
	controller.mutationMu.Lock()
	err := controller.deletePolicy(ctx, name)
	controller.mutationMu.Unlock()
	eventName := ""
	if policy.ValidName(name) {
		eventName = name
	}
	code := mutationErrorCode(err)
	controller.record(events.Event{Operation: events.OperationPolicyDeleted, Outcome: outcomeFor(code), ErrorCode: code, Policy: eventName, Operator: operator, Latency: controller.now().Sub(started)})
	return err
}

func (controller *Controller) deletePolicy(ctx context.Context, name string) error {
	missing := &OperationError{Code: events.ErrorPolicyDenied, PolicyMissing: true, Message: "this policy does not exist; another operator may have deleted it"}
	if !policy.ValidName(name) {
		return missing
	}
	stored, err := controller.store.Policy(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return missing
	}
	if err != nil {
		return operationError(events.ErrorInternal, "the stored policy could not be read")
	}
	bindings, err := controller.store.Bindings(ctx, "")
	if err != nil {
		return operationError(events.ErrorInternal, "bindings could not be read")
	}
	for _, binding := range bindings {
		if binding.HasPolicy(name) {
			return &OperationError{Code: events.ErrorPolicyDenied, PolicyBound: true, Message: "bindings still select this policy; change or unbind them before deleting it"}
		}
	}
	if err := controller.openbao.DeletePolicy(ctx, stored.Policy.OpenBaoPolicyName()); err != nil {
		code := openBaoError(err)
		// An interrupted response can hide a successful delete.
		if err := controller.restorePolicy(ctx, stored.Policy, stored, true); err != nil {
			return operationError(code, "OpenBao could not confirm the deletion; the policy is kept, its restoration is pending, and fresh issuance is blocked until OpenBao answers")
		}
		return operationError(code, "OpenBao could not delete the policy; the policy is kept, so try again")
	}
	if err := controller.store.DeletePolicy(ctx, name); err != nil {
		return controller.settleFailedPolicyDelete(ctx, stored)
	}
	return nil
}

// settleFailedPolicyDelete decides from the store, not from the failed call,
// whether the row is gone, because restoring the OpenBao policy of a row that
// committed would leave an OpenBao policy that nothing removes. A failed read
// restores nothing here: syncPolicies publishes exactly the rows that exist.
func (controller *Controller) settleFailedPolicyDelete(ctx context.Context, stored store.StoredPolicy) error {
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), operationTimeout)
	defer cancel()
	name := stored.Policy.Name
	_, err := controller.store.Policy(readCtx, name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		controller.policySyncPending = true
		return operationError(events.ErrorInternal, "the deletion could not be confirmed; its OpenBao policy is restored if the policy is still stored, and fresh issuance is blocked until then")
	}
	if err := controller.restorePolicy(ctx, stored.Policy, stored, true); err != nil {
		return operationError(events.ErrorInternal, "the policy could not be removed; it is kept, its OpenBao restoration is pending, and fresh issuance is blocked until then")
	}
	return operationError(events.ErrorInternal, "the policy could not be removed; it is kept, so try again")
}
