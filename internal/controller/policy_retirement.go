// ---
// relationships:
//   implements: composable-policy-bindings
//   uses: store
// ---

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/wyrd-company/wyrwood/internal/openbao"
)

// wakePolicyRetirements starts the consumer if it is idle. It never blocks: a
// wake that is already queued covers this one.
func (controller *Controller) wakePolicyRetirements() {
	select {
	case controller.retirementWake <- struct{}{}:
	default:
	}
}

// runPolicyRetirements is the server-side consumer of durable retirement records.
// It sleeps until woken and retries on the controller's OpenBao retry interval
// only while a record remains, so finishing a rename needs no client and no
// restart.
func (controller *Controller) runPolicyRetirements(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-controller.retirementWake:
		}
		for controller.retirePolicies(ctx) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(controller.retirementRetry):
			}
		}
	}
}

// retirePolicies runs one pass and reports whether work remains.
func (controller *Controller) retirePolicies(ctx context.Context) bool {
	passCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	controller.mutationMu.Lock()
	agents, err := controller.settlePolicyRetirements(passCtx)
	controller.mutationMu.Unlock()
	for agent := range agents {
		controller.hub.pushAgent(passCtx, agent)
	}
	if err != nil {
		controller.logf("policy retirement pending (%s); retrying", openbao.CategoryOf(err))
		return true
	}
	return false
}

// settlePolicyRetirements finishes every pending transition and then removes each
// recorded identity. A role that is not applied may still name a retired identity,
// so no identity is removed until every binding is applied. An identity a stored
// policy holds is not retired: a policy took it after the record was written. The
// caller holds mutationMu. It returns the agents whose bindings it applied.
func (controller *Controller) settlePolicyRetirements(ctx context.Context) (map[string]bool, error) {
	agents := map[string]bool{}
	identities, err := controller.store.PolicyRetirements(ctx)
	if err != nil {
		return agents, err
	}
	if len(identities) == 0 {
		return agents, nil
	}
	if controller.policySyncPending {
		if err := controller.syncPolicies(ctx); err != nil {
			return agents, err
		}
	}
	bindings, err := controller.store.Bindings(ctx, "")
	if err != nil {
		return agents, err
	}
	var failures []error
	for _, b := range bindings {
		if b.Applied {
			continue
		}
		if err := controller.applyBinding(ctx, b); err != nil {
			failures = append(failures, err)
			continue
		}
		agents[b.Agent] = true
	}
	if len(failures) > 0 {
		return agents, errors.Join(failures...)
	}
	documents, err := controller.store.Policies(ctx)
	if err != nil {
		return agents, err
	}
	held := make(map[string]bool, len(documents))
	for _, stored := range documents {
		held[stored.Policy.OpenBaoPolicyName()] = true
	}
	for _, identity := range identities {
		if held[identity] {
			err = controller.store.ForgetPolicyRetirement(ctx, identity)
		} else {
			err = controller.removePolicyIdentity(ctx, identity)
		}
		if err != nil {
			failures = append(failures, err)
		}
	}
	return agents, errors.Join(failures...)
}

// removePolicyIdentity deletes one exact identity and ends its record only after
// a read-back confirms it is gone.
func (controller *Controller) removePolicyIdentity(ctx context.Context, identity string) error {
	if err := controller.openbao.DeletePolicy(ctx, identity); err != nil {
		return err
	}
	exists, err := controller.openbao.PolicyExists(ctx, identity)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("policy %s is still present after its removal", identity)
	}
	return controller.store.ForgetPolicyRetirement(ctx, identity)
}
