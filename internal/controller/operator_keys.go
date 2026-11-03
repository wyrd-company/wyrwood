// ---
// relationships:
//   implements: controller
//   uses: authenticate-operator-keys-over-ssh
// ---

package controller

import (
	"context"
	"errors"
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
