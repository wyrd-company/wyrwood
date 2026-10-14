// ---
// relationships:
//   implements:
//     - controller
//     - policy
// ---

package controller

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// OperationError is an operator-facing failure with fixed, non-leaking text.
type OperationError struct {
	Message string
	Code    events.ErrorCode
	// TokenLive marks a binding deletion that took effect while the
	// binding's token may still be valid.
	TokenLive bool
}

func (err *OperationError) Error() string { return err.Message }

func operationError(code events.ErrorCode, format string, arguments ...any) error {
	return &OperationError{Message: fmt.Sprintf(format, arguments...), Code: code}
}

var roleNameUnsafe = regexp.MustCompile(`[^a-z0-9-]+`)

// RoleName returns the AppRole name for a binding on an agent.
func RoleName(agent, binding string) string {
	sanitized := strings.Trim(roleNameUnsafe.ReplaceAllString(strings.ToLower(agent), "-"), "-")
	if len(sanitized) > 60 {
		sanitized = sanitized[:60]
	}
	return openbao.ManagedPrefix + sanitized + "-" + binding
}

// DecideAgent approves or rejects a pending agent key.
func (controller *Controller) DecideAgent(ctx context.Context, fingerprint string, approve bool, operator string) error {
	state, operation := store.AgentRejected, events.OperationAgentRejected
	if approve {
		state, operation = store.AgentApproved, events.OperationAgentApproved
	}
	agent, err := controller.store.DecideAgent(ctx, fingerprint, state, operator, controller.now())
	switch {
	case errors.Is(err, store.ErrConflict):
		return operationError(events.ErrorPolicyDenied, "another approved agent already uses this hostname")
	case errors.Is(err, store.ErrNotFound):
		return operationError(events.ErrorNotBound, "no pending agent has this key")
	case err != nil:
		return operationError(events.ErrorInternal, "the decision could not be recorded")
	}
	controller.record(events.Event{Operation: operation, Outcome: events.OutcomeOK, Agent: agent.Name, Operator: operator})
	return nil
}

// SavePolicy validates a policy, writes its HCL to OpenBao, records the new
// revision, refreshes the AppRoles bound to it, and pushes it to agents.
func (controller *Controller) SavePolicy(ctx context.Context, document policy.Policy, operator string) (policy.Policy, error) {
	started := controller.now()
	fail := func(code events.ErrorCode, err error) (policy.Policy, error) {
		controller.record(events.Event{Operation: events.OperationPolicySaved, Outcome: outcomeFor(code), ErrorCode: code,
			Policy: boundedPolicyName(document.Name), Operator: operator, Latency: controller.now().Sub(started)})
		return policy.Policy{}, err
	}
	if err := document.Validate(); err != nil {
		return fail(events.ErrorPolicyDenied, operationError(events.ErrorPolicyDenied, "the policy is invalid: %v", err))
	}
	var missing []string
	for _, name := range document.TransitKeys() {
		exists, err := controller.openbao.TransitKeyExists(ctx, name)
		if err != nil {
			return fail(openBaoError(err), operationError(openBaoError(err), "OpenBao could not confirm the Transit keys"))
		}
		if !exists {
			missing = append(missing, "Transit key "+name)
		}
	}
	for _, name := range document.CARoles() {
		exists, err := controller.openbao.SSHRoleExists(ctx, name)
		if err != nil {
			return fail(openBaoError(err), operationError(openBaoError(err), "OpenBao could not confirm the SSH roles"))
		}
		if !exists {
			missing = append(missing, "SSH role "+name)
		}
	}
	if len(missing) > 0 {
		return fail(events.ErrorPolicyDenied, operationError(events.ErrorPolicyDenied, "these do not exist: %s", strings.Join(missing, ", ")))
	}
	if err := controller.openbao.WritePolicy(ctx, document.OpenBaoPolicyName(), document.OpenBao.Policy); err != nil {
		code := openBaoError(err)
		if openbao.CategoryOf(err) == openbao.CategoryInvalid {
			return fail(events.ErrorPolicyDenied, operationError(events.ErrorPolicyDenied, "OpenBao rejected the HCL policy"))
		}
		return fail(code, operationError(code, "OpenBao could not store the policy"))
	}
	saved, err := controller.store.SavePolicy(ctx, document, operator, controller.now())
	if err != nil {
		return fail(events.ErrorInternal, operationError(events.ErrorInternal, "the policy could not be recorded"))
	}
	bindings, err := controller.store.Bindings(ctx, "")
	if err != nil {
		return fail(events.ErrorInternal, operationError(events.ErrorInternal, "bindings could not be read"))
	}
	agents := map[string]bool{}
	for _, binding := range bindings {
		if binding.Policy != saved.Name {
			continue
		}
		agents[binding.Agent] = true
		if err := controller.openbao.WriteRole(ctx, binding.Role, saved.OpenBaoPolicyName(), saved.TokenTTL(), saved.TokenMaxTTL()); err != nil {
			controller.logf("AppRole for a binding was not refreshed (%s)", openbao.CategoryOf(err))
		}
	}
	controller.record(events.Event{Operation: events.OperationPolicySaved, Outcome: events.OutcomeOK,
		Policy: saved.Name, Operator: operator, Latency: controller.now().Sub(started)})
	for agent := range agents {
		controller.hub.pushAgent(ctx, agent)
	}
	return saved, nil
}

func boundedPolicyName(name string) string {
	if len(name) > 64 || strings.ContainsAny(name, "\x00\n\r\t") {
		return ""
	}
	return name
}

// CreateBinding binds policyName to a container key on agent and creates the
// binding's AppRole.
func (controller *Controller) CreateBinding(ctx context.Context, agent string, key protocol.Key, policyName, operator string) (store.Binding, error) {
	started := controller.now()
	record := func(code events.ErrorCode, binding string) {
		controller.record(events.Event{Operation: events.OperationBindingCreated, Outcome: outcomeFor(code), ErrorCode: code,
			Agent: agent, Binding: binding, ContainerKey: events.ContainerKey(string(key.Kind), key.Value),
			Policy: boundedPolicyName(policyName), Operator: operator, Latency: controller.now().Sub(started)})
	}
	if err := key.Validate(); err != nil {
		return store.Binding{}, operationError(events.ErrorPolicyDenied, "the container key is invalid")
	}
	if _, err := controller.store.ApprovedAgent(ctx, agent); err != nil {
		return store.Binding{}, operationError(events.ErrorNotBound, "the agent is not approved")
	}
	stored, err := controller.store.Policy(ctx, policyName)
	if err != nil {
		return store.Binding{}, operationError(events.ErrorNotBound, "the policy does not exist")
	}
	binding := store.Binding{ID: store.NewID("b-"), Agent: agent, Key: key, Policy: policyName, CreatedAt: controller.now(), CreatedBy: operator}
	binding.Role = RoleName(agent, binding.ID)
	if err := controller.openbao.WriteRole(ctx, binding.Role, stored.Policy.OpenBaoPolicyName(), stored.Policy.TokenTTL(), stored.Policy.TokenMaxTTL()); err != nil {
		record(openBaoError(err), "")
		return store.Binding{}, operationError(openBaoError(err), "OpenBao could not create the binding's AppRole")
	}
	if err := controller.store.CreateBinding(ctx, binding); err != nil {
		_ = controller.openbao.DeleteRole(ctx, binding.Role)
		if errors.Is(err, store.ErrConflict) {
			record(events.ErrorPolicyDenied, "")
			return store.Binding{}, operationError(events.ErrorPolicyDenied, "this container key is already bound on the agent")
		}
		record(events.ErrorInternal, "")
		return store.Binding{}, operationError(events.ErrorInternal, "the binding could not be recorded")
	}
	record(events.ErrorNone, binding.ID)
	controller.hub.pushAgent(ctx, agent)
	return binding, nil
}

// ChangeBinding moves a binding to another policy. The AppRole's token
// policy changes so the next token carries it, and the agent receives a
// fresh credential on the push.
func (controller *Controller) ChangeBinding(ctx context.Context, id, policyName, operator string) error {
	started := controller.now()
	binding, err := controller.store.Binding(ctx, id)
	if err != nil {
		return operationError(events.ErrorNotBound, "the binding does not exist")
	}
	record := func(code events.ErrorCode) {
		controller.record(events.Event{Operation: events.OperationBindingChanged, Outcome: outcomeFor(code), ErrorCode: code,
			Agent: binding.Agent, Binding: binding.ID, ContainerKey: events.ContainerKey(string(binding.Key.Kind), binding.Key.Value),
			Policy: boundedPolicyName(policyName), Operator: operator, Latency: controller.now().Sub(started)})
	}
	stored, err := controller.store.Policy(ctx, policyName)
	if err != nil {
		return operationError(events.ErrorNotBound, "the policy does not exist")
	}
	if err := controller.openbao.WriteRole(ctx, binding.Role, stored.Policy.OpenBaoPolicyName(), stored.Policy.TokenTTL(), stored.Policy.TokenMaxTTL()); err != nil {
		record(openBaoError(err))
		return operationError(openBaoError(err), "OpenBao could not update the binding's AppRole")
	}
	if err := controller.store.ChangeBindingPolicy(ctx, id, policyName); err != nil {
		record(events.ErrorInternal)
		return operationError(events.ErrorInternal, "the binding could not be updated")
	}
	record(events.ErrorNone)
	controller.hub.pushAgent(ctx, binding.Agent)
	return nil
}

// DeleteBinding retires a binding. A connected agent is told to revoke
// the binding's token; the controller also revokes it by the accessor the
// agent reported, whether or not the agent is connected, and deletes the
// AppRole. When the token could not be revoked, because revocation failed
// or the agent is not connected and reported no accessor, the binding is
// still removed and the error says the token stays valid until it expires.
func (controller *Controller) DeleteBinding(ctx context.Context, id, operator string) error {
	started := controller.now()
	binding, err := controller.store.Binding(ctx, id)
	if err != nil {
		return operationError(events.ErrorNotBound, "the binding does not exist")
	}
	accessor, accessorErr := controller.store.TokenAccessor(ctx, id)
	connected := controller.hub.send(binding.Agent, protocol.Unbind{Binding: binding.ID}) == nil
	var tokenCode, roleCode events.ErrorCode
	switch {
	case accessorErr == nil:
		if err := controller.openbao.RevokeAccessor(ctx, accessor); err != nil {
			tokenCode = openBaoError(err)
		}
	case !connected:
		tokenCode = events.ErrorControllerUnavailable
	}
	if err := controller.openbao.DeleteRole(ctx, binding.Role); err != nil {
		roleCode = openBaoError(err)
	}
	code := events.ErrorNone
	switch {
	case controller.store.DeleteBinding(ctx, id) != nil:
		code = events.ErrorInternal
	case tokenCode != "":
		code = tokenCode
	case roleCode != "":
		code = roleCode
	}
	controller.record(events.Event{Operation: events.OperationBindingDeleted, Outcome: outcomeFor(code), ErrorCode: code,
		Agent: binding.Agent, Binding: binding.ID, ContainerKey: events.ContainerKey(string(binding.Key.Kind), binding.Key.Value),
		Policy: binding.Policy, Operator: operator, Latency: controller.now().Sub(started)})
	if code == events.ErrorInternal {
		return operationError(code, "the binding could not be removed")
	}
	controller.hub.pushAgent(ctx, binding.Agent)
	switch {
	case code == events.ErrorNone:
		return nil
	case tokenCode == events.ErrorControllerUnavailable:
		return &OperationError{Code: code, TokenLive: true, Message: "the binding was removed, but its agent is not connected " +
			"and has not reported the container's token: the token stays valid until the agent reconnects and revokes it, " +
			"or until it expires"}
	case tokenCode != "":
		return &OperationError{Code: code, TokenLive: true, Message: "the binding was removed, but OpenBao could not revoke " +
			"the container's token: it stays valid until the agent revokes it or it expires"}
	default:
		return operationError(code, "the binding was removed but OpenBao could not delete its AppRole")
	}
}

// RequestRecreate asks the agent to recreate a bound container with its contract.
func (controller *Controller) RequestRecreate(ctx context.Context, id, operator string) error {
	binding, err := controller.store.Binding(ctx, id)
	if err != nil {
		return operationError(events.ErrorNotBound, "the binding does not exist")
	}
	code := events.ErrorNone
	if err := controller.hub.send(binding.Agent, protocol.RecreateRequest{Binding: binding.ID}); err != nil {
		code = events.ErrorControllerUnavailable
	}
	controller.record(events.Event{Operation: events.OperationRecreateRequested, Outcome: outcomeFor(code), ErrorCode: code,
		Agent: binding.Agent, Binding: binding.ID, ContainerKey: events.ContainerKey(string(binding.Key.Kind), binding.Key.Value),
		Policy: binding.Policy, Operator: operator})
	if code != events.ErrorNone {
		return operationError(code, "the agent is not connected")
	}
	return nil
}

// OpenBao exposes the OpenBao manager for key management pages.
func (controller *Controller) OpenBao() OpenBao { return controller.openbao }
