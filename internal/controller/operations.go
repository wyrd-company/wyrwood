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
	"reflect"
	"regexp"
	"slices"
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

// BindingRequest replaces the complete policy selection and runtime settings.
type BindingRequest = policy.Selection

func boundedPolicyName(name string) string {
	if len(name) > 64 || strings.ContainsAny(name, "\x00\n\r\t") {
		return ""
	}
	return name
}

func (controller *Controller) compose(ctx context.Context, names []string, settings policy.Settings, replacement *policy.Policy) (policy.Effective, error) {
	var sources []policy.Policy
	for _, name := range names {
		if replacement != nil && name == replacement.Name {
			sources = append(sources, *replacement)
			continue
		}
		stored, err := controller.store.Policy(ctx, name)
		if err != nil {
			return policy.Effective{}, operationError(events.ErrorPolicyDenied, "policy %s does not exist", boundedPolicyName(name))
		}
		sources = append(sources, stored.Policy)
	}
	effective, err := policy.Compose(sources, settings)
	if err != nil {
		return policy.Effective{}, operationError(events.ErrorPolicyDenied, "the policy selection is invalid: %v", err)
	}
	return effective, nil
}

// PreviewBinding uses exactly the same composition as persistence and delivery.
func (controller *Controller) PreviewBinding(ctx context.Context, request BindingRequest) (policy.Effective, error) {
	controller.mutationMu.Lock()
	defer controller.mutationMu.Unlock()
	return controller.compose(ctx, request.Policies, request.Settings, nil)
}

func (controller *Controller) applyBinding(ctx context.Context, b store.Binding) error {
	// Derive allowed names only from the durable resolved selection.
	if !slices.Equal(b.Policies, b.Effective.Names()) {
		return operationError(events.ErrorPolicyDenied, "binding policy membership is inconsistent")
	}
	if b.Applied {
		return nil
	}
	if err := controller.openbao.WriteRole(ctx, b.Role, b.Effective.OpenBaoPolicies(), b.Settings.TTL(), b.Settings.MaxTTL()); err != nil {
		return err
	}
	accessor, err := controller.store.TokenAccessor(ctx, b.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if accessor != "" {
		if err := controller.openbao.RevokeAccessor(ctx, accessor); err != nil {
			return err
		}
	}
	return controller.store.MarkBindingApplied(ctx, b.ID)
}

// SavePolicy preflights every affected composition before publishing the HCL.
func (controller *Controller) SavePolicy(ctx context.Context, document policy.Policy, operator string) (policy.Policy, error) {
	started := controller.now()
	controller.mutationMu.Lock()
	saved, agents, err := controller.savePolicy(ctx, document, operator)
	controller.mutationMu.Unlock()
	code := mutationErrorCode(err)
	controller.record(events.Event{Operation: events.OperationPolicySaved, Outcome: outcomeFor(code), ErrorCode: code, Policy: boundedPolicyName(document.Name), Operator: operator, Latency: controller.now().Sub(started)})
	for agent := range agents {
		controller.hub.pushAgent(ctx, agent)
	}
	return saved, err
}
func (controller *Controller) savePolicy(ctx context.Context, document policy.Policy, operator string) (policy.Policy, map[string]bool, error) {
	agents := map[string]bool{}
	fail := func(message string) (policy.Policy, map[string]bool, error) {
		return policy.Policy{}, agents, operationError(events.ErrorPolicyDenied, "%s", message)
	}
	if err := document.Validate(); err != nil {
		return fail("the policy is invalid: " + err.Error())
	}
	for _, name := range document.TransitKeys() {
		exists, err := controller.openbao.TransitKeyExists(ctx, name)
		if err != nil || !exists {
			return fail("OpenBao could not confirm Transit key " + name)
		}
	}
	for _, name := range document.CARoles() {
		exists, err := controller.openbao.SSHRoleExists(ctx, name)
		if err != nil || !exists {
			return fail("OpenBao could not confirm SSH role " + name)
		}
	}
	old, lookup := controller.store.Policy(ctx, document.Name)
	if lookup != nil && !errors.Is(lookup, store.ErrNotFound) {
		return fail("the stored policy could not be read")
	}
	if lookup == nil {
		previous := old.Policy.Clone()
		candidate := document.Clone()
		previous.Revision = 0
		candidate.Revision = 0
		if reflect.DeepEqual(previous, candidate) {
			return old.Policy, agents, nil
		}
		document.Revision = old.Policy.Revision + 1
	} else {
		document.Revision = 1
	}
	bindings, err := controller.store.Bindings(ctx, "")
	if err != nil {
		return fail("bindings could not be read")
	}
	var affected []store.Binding
	for _, b := range bindings {
		if !b.HasPolicy(document.Name) {
			continue
		}
		effective, err := controller.compose(ctx, b.Policies, b.Settings, &document)
		if err != nil {
			return policy.Policy{}, agents, err
		}
		b.Effective = effective
		b.Revision++
		b.Applied = false
		affected = append(affected, b)
	}
	if err := controller.preflight(ctx, affected); err != nil {
		return policy.Policy{}, agents, err
	}
	if err := controller.openbao.WritePolicy(ctx, document.OpenBaoPolicyName(), document.PublishedHCL()); err != nil {
		if openbao.CategoryOf(err) == openbao.CategoryInvalid {
			return fail("OpenBao rejected the HCL policy")
		}
		if err := controller.restorePolicy(ctx, document.Name, old, lookup == nil); err != nil {
			return fail("OpenBao policy publication was uncertain; restoration is pending and fresh issuance is blocked")
		}
		return fail("OpenBao could not store the HCL policy; its change was rolled back")
	}
	saved, err := controller.store.SavePolicyBindings(ctx, document, affected, operator, controller.now())
	if err != nil {
		if err := controller.restorePolicy(ctx, document.Name, old, lookup == nil); err != nil {
			return fail("the policy could not be recorded; OpenBao restoration is pending and fresh issuance is blocked")
		}
		return fail("the policy could not be recorded; the OpenBao change was rolled back")
	}
	var transitionErr error
	for _, b := range affected {
		agents[b.Agent] = true
		if err := controller.applyBinding(ctx, b); err != nil {
			transitionErr = operationError(openBaoError(err), "policy saved; a binding transition is pending until OpenBao can apply and revoke its old token")
		}
	}
	if transitionErr != nil {
		return saved, agents, transitionErr
	}
	return saved, agents, nil
}

func (controller *Controller) CreateBinding(ctx context.Context, agent string, key protocol.Key, request BindingRequest, operator string) (store.Binding, error) {
	started := controller.now()
	controller.mutationMu.Lock()
	b, err := controller.createBinding(ctx, agent, key, request, operator)
	controller.mutationMu.Unlock()
	eventBinding := b
	if eventBinding.ID == "" {
		eventBinding.Agent = agent
		eventBinding.Key = key
	}
	// Failed input is not an audit fan-out source. One categorical event
	// identifies the attempted binding even for repeated or oversized input.
	if err != nil {
		eventBinding.Policies = nil
	}
	code := mutationErrorCode(err)
	controller.recordBinding(eventBinding, events.Event{Operation: events.OperationBindingCreated, Outcome: outcomeFor(code), ErrorCode: code, Binding: b.ID, Agent: agent, Operator: operator, Latency: controller.now().Sub(started)})
	if b.ID != "" {
		controller.hub.pushAgent(ctx, agent)
	}
	return b, err
}
func (controller *Controller) createBinding(ctx context.Context, agent string, key protocol.Key, request BindingRequest, operator string) (store.Binding, error) {
	if err := key.Validate(); err != nil {
		return store.Binding{}, operationError(events.ErrorPolicyDenied, "the container key is invalid")
	}
	if _, err := controller.store.ApprovedAgent(ctx, agent); err != nil {
		return store.Binding{}, operationError(events.ErrorNotBound, "the agent is not approved")
	}
	if err := controller.validateAccessGroup(agent, request.Settings.AccessGroup); err != nil {
		return store.Binding{}, err
	}
	effective, err := controller.compose(ctx, request.Policies, request.Settings, nil)
	if err != nil {
		return store.Binding{}, err
	}
	b := store.Binding{ID: store.NewID("b-"), Agent: agent, Key: key, Policies: effective.Names(), Settings: effective.Settings, Effective: effective, Revision: 1, CreatedAt: controller.now(), CreatedBy: operator}
	b.Role = RoleName(agent, b.ID)
	if err := controller.preflight(ctx, []store.Binding{b}); err != nil {
		return store.Binding{}, err
	}
	if err := controller.store.CreateBinding(ctx, b); err != nil {
		return store.Binding{}, operationError(events.ErrorPolicyDenied, "this container key is already bound or the binding could not be recorded")
	}
	if err := controller.applyBinding(ctx, b); err != nil {
		return b, operationError(openBaoError(err), "binding saved; OpenBao could not apply its pending assignment")
	}
	b.Applied = true
	return b, nil
}

func (controller *Controller) ChangeBinding(ctx context.Context, id string, request BindingRequest, operator string) error {
	started := controller.now()
	controller.mutationMu.Lock()
	b, err := controller.changeBinding(ctx, id, request, operator)
	controller.mutationMu.Unlock()
	eventBinding := b
	// Failed input is not an audit fan-out source. One categorical event
	// identifies the attempted binding even for repeated or oversized input.
	if err != nil {
		eventBinding.Policies = nil
	}
	code := mutationErrorCode(err)
	controller.recordBinding(eventBinding, events.Event{Operation: events.OperationBindingChanged, Outcome: outcomeFor(code), ErrorCode: code, Binding: id, Agent: b.Agent, Operator: operator, Latency: controller.now().Sub(started)})
	if b.ID != "" {
		controller.hub.pushAgent(ctx, b.Agent)
	}
	return err
}
func (controller *Controller) changeBinding(ctx context.Context, id string, request BindingRequest, operator string) (store.Binding, error) {
	b, err := controller.store.Binding(ctx, id)
	if err != nil {
		return b, operationError(events.ErrorNotBound, "the binding does not exist")
	}
	if request.Revision != b.Revision {
		return b, operationError(events.ErrorPolicyDenied, "the binding changed; reload before saving")
	}
	if err := controller.validateAccessGroup(b.Agent, request.Settings.AccessGroup); err != nil {
		return b, err
	}
	effective, err := controller.compose(ctx, request.Policies, request.Settings, nil)
	if err != nil {
		return b, err
	}
	if effective.Identity() == b.Effective.Identity() {
		return b, nil
	}
	b.Policies = effective.Names()
	b.Settings = effective.Settings
	b.Effective = effective
	b.Revision++
	b.Applied = false
	if err := controller.preflight(ctx, []store.Binding{b}); err != nil {
		return b, err
	}
	if err := controller.store.ChangeBinding(ctx, b); err != nil {
		return b, operationError(events.ErrorInternal, "the binding could not be updated")
	}
	if err := controller.applyBinding(ctx, b); err != nil {
		return b, operationError(openBaoError(err), "binding saved; token transition pending until the old token can be revoked")
	}
	return b, nil
}

// DeleteBinding retires a binding. A connected agent is told to revoke
// the binding's token. The AppRole is deleted first, which stops new logins
// and voids outstanding secret identifiers; then the binding is retired and
// the token is revoked by the latest accessor the agent reported, whether or
// not the agent is connected. An accessor the agent reports after this is
// revoked as it arrives. When the token could not be revoked, because
// revocation failed or the agent is not connected and reported no accessor,
// the binding is still removed and the error says the token stays valid
// until it expires.
func (controller *Controller) DeleteBinding(ctx context.Context, id, operator string) error {
	binding, _ := controller.store.Binding(ctx, id)
	connected := binding.ID != "" && controller.hub.send(binding.Agent, protocol.Unbind{Binding: binding.ID}) == nil
	controller.mutationMu.Lock()
	err := controller.deleteBinding(ctx, id, operator, connected)
	controller.mutationMu.Unlock()
	if binding.ID != "" {
		controller.hub.pushAgent(ctx, binding.Agent)
	}
	return err
}
func (controller *Controller) deleteBinding(ctx context.Context, id, operator string, connected bool) error {
	started := controller.now()
	binding, err := controller.store.Binding(ctx, id)
	if err != nil {
		return operationError(events.ErrorNotBound, "the binding does not exist")
	}
	var roleCode, tokenCode events.ErrorCode
	if err := controller.openbao.DeleteRole(ctx, binding.Role); err != nil {
		roleCode = openBaoError(err)
	}
	accessor, retireErr := controller.store.RetireBinding(ctx, id, controller.now())
	switch {
	case retireErr != nil:
	case accessor != "":
		if err := controller.openbao.RevokeAccessor(ctx, accessor); err != nil {
			tokenCode = openBaoError(err)
		}
	case !connected:
		tokenCode = events.ErrorControllerUnavailable
	}
	code := events.ErrorNone
	switch {
	case retireErr != nil:
		code = events.ErrorInternal
	case tokenCode != "":
		code = tokenCode
	case roleCode != "":
		code = roleCode
	}
	controller.recordBinding(binding, events.Event{Operation: events.OperationBindingDeleted, Outcome: outcomeFor(code), ErrorCode: code,
		Agent: binding.Agent, Binding: binding.ID, ContainerKey: events.ContainerKey(string(binding.Key.Kind), binding.Key.Value),
		Operator: operator, Latency: controller.now().Sub(started)})
	if code == events.ErrorInternal {
		return operationError(code, "the binding could not be removed")
	}
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
	controller.recordBinding(binding, events.Event{Operation: events.OperationRecreateRequested, Outcome: outcomeFor(code), ErrorCode: code,
		Agent: binding.Agent, Binding: binding.ID, ContainerKey: events.ContainerKey(string(binding.Key.Kind), binding.Key.Value),
		Operator: operator})
	if code != events.ErrorNone {
		return operationError(code, "the agent is not connected")
	}
	return nil
}

// OpenBao exposes the OpenBao manager for key management pages.
func (controller *Controller) OpenBao() OpenBao { return controller.openbao }

// preflight applies the existing wire bound to each assignment and the complete
// matched policy set before a mutation becomes durable.
func (controller *Controller) preflight(ctx context.Context, candidates []store.Binding) error {
	agents := map[string][]store.Binding{}
	wire := func(b store.Binding) protocol.Binding {
		return protocol.Binding{Binding: b.ID, Key: b.Key, Assignment: b.Assignment(), Policy: b.Effective}
	}
	for _, b := range candidates {
		if _, err := protocol.Encode(protocol.PolicySet{OpenBao: controller.agentOB, Bindings: []protocol.Binding{wire(b)}}); err != nil {
			return operationError(events.ErrorPolicyDenied, "effective policy exceeds the agent protocol limits")
		}
		agents[b.Agent] = append(agents[b.Agent], b)
	}
	for agent, changes := range agents {
		bindings, err := controller.store.Bindings(ctx, agent)
		if err != nil {
			return operationError(events.ErrorInternal, "bindings could not be read")
		}
		for _, change := range changes {
			found := false
			for i, b := range bindings {
				if b.ID == change.ID {
					bindings[i] = change
					found = true
				}
			}
			if !found {
				bindings = append(bindings, change)
			}
		}
		containers, _, err := controller.store.Inventory(ctx, agent)
		if err != nil {
			continue
		}
		set := protocol.PolicySet{OpenBao: controller.agentOB, Bindings: []protocol.Binding{}}
		for _, b := range MatchBindings(containers, bindings) {
			set.Bindings = append(set.Bindings, wire(b))
		}
		if _, err := protocol.Encode(set); err != nil {
			return operationError(events.ErrorPolicyDenied, "the complete effective policy set exceeds the agent protocol limits")
		}
	}
	return nil
}

// reconcileBindings repairs durable pending transitions on controller startup.
// Issuance uses the same gate again on every credential request.
func (controller *Controller) reconcileBindings(ctx context.Context) error {
	controller.mutationMu.Lock()
	defer controller.mutationMu.Unlock()
	if err := controller.syncPolicies(ctx); err != nil {
		return err
	}
	bindings, err := controller.store.Bindings(ctx, "")
	if err != nil {
		return operationError(events.ErrorInternal, "bindings could not be read")
	}
	var failures []error
	for _, b := range bindings {
		if err := controller.applyBinding(ctx, b); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// SQLite is the authoritative source after a partial policy publication.
func (controller *Controller) syncPolicies(ctx context.Context) error {
	controller.policySyncPending = true
	documents, err := controller.store.Policies(ctx)
	if err != nil {
		return err
	}
	for _, stored := range documents {
		if err := controller.openbao.WritePolicy(ctx, stored.Policy.OpenBaoPolicyName(), stored.Policy.PublishedHCL()); err != nil {
			return err
		}
	}
	controller.policySyncPending = false
	return nil
}

func (controller *Controller) recordBinding(b store.Binding, event events.Event) {
	if len(b.Policies) == 0 {
		controller.record(event)
		return
	}
	for _, name := range b.Policies {
		event.Policy = boundedPolicyName(name)
		controller.record(event)
	}
}

// An interrupted response can hide a successful remote write. Restore the
// authoritative source on either a remote or local publication failure.
func (controller *Controller) restorePolicy(ctx context.Context, name string, previous store.StoredPolicy, existed bool) error {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), operationTimeout)
	defer cancel()
	var err error
	if existed {
		err = controller.openbao.WritePolicy(rollbackCtx, previous.Policy.OpenBaoPolicyName(), previous.Policy.PublishedHCL())
	} else {
		err = controller.openbao.DeletePolicy(rollbackCtx, "wyrwood-"+name)
	}
	if err != nil {
		controller.policySyncPending = true
	}
	return err
}

func mutationErrorCode(err error) events.ErrorCode {
	if err == nil {
		return events.ErrorNone
	}
	var operation *OperationError
	if errors.As(err, &operation) && operation.Code != events.ErrorNone {
		return operation.Code
	}
	return events.ErrorInternal
}
