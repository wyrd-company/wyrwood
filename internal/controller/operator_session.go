// ---
// relationships:
//   implements:
//     - controller
//     - operator-interface
//   uses: authenticate-operator-keys-over-ssh
// ---

package controller

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"

	"charm.land/ssh"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
	"github.com/wyrd-company/wyrwood/operator"
)

const outsideGrantMessage = "this key's grant does not cover this request"

var outsideGrant = &OperationError{Code: events.ErrorOutsideGrant, Message: outsideGrantMessage}

// serveOperatorSubsystem answers one operator key's requests in order. Only a
// connection authenticated by the operator list reaches past the first check.
func (controller *Controller) serveOperatorSubsystem(session ssh.Session) {
	fingerprint, ok := session.Context().Value(operatorContextKey{}).(string)
	if !ok {
		_ = session.Exit(1)
		return
	}
	recordCtx, cancel := context.WithTimeout(session.Context(), operationTimeout)
	if err := controller.store.RecordOperatorKeyUse(recordCtx, fingerprint, controller.now()); err != nil {
		controller.logf("operator key use not recorded")
	}
	cancel()
	controller.serveOperatorRequests(session.Context(), fingerprint, session)
	_ = session.Exit(0)
}

func (controller *Controller) serveOperatorRequests(ctx context.Context, fingerprint string, stream io.ReadWriter) {
	reader := bufio.NewReaderSize(stream, 64<<10)
	for {
		line, err := operator.ReadLine(reader, operator.MaximumLineBytes)
		if err != nil {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, operationTimeout)
		response := controller.answerOperator(requestCtx, fingerprint, line)
		cancel()
		encoded, err := encodeOperatorResponse(response)
		if err != nil {
			return
		}
		if _, err := stream.Write(encoded); err != nil {
			return
		}
		if response.Error != nil && response.Error.Code == operator.CodeNotApproved {
			return
		}
	}
}

func encodeOperatorResponse(response operator.Response) ([]byte, error) {
	encoded, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	if len(encoded) >= operator.MaximumResponseBytes {
		encoded, err = json.Marshal(operator.Response{Version: operator.ProtocolVersion, Error: &operator.Error{
			Code: operator.CodeFailed, Message: "the result exceeds the response limit; select one agent",
		}})
		if err != nil {
			return nil, err
		}
	}
	return append(encoded, '\n'), nil
}

func (controller *Controller) answerOperator(ctx context.Context, fingerprint string, line []byte) operator.Response {
	body, err := controller.dispatchOperator(ctx, fingerprint, line)
	response := operator.Response{Version: operator.ProtocolVersion}
	if err != nil {
		response.Error = operatorWireError(err)
		return response
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		response.Error = &operator.Error{Code: operator.CodeFailed, Message: "the result could not be encoded"}
		return response
	}
	response.Body = encoded
	return response
}

var errOperatorNotApproved = errors.New("operator key is not approved")

// pendingError marks a change that is durable and that OpenBao has not applied.
type pendingError struct{ error }

func (err pendingError) Unwrap() error { return err.error }

func operatorWireError(err error) *operator.Error {
	var pending pendingError
	if errors.As(err, &pending) {
		return &operator.Error{Code: operator.CodePending, Message: problemText(err)}
	}
	var wire *operator.Error
	if errors.As(err, &wire) {
		return wire
	}
	if errors.Is(err, errOperatorNotApproved) {
		return &operator.Error{Code: operator.CodeNotApproved, Message: "this key is not approved"}
	}
	var operation *OperationError
	if !errors.As(err, &operation) {
		return &operator.Error{Code: operator.CodeFailed, Message: "the operation failed"}
	}
	result := &operator.Error{Message: operation.Message, Part: string(operation.Part)}
	switch operation.Code {
	case events.ErrorOutsideGrant:
		result.Code = operator.CodeOutsideGrant
	case events.ErrorNotBound:
		result.Code = operator.CodeNotFound
	case events.ErrorPolicyDenied:
		result.Code = operator.CodeInvalid
	default:
		result.Code = operator.CodeFailed
	}
	return result
}

func problemText(err error) string {
	var operation *OperationError
	if errors.As(err, &operation) {
		return operation.Message
	}
	return "the operation failed"
}

func decodeOperatorBody(raw json.RawMessage, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return &operator.Error{Code: operator.CodeInvalid, Message: "the request is not valid"}
	}
	if decoder.More() {
		return &operator.Error{Code: operator.CodeInvalid, Message: "the request is not valid"}
	}
	return nil
}

// dispatchOperator reads the key again for each request, so that a revocation
// holds for a session that is already open, and then checks the grant.
func (controller *Controller) dispatchOperator(ctx context.Context, fingerprint string, line []byte) (any, error) {
	key, err := controller.store.OperatorKey(ctx, fingerprint)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, operationError(events.ErrorInternal, "the key could not be read")
	}
	if err != nil || key.State != store.OperatorKeyApproved {
		return nil, errOperatorNotApproved
	}
	var request operator.Request
	if err := decodeOperatorBody(line, &request); err != nil {
		return nil, err
	}
	if request.Version != operator.ProtocolVersion {
		return nil, &operator.Error{Code: operator.CodeInvalid, Message: "this protocol version is not supported"}
	}
	switch request.Operation {
	case operator.OperationWhoami:
		return operator.Identity{Label: key.Label, Fingerprint: key.Fingerprint, Grant: key.Grant}, nil
	case operator.OperationPolicyList:
		return controller.operatorPolicies(ctx, key)
	case operator.OperationPolicyGet:
		var name operator.PolicyName
		if err := decodeOperatorBody(request.Body, &name); err != nil {
			return nil, err
		}
		return controller.operatorPolicy(ctx, key, name.Name)
	case operator.OperationPolicyPut:
		var put operator.PolicyPut
		if err := decodeOperatorBody(request.Body, &put); err != nil {
			return nil, err
		}
		return controller.operatorPutPolicy(ctx, key, put)
	case operator.OperationBindingList:
		var selection operator.BindingList
		if err := decodeOperatorBody(request.Body, &selection); err != nil {
			return nil, err
		}
		return controller.operatorBindings(ctx, key, selection)
	case operator.OperationBindingGet:
		var id operator.BindingID
		if err := decodeOperatorBody(request.Body, &id); err != nil {
			return nil, err
		}
		return controller.operatorBinding(ctx, key, id.ID)
	case operator.OperationBind:
		var bind operator.BindRequest
		if err := decodeOperatorBody(request.Body, &bind); err != nil {
			return nil, err
		}
		return controller.operatorBind(ctx, key, bind)
	case operator.OperationUnbind:
		var unbind operator.UnbindRequest
		if err := decodeOperatorBody(request.Body, &unbind); err != nil {
			return nil, err
		}
		return controller.operatorUnbind(ctx, key, unbind)
	default:
		return nil, &operator.Error{Code: operator.CodeInvalid, Message: "this operation is not supported"}
	}
}

func publicPolicy(document policy.Policy) operator.Policy {
	result := operator.Policy{Name: document.Name, Revision: document.Revision, HCL: document.OpenBao.Policy, ValueNames: document.ValueNames()}
	if document.SSH != nil {
		result.SSH = &operator.PolicySSH{TransitKeys: document.SSH.TransitKeys, CARoles: document.SSH.CARoles}
	}
	return result
}

func (controller *Controller) operatorPolicies(ctx context.Context, key store.OperatorKey) (operator.Policies, error) {
	result := operator.Policies{Policies: []operator.Policy{}}
	if !key.Grant.Can(operator.ActionRead) {
		return result, outsideGrant
	}
	documents, err := controller.store.Policies(ctx)
	if err != nil {
		return result, operationError(events.ErrorInternal, "policies could not be read")
	}
	for _, stored := range documents {
		if key.Grant.AllowsPolicy(stored.Policy.Name) {
			result.Policies = append(result.Policies, publicPolicy(stored.Policy))
		}
	}
	return result, nil
}

func (controller *Controller) operatorPolicy(ctx context.Context, key store.OperatorKey, name string) (operator.Policy, error) {
	if !key.Grant.Can(operator.ActionRead) || !key.Grant.AllowsPolicy(name) {
		return operator.Policy{}, outsideGrant
	}
	stored, err := controller.store.Policy(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return operator.Policy{}, operationError(events.ErrorNotBound, "the policy does not exist")
	}
	if err != nil {
		return operator.Policy{}, operationError(events.ErrorInternal, "the policy could not be read")
	}
	return publicPolicy(stored.Policy), nil
}

// operatorPutPolicy writes a policy for a key whose grant covers it and every
// binding that holds it, since a policy change reaches those bindings.
func (controller *Controller) operatorPutPolicy(ctx context.Context, key store.OperatorKey, put operator.PolicyPut) (operator.Policy, error) {
	started := controller.now()
	subject := OperatorSubject(key.Label)
	controller.mutationMu.Lock()
	saved, agents, err := controller.authorizedPutPolicy(ctx, key, put, subject)
	controller.mutationMu.Unlock()
	code := mutationErrorCode(err)
	controller.record(events.Event{Operation: events.OperationPolicySaved, Outcome: outcomeFor(code), ErrorCode: code, Policy: boundedPolicyName(put.Name), Operator: subject, Latency: controller.now().Sub(started)})
	for agent := range agents {
		controller.hub.pushAgent(ctx, agent)
	}
	if err != nil && saved.Name != "" {
		return publicPolicy(saved), pendingError{err}
	}
	if err != nil {
		return operator.Policy{}, err
	}
	return publicPolicy(saved), nil
}

func (controller *Controller) authorizedPutPolicy(ctx context.Context, key store.OperatorKey, put operator.PolicyPut, subject string) (policy.Policy, map[string]bool, error) {
	if !key.Grant.Can(operator.ActionPolicyWrite) || !key.Grant.AllowsPolicy(put.Name) {
		return policy.Policy{}, nil, outsideGrant
	}
	bindings, err := controller.store.Bindings(ctx, "")
	if err != nil {
		return policy.Policy{}, nil, operationError(events.ErrorInternal, "bindings could not be read")
	}
	for _, b := range bindings {
		if b.HasPolicy(put.Name) && !key.Grant.Covers(b.Agent, b.Policies) {
			return policy.Policy{}, nil, outsideGrant
		}
	}
	document := policy.New(put.Name, put.HCL)
	stored, err := controller.store.Policy(ctx, put.Name)
	switch {
	case err == nil:
		document = stored.Policy.Clone()
		document.OpenBao.Policy = put.HCL
	case !errors.Is(err, store.ErrNotFound):
		return policy.Policy{}, nil, operationError(events.ErrorInternal, "the stored policy could not be read")
	}
	if put.SSH != nil {
		document.SSH = replaceSSH(document.SSH, *put.SSH)
	}
	return controller.savePolicy(ctx, document, subject)
}

// replaceSSH sets the offered identities, and keeps the not-forwardable mark on
// each identity that is still offered.
func replaceSSH(previous *policy.SSH, put operator.PolicySSH) *policy.SSH {
	if len(put.TransitKeys) == 0 && len(put.CARoles) == 0 {
		return nil
	}
	result := &policy.SSH{TransitKeys: put.TransitKeys, CARoles: put.CARoles}
	if previous == nil || previous.NotForwardable == nil {
		return result
	}
	kept := policy.SSHIdentityNames{}
	for _, name := range previous.NotForwardable.TransitKeys {
		if slices.Contains(put.TransitKeys, name) {
			kept.TransitKeys = append(kept.TransitKeys, name)
		}
	}
	for _, name := range previous.NotForwardable.CARoles {
		if slices.Contains(put.CARoles, name) {
			kept.CARoles = append(kept.CARoles, name)
		}
	}
	if len(kept.TransitKeys) > 0 || len(kept.CARoles) > 0 {
		result.NotForwardable = &kept
	}
	return result
}

func publicSettings(settings policy.Settings) operator.Settings {
	return operator.Settings{
		TokenTTL: settings.TokenTTL, TokenMaxTTL: settings.TokenMaxTTL, AccessGroup: settings.AccessGroup,
		Enforcement: string(settings.Enforcement), Values: settings.Values,
	}
}

func publicStatus(status BindingStatus) (operator.BindingStatus, error) {
	var result operator.BindingStatus
	encoded, err := json.Marshal(status)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(encoded, &result)
	return result, err
}

func publicBinding(b store.Binding, status BindingStatus) (operator.Binding, error) {
	public, err := publicStatus(status)
	if err != nil {
		return operator.Binding{}, operationError(events.ErrorInternal, "the binding status could not be read")
	}
	return operator.Binding{
		ID: b.ID, Agent: b.Agent, Key: operator.Key{Kind: operator.KeyKind(b.Key.Kind), Value: b.Key.Value},
		Policies: b.Policies, Settings: publicSettings(b.Settings), Revision: b.Revision, Applied: b.Applied, Status: public,
	}, nil
}

func (controller *Controller) operatorBindings(ctx context.Context, key store.OperatorKey, selection operator.BindingList) (operator.Bindings, error) {
	result := operator.Bindings{Bindings: []operator.Binding{}}
	if !key.Grant.Can(operator.ActionRead) || (selection.Agent != "" && !key.Grant.AllowsAgent(selection.Agent)) {
		return result, outsideGrant
	}
	bindings, err := controller.store.Bindings(ctx, selection.Agent)
	if err != nil {
		return result, operationError(events.ErrorInternal, "bindings could not be read")
	}
	statuses := map[string]map[string]BindingStatus{}
	for _, b := range bindings {
		if !key.Grant.Covers(b.Agent, b.Policies) {
			continue
		}
		if statuses[b.Agent] == nil {
			list, err := controller.BindingStatuses(ctx, b.Agent)
			if err != nil {
				return result, operationError(events.ErrorInternal, "binding status could not be read")
			}
			statuses[b.Agent] = make(map[string]BindingStatus, len(list))
			for _, status := range list {
				statuses[b.Agent][status.Binding] = status
			}
		}
		public, err := publicBinding(b, statuses[b.Agent][b.ID])
		if err != nil {
			return result, err
		}
		result.Bindings = append(result.Bindings, public)
	}
	return result, nil
}

func (controller *Controller) operatorBinding(ctx context.Context, key store.OperatorKey, id string) (operator.Binding, error) {
	if !key.Grant.Can(operator.ActionRead) {
		return operator.Binding{}, outsideGrant
	}
	b, err := controller.store.Binding(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return operator.Binding{}, operationError(events.ErrorNotBound, "the binding does not exist")
	}
	if err != nil {
		return operator.Binding{}, operationError(events.ErrorInternal, "the binding could not be read")
	}
	if !key.Grant.Covers(b.Agent, b.Policies) {
		return operator.Binding{}, outsideGrant
	}
	return controller.readOperatorBinding(ctx, b)
}

func (controller *Controller) readOperatorBinding(ctx context.Context, b store.Binding) (operator.Binding, error) {
	status, err := controller.BindingStatus(ctx, b.ID)
	if err != nil {
		return operator.Binding{}, operationError(events.ErrorInternal, "binding status could not be read")
	}
	return publicBinding(b, status)
}

func protocolKey(key operator.Key) protocol.Key {
	return protocol.Key{Kind: protocol.KeyKind(key.Kind), Value: key.Value}
}

func eventAgent(agent string) string {
	if ValidAgentName(agent) {
		return agent
	}
	return ""
}

func (controller *Controller) recordDenied(operation events.Operation, agent, subject string) {
	controller.record(events.Event{Operation: operation, Outcome: events.OutcomeDenied, ErrorCode: events.ErrorOutsideGrant, Agent: eventAgent(agent), Operator: subject})
}

// operatorBind returns the binding of a container key, creating it when absent.
// A repeat of the same selection also finishes an assignment that OpenBao could
// not apply before. Another selection changes nothing, so that a script cannot
// read a binding as what it asked for when it is not.
func (controller *Controller) operatorBind(ctx context.Context, key store.OperatorKey, request operator.BindRequest) (operator.Binding, error) {
	subject := OperatorSubject(key.Label)
	if !key.Grant.Can(operator.ActionBind) || !key.Grant.Covers(request.Agent, request.Policies) {
		controller.recordDenied(events.OperationBindingCreated, request.Agent, subject)
		return operator.Binding{}, outsideGrant
	}
	selection := BindingRequest{Policies: request.Policies, Settings: policy.Settings{
		TokenTTL: request.Settings.TokenTTL, TokenMaxTTL: request.Settings.TokenMaxTTL, AccessGroup: request.Settings.AccessGroup,
		Enforcement: policy.Enforcement(request.Settings.Enforcement), Values: request.Settings.Values,
	}}
	wanted := protocolKey(request.Key)
	started := controller.now()
	controller.mutationMu.Lock()
	existing, found, err := controller.findBinding(ctx, request.Agent, wanted)
	if err != nil {
		controller.mutationMu.Unlock()
		return operator.Binding{}, err
	}
	if found {
		applied, err := controller.repeatBind(ctx, key, existing, selection)
		controller.mutationMu.Unlock()
		if errors.Is(err, outsideGrant) {
			controller.recordDenied(events.OperationBindingCreated, request.Agent, subject)
		}
		if err != nil {
			return operator.Binding{}, err
		}
		if !existing.Applied {
			controller.hub.pushAgent(ctx, request.Agent)
		}
		return controller.readOperatorBinding(ctx, applied)
	}
	created, err := controller.createBinding(ctx, request.Agent, wanted, selection, subject)
	controller.mutationMu.Unlock()
	controller.finishCreateBinding(ctx, request.Agent, wanted, created, err, subject, started)
	if err != nil && created.ID != "" {
		return operator.Binding{}, pendingError{err}
	}
	if err != nil {
		return operator.Binding{}, err
	}
	return controller.readOperatorBinding(ctx, created)
}

func (controller *Controller) repeatBind(ctx context.Context, key store.OperatorKey, existing store.Binding, selection BindingRequest) (store.Binding, error) {
	if !key.Grant.Covers(existing.Agent, existing.Policies) {
		return existing, outsideGrant
	}
	effective, err := controller.compose(ctx, selection.Policies, selection.Settings, nil)
	if err != nil {
		return existing, err
	}
	if effective.Identity() != existing.Effective.Identity() {
		return existing, &operator.Error{Code: operator.CodeBindingDiffer, Message: "this container key is bound to another selection; unbind it first"}
	}
	if err := controller.applyBinding(ctx, existing); err != nil {
		return existing, pendingError{operationError(openBaoError(err), "binding saved; OpenBao could not apply its pending assignment")}
	}
	existing.Applied = true
	return existing, nil
}

func (controller *Controller) findBinding(ctx context.Context, agent string, key protocol.Key) (store.Binding, bool, error) {
	bindings, err := controller.store.Bindings(ctx, agent)
	if err != nil {
		return store.Binding{}, false, operationError(events.ErrorInternal, "bindings could not be read")
	}
	for _, b := range bindings {
		if b.Key == key {
			return b, true, nil
		}
	}
	return store.Binding{}, false, nil
}

// operatorUnbind removes a binding inside the grant. A binding that is not there
// is a success, and a removal that left its token live is a success with a warning.
func (controller *Controller) operatorUnbind(ctx context.Context, key store.OperatorKey, request operator.UnbindRequest) (operator.UnbindResult, error) {
	subject := OperatorSubject(key.Label)
	byID := request.ID != ""
	byKey := request.Agent != "" || request.Key != nil
	if byID == byKey || (byKey && (request.Agent == "" || request.Key == nil)) {
		return operator.UnbindResult{}, &operator.Error{Code: operator.CodeInvalid, Message: "select a binding by its ID, or by its agent and key"}
	}
	if !key.Grant.Can(operator.ActionBind) || (byKey && !key.Grant.AllowsAgent(request.Agent)) {
		controller.recordDenied(events.OperationBindingDeleted, request.Agent, subject)
		return operator.UnbindResult{}, outsideGrant
	}
	// The lock holds from the grant check through the removal, so that a change to
	// the binding cannot fall between them, and the agent hears only of a removal.
	controller.mutationMu.Lock()
	b, exists, err := controller.resolveUnbind(ctx, request, byID)
	if err != nil || !exists {
		controller.mutationMu.Unlock()
		return operator.UnbindResult{}, err
	}
	if !key.Grant.Covers(b.Agent, b.Policies) {
		controller.mutationMu.Unlock()
		controller.recordDenied(events.OperationBindingDeleted, b.Agent, subject)
		return operator.UnbindResult{}, outsideGrant
	}
	err = controller.deleteBinding(ctx, b.ID, subject, controller.Connected(b.Agent))
	controller.mutationMu.Unlock()
	if !bindingStays(err) {
		_ = controller.hub.send(b.Agent, protocol.Unbind{Binding: b.ID})
	}
	controller.hub.pushAgent(ctx, b.Agent)
	if err == nil {
		return operator.UnbindResult{Removed: true}, nil
	}
	var operation *OperationError
	if !errors.As(err, &operation) {
		return operator.UnbindResult{}, err
	}
	switch {
	case operation.TokenLive:
		return operator.UnbindResult{Removed: true, TokenLive: true, Warning: operation.Message}, nil
	case operation.Code == events.ErrorInternal:
		return operator.UnbindResult{}, err
	default:
		return operator.UnbindResult{Removed: true, Warning: operation.Message}, nil
	}
}

func (controller *Controller) resolveUnbind(ctx context.Context, request operator.UnbindRequest, byID bool) (store.Binding, bool, error) {
	if !byID {
		return controller.findBinding(ctx, request.Agent, protocolKey(*request.Key))
	}
	found, err := controller.store.Binding(ctx, request.ID)
	if errors.Is(err, store.ErrNotFound) {
		return store.Binding{}, false, nil
	}
	if err != nil {
		return store.Binding{}, false, operationError(events.ErrorInternal, "the binding could not be read")
	}
	return found, true, nil
}

// bindingStays reports whether a failed deletion left the binding in place.
func bindingStays(err error) bool {
	var operation *OperationError
	return errors.As(err, &operation) && operation.Code == events.ErrorInternal
}
