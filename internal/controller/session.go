// ---
// relationships:
//   implements:
//     - controller
//     - agent-controller-protocol
// ---

package controller

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// ErrAgentDisconnected means an operation needs a live agent session.
var ErrAgentDisconnected = errors.New("agent is not connected")

type hub struct {
	controller *Controller
	mu         sync.Mutex
	sessions   map[string]*agentSession
}

func newHub(controller *Controller) *hub {
	return &hub{controller: controller, sessions: map[string]*agentSession{}}
}

type agentSession struct {
	controller *Controller
	agent      string
	conn       *protocol.Conn
	closer     io.Closer
	cancel     context.CancelFunc

	// pushMu serializes computing and sending policy sets so a newer set
	// is never overtaken by an older one.
	pushMu sync.Mutex

	mu sync.Mutex
	// credentialed maps each binding the agent received a credential for in
	// this session to the policy that credential carried.
	credentialed map[string]string
	matched      map[string]bool
}

// serve runs one agent session until the stream ends or a newer session
// replaces it.
func (hub *hub) serve(parent context.Context, identity authenticatedAgent, stream io.ReadWriteCloser) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	session := &agentSession{
		controller: hub.controller, agent: identity.name, conn: protocol.NewConn(stream),
		closer: stream, cancel: cancel, credentialed: map[string]string{}, matched: map[string]bool{},
	}
	controller := hub.controller
	started := controller.now()
	hello, err := session.receiveHello(ctx)
	if err != nil {
		controller.record(events.Event{Operation: events.OperationSessionOpened, Outcome: events.OutcomeFailed,
			ErrorCode: events.ErrorProtocol, Agent: identity.name, Latency: controller.now().Sub(started)})
		return
	}
	recordCtx, recordCancel := context.WithTimeout(ctx, operationTimeout)
	_ = controller.store.RecordConnection(recordCtx, identity.fingerprint, boundedVersion(hello.AgentVersion), hello.AllowRecreate, controller.now())
	recordCancel()

	hub.mu.Lock()
	previous := hub.sessions[identity.name]
	hub.sessions[identity.name] = session
	hub.mu.Unlock()
	if previous != nil {
		previous.close()
	}
	controller.record(events.Event{Operation: events.OperationSessionOpened, Outcome: events.OutcomeOK,
		Agent: identity.name, Latency: controller.now().Sub(started)})

	closeCode := events.ErrorNone
	for {
		message, err := session.conn.Receive()
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				closeCode = events.ErrorProtocol
			}
			break
		}
		if err := session.handle(ctx, identity, message); err != nil {
			closeCode = events.ErrorProtocol
			break
		}
	}
	hub.mu.Lock()
	if hub.sessions[identity.name] == session {
		delete(hub.sessions, identity.name)
	}
	hub.mu.Unlock()
	controller.record(events.Event{Operation: events.OperationSessionClosed, Outcome: outcomeFor(closeCode),
		ErrorCode: closeCode, Agent: identity.name, Latency: controller.now().Sub(started)})
}

func boundedVersion(value string) string {
	if len(value) > 64 {
		return value[:64]
	}
	return value
}

func (session *agentSession) receiveHello(ctx context.Context) (protocol.Hello, error) {
	type result struct {
		message protocol.Message
		err     error
	}
	received := make(chan result, 1)
	go func() {
		message, err := session.conn.Receive()
		received <- result{message, err}
	}()
	select {
	case <-ctx.Done():
		return protocol.Hello{}, ctx.Err()
	case <-time.After(helloTimeout):
		_ = session.closer.Close()
		return protocol.Hello{}, errors.New("hello timeout")
	case outcome := <-received:
		if outcome.err != nil {
			return protocol.Hello{}, outcome.err
		}
		hello, ok := outcome.message.(protocol.Hello)
		if !ok {
			return protocol.Hello{}, errors.New("first message must be hello")
		}
		return hello, nil
	}
}

func (session *agentSession) close() {
	session.cancel()
	_ = session.closer.Close()
}

func (session *agentSession) handle(ctx context.Context, identity authenticatedAgent, message protocol.Message) error {
	controller := session.controller
	switch typed := message.(type) {
	case protocol.Inventory:
		saveCtx, cancel := context.WithTimeout(ctx, operationTimeout)
		err := controller.store.SaveInventory(saveCtx, identity.name, identity.fingerprint, typed.Containers, controller.now())
		cancel()
		if err != nil {
			controller.logf("inventory not recorded")
		}
		return session.push(ctx)
	case protocol.ContractResult:
		// The acknowledgement tells the agent it may discard its durable
		// copy, so it is sent only once the result is stored or can never
		// be: its binding is gone or belongs to another agent.
		binding, err := controller.store.Binding(ctx, typed.Binding)
		switch {
		case errors.Is(err, store.ErrNotFound), err == nil && binding.Agent != session.agent:
			return session.conn.Send(typed.Acknowledge())
		case err != nil:
			controller.logf("contract result not recorded")
			return nil
		}
		if err := controller.store.SaveContractResult(ctx, typed, controller.now()); err != nil {
			// A save that fails because the binding was deleted meanwhile
			// is a discard; any other failure leaves the agent's copy.
			if _, lookup := controller.store.Binding(ctx, typed.Binding); !errors.Is(lookup, store.ErrNotFound) {
				controller.logf("contract result not recorded")
				return nil
			}
		}
		return session.conn.Send(typed.Acknowledge())
	case protocol.TokenAccessor:
		return session.recordAccessor(ctx, typed)
	case protocol.CredentialRequest:
		binding, err := controller.store.Binding(ctx, typed.Binding)
		if err != nil || binding.Agent != session.agent {
			return nil
		}
		session.mu.Lock()
		matched := session.matched[binding.ID]
		session.mu.Unlock()
		if !matched {
			return nil
		}
		return session.issue(ctx, binding)
	default:
		// Controller-to-agent message types are protocol violations here.
		return errors.New("unexpected message type")
	}
}

// push sends the policy set for the latest inventory and a credential for
// every matched binding the agent does not yet hold one for.
func (session *agentSession) push(ctx context.Context) error {
	session.pushMu.Lock()
	defer session.pushMu.Unlock()
	controller := session.controller
	readCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	containers, _, err := controller.store.Inventory(readCtx, session.agent)
	if err != nil {
		return nil
	}
	bindings, err := controller.store.Bindings(readCtx, session.agent)
	if err != nil {
		return nil
	}
	matched := MatchBindings(containers, bindings)
	set := protocol.PolicySet{OpenBao: controller.agentOB, Bindings: []protocol.Binding{}}
	var issue []store.Binding
	session.mu.Lock()
	session.matched = map[string]bool{}
	for _, binding := range matched {
		set.Bindings = append(set.Bindings, protocol.Binding{Binding: binding.ID, Key: binding.Key, Policy: binding.Effective, Assignment: binding.Assignment()})
		session.matched[binding.ID] = true
		if session.credentialed[binding.ID] != binding.Assignment() {
			issue = append(issue, binding)
		}
	}
	for id := range session.credentialed {
		if !session.matched[id] {
			delete(session.credentialed, id)
		}
	}
	session.mu.Unlock()
	if err := session.conn.Send(set); err != nil {
		return err
	}
	for _, binding := range issue {
		if err := session.issue(ctx, binding); err != nil {
			return err
		}
	}
	return nil
}

// issue sends a fresh AppRole credential for binding. OpenBao failures are
// recorded and do not end the session; the agent asks again later.
func (session *agentSession) issue(ctx context.Context, binding store.Binding) error {
	controller := session.controller
	controller.mutationMu.Lock()
	defer controller.mutationMu.Unlock()
	if controller.policySyncPending {
		if err := controller.syncPolicies(ctx); err != nil {
			return nil
		}
	}
	current, lookup := controller.store.Binding(ctx, binding.ID)
	if lookup != nil || current.Agent != session.agent || current.Assignment() != binding.Assignment() {
		return nil
	}
	binding = current
	if err := controller.applyBinding(ctx, binding); err != nil {
		return nil
	}
	started := controller.now()
	issueCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	roleID, err := controller.openbao.RoleID(issueCtx, binding.Role)
	var wrapped string
	if err == nil {
		wrapped, err = controller.openbao.WrappedSecretID(issueCtx, binding.Role, credentialWrapTTL)
	}
	code := events.ErrorNone
	if err != nil {
		code = openBaoError(err)
	}
	controller.recordBinding(binding, events.Event{Operation: events.OperationCredentialIssued, Outcome: outcomeFor(code), ErrorCode: code,
		Agent: session.agent, Binding: binding.ID, Latency: controller.now().Sub(started)})
	if err != nil {
		return nil
	}
	if err := session.conn.Send(protocol.Credential{
		Binding: binding.ID, Assignment: binding.Assignment(), AppRoleMount: controller.openbao.Mounts().AppRole, RoleID: roleID, WrappedSecretID: wrapped,
	}); err != nil {
		return err
	}
	session.mu.Lock()
	session.credentialed[binding.ID] = binding.Assignment()
	session.mu.Unlock()
	return nil
}

func (hub *hub) session(agent string) *agentSession {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	return hub.sessions[agent]
}

// Connected reports whether agent has a live session.
func (controller *Controller) Connected(agent string) bool {
	return controller.hub.session(agent) != nil
}

// pushAgent recomputes and sends the policy set to a connected agent.
func (hub *hub) pushAgent(ctx context.Context, agent string) {
	if session := hub.session(agent); session != nil {
		if err := session.push(ctx); err != nil {
			session.close()
		}
	}
}

func (hub *hub) send(agent string, message protocol.Message) error {
	session := hub.session(agent)
	if session == nil {
		return ErrAgentDisconnected
	}
	if err := session.conn.Send(message); err != nil {
		session.close()
		return ErrAgentDisconnected
	}
	return nil
}

func (hub *hub) closeAll() {
	hub.mu.Lock()
	sessions := make([]*agentSession, 0, len(hub.sessions))
	for _, session := range hub.sessions {
		sessions = append(sessions, session)
	}
	hub.mu.Unlock()
	for _, session := range sessions {
		session.close()
	}
}

// MatchBindings returns the bindings that match at least one container. A
// container matches the binding on its most stable key: when several
// bindings match one container, the binding on the earliest key in the
// container's precedence order wins.
func MatchBindings(containers []protocol.Container, bindings []store.Binding) []store.Binding {
	byKey := make(map[protocol.Key]store.Binding, len(bindings))
	for _, binding := range bindings {
		byKey[binding.Key] = binding
	}
	seen := map[string]bool{}
	var matched []store.Binding
	for _, container := range containers {
		for _, key := range container.Keys {
			binding, ok := byKey[key]
			if !ok {
				continue
			}
			if !seen[binding.ID] {
				seen[binding.ID] = true
				matched = append(matched, binding)
			}
			break
		}
	}
	return matched
}

// ContainerBinding returns the binding that governs one container, if any.
func ContainerBinding(container protocol.Container, bindings []store.Binding) (store.Binding, bool) {
	byKey := make(map[protocol.Key]store.Binding, len(bindings))
	for _, binding := range bindings {
		byKey[binding.Key] = binding
	}
	for _, key := range container.Keys {
		if binding, ok := byKey[key]; ok {
			return binding, true
		}
	}
	return store.Binding{}, false
}

// recordAccessor keeps the accessor an agent reports for its own binding and
// acknowledges it once it is durable. A report for a binding the agent held
// and that was since retired is revoked instead, since the binding's
// deletion could not have seen it. A report for a binding that never
// belonged to the agent is acknowledged and dropped. Storage and OpenBao
// failures are not acknowledged, so the agent reports again.
func (session *agentSession) recordAccessor(ctx context.Context, report protocol.TokenAccessor) error {
	controller := session.controller
	binding, err := controller.store.Binding(ctx, report.Binding)
	switch {
	case err == nil && binding.Agent != session.agent:
		return session.conn.Send(report.Acknowledge())
	case err == nil:
		if report.Assignment != binding.Assignment() || !binding.Applied {
			if err := controller.openbao.RevokeAccessor(ctx, report.Accessor); err != nil {
				return nil
			}
			return session.conn.Send(report.Acknowledge())
		}
		err = controller.store.SaveAssignmentAccessor(ctx, binding, report.Accessor, controller.now())
		if err == nil {
			return session.conn.Send(report.Acknowledge())
		}
		if errors.Is(err, store.ErrConflict) {
			if err := controller.openbao.RevokeAccessor(ctx, report.Accessor); err != nil {
				return nil
			}
			return session.conn.Send(report.Acknowledge())
		}
		// The binding may have been retired since it was read.
		if _, lookup := controller.store.Binding(ctx, report.Binding); !errors.Is(lookup, store.ErrNotFound) {
			controller.logf("token accessor not recorded")
			return nil
		}
	case !errors.Is(err, store.ErrNotFound):
		controller.logf("token accessor not recorded")
		return nil
	}
	owner, err := controller.store.RetiredBindingAgent(ctx, report.Binding)
	switch {
	case errors.Is(err, store.ErrNotFound), err == nil && owner != session.agent:
		return session.conn.Send(report.Acknowledge())
	case err != nil:
		controller.logf("token accessor not recorded")
		return nil
	}
	revokeCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := controller.openbao.RevokeAccessor(revokeCtx, report.Accessor); err != nil {
		controller.logf("token of a retired binding not revoked")
		return nil
	}
	return session.conn.Send(report.Acknowledge())
}
