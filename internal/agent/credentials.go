// ---
// relationships:
//   implements: agent
//   mitigates: agent-compromise-exposes-host-container-secrets
// ---

package agent

import (
	"context"
	"sync"
	"time"

	"github.com/openbao/openbao/api/v2"

	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// credentials holds one OpenBao token per binding in memory only.
//
// Each credential delivery carries a generation taken when the agent
// receives it. Receiving a newer credential, changing the binding's policy,
// and retiring the binding each advance the generation, so a delivery that
// completes late cannot replace a newer token or outlive its binding.
type credentials struct {
	timeout    time.Duration
	retryDelay time.Duration
	now        func() time.Time
	request    func(binding string)
	record     func(events.Event)
	keyOf      func(binding string) string
	// report sends a binding's token accessor to the controller.
	report func(binding, accessor string)

	// reportMu orders reports so the last one sent for a binding carries
	// its current token's accessor.
	reportMu sync.Mutex

	mu         sync.Mutex
	endpoint   protocol.OpenBao
	client     *api.Client
	held       map[string]*heldToken
	next       uint64
	generation map[string]uint64
}

type heldToken struct {
	token openbao.Token
	// period is the time-to-live the token had at login, which each
	// renewal asks for again. A renewal that returns less was capped by
	// the token's maximum lifetime.
	period time.Duration
	cancel context.CancelFunc
}

func newCredentials(timeout time.Duration, request func(string), record func(events.Event), keyOf func(string) string) *credentials {
	return &credentials{
		timeout: timeout, retryDelay: time.Second, now: time.Now, request: request, record: record, keyOf: keyOf,
		report: func(string, string) {},
		held:   map[string]*heldToken{}, generation: map[string]uint64{},
	}
}

// setEndpoint updates the OpenBao endpoint from a policy set. A change of
// address, CA, or namespace rebuilds the client; held tokens stay valid.
func (manager *credentials) setEndpoint(endpoint protocol.OpenBao) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.client != nil && manager.endpoint == endpoint {
		return nil
	}
	client, err := openbao.NewClient(openbao.Endpoint{
		Address: endpoint.Address, CAPEM: []byte(endpoint.CAPEM), Namespace: endpoint.Namespace, Timeout: manager.timeout,
	})
	if err != nil {
		return err
	}
	manager.endpoint = endpoint
	manager.client = client
	return nil
}

func (manager *credentials) openBaoClient() *api.Client {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.client
}

// current returns the binding's token when one is held and unexpired.
func (manager *credentials) current(binding string) (openbao.Token, bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	held, ok := manager.held[binding]
	if !ok || !held.token.Valid(manager.now()) {
		return openbao.Token{}, false
	}
	return held.token, true
}

// begin starts a credential delivery for binding and returns its
// generation. Call it in message order, before deliver runs.
func (manager *credentials) begin(binding string) uint64 {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.advanceLocked(binding)
}

// invalidate makes every delivery already begun for binding stale.
func (manager *credentials) invalidate(binding string) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.advanceLocked(binding)
}

func (manager *credentials) advanceLocked(binding string) uint64 {
	manager.next++
	manager.generation[binding] = manager.next
	return manager.next
}

// deliver unwraps a credential, logs in, and replaces the binding's token.
// The previous token is revoked once the new one is held. A token from a
// stale delivery is revoked instead of held. A failed delivery asks the
// controller for another credential until a newer delivery begins.
func (manager *credentials) deliver(ctx context.Context, credential protocol.Credential, generation uint64) {
	client := manager.openBaoClient()
	started := manager.now()
	if client == nil {
		manager.recordOutcome(events.OperationLogin, credential.Binding, started, errNoEndpoint)
		go manager.retry(ctx, credential.Binding, generation)
		return
	}
	operation, cancel := context.WithTimeout(ctx, manager.timeout)
	defer cancel()
	secretID, err := openbao.UnwrapSecretID(operation, client, credential.WrappedSecretID)
	var token openbao.Token
	if err == nil {
		token, err = openbao.AppRoleLogin(operation, client, credential.AppRoleMount, credential.RoleID, secretID)
	}
	manager.recordOutcome(events.OperationLogin, credential.Binding, started, err)
	if err != nil {
		go manager.retry(ctx, credential.Binding, generation)
		return
	}
	renewCtx, renewCancel := context.WithCancel(context.Background())
	manager.mu.Lock()
	if manager.generation[credential.Binding] != generation {
		manager.mu.Unlock()
		renewCancel()
		manager.revoke(credential.Binding, token)
		return
	}
	previous := manager.held[credential.Binding]
	manager.held[credential.Binding] = &heldToken{token: token, period: token.TTL, cancel: renewCancel}
	manager.mu.Unlock()
	if previous != nil {
		previous.cancel()
		go manager.revoke(credential.Binding, previous.token)
	}
	manager.reportAccessor(credential.Binding)
	go manager.maintain(renewCtx, credential.Binding)
}

// reportAccessor sends the accessor of the binding's current token.
func (manager *credentials) reportAccessor(binding string) {
	manager.reportMu.Lock()
	defer manager.reportMu.Unlock()
	manager.mu.Lock()
	var accessor string
	if held, ok := manager.held[binding]; ok {
		accessor = held.token.Accessor
	}
	manager.mu.Unlock()
	if accessor != "" {
		manager.report(binding, accessor)
	}
}

var errNoEndpoint = &openbao.Error{Category: openbao.CategoryUnavailable}

// retry asks the controller for a fresh credential with exponential backoff
// until a newer delivery begins or the binding retires. A token still held
// from an earlier delivery does not stop it: that token is the one being
// replaced. The controller may fail to issue, so asking once is not enough.
func (manager *credentials) retry(ctx context.Context, binding string, generation uint64) {
	delay := manager.retryDelay
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		manager.mu.Lock()
		current := manager.generation[binding] == generation
		manager.mu.Unlock()
		if !current {
			return
		}
		manager.request(binding)
		if delay < time.Minute {
			delay *= 2
		}
	}
}

// maintain renews at half the remaining time-to-live and asks the
// controller for a fresh credential when renewal fails or the token's
// maximum lifetime caps it.
func (manager *credentials) maintain(ctx context.Context, binding string) {
	for {
		manager.mu.Lock()
		held, ok := manager.held[binding]
		manager.mu.Unlock()
		if !ok || held.token.TTL == 0 {
			return
		}
		wait := held.token.Expires().Sub(manager.now()) / 2
		if wait < time.Second {
			wait = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		client := manager.openBaoClient()
		started := manager.now()
		increment := held.token
		increment.TTL = held.period
		operation, cancel := context.WithTimeout(ctx, manager.timeout)
		renewed, err := openbao.RenewSelf(operation, client, increment)
		cancel()
		if ctx.Err() != nil {
			return
		}
		manager.recordOutcome(events.OperationRenew, binding, started, err)
		if err != nil {
			manager.request(binding)
			if !held.token.Valid(manager.now()) {
				manager.mu.Lock()
				expired := manager.held[binding] == held
				if expired {
					delete(manager.held, binding)
				}
				generation := manager.generation[binding]
				manager.mu.Unlock()
				if expired {
					go manager.retry(ctx, binding, generation)
				}
				return
			}
			continue
		}
		manager.mu.Lock()
		if manager.held[binding] == held {
			held.token = renewed
		}
		manager.mu.Unlock()
		if renewed.TTL < held.period || !renewed.Renewable {
			// The token's maximum lifetime capped the renewal; replace it
			// while it is still valid.
			manager.request(binding)
		}
	}
}

// retire stops renewal and revokes the binding's token. Deliveries already
// begun for the binding become stale.
func (manager *credentials) retire(binding string) {
	manager.mu.Lock()
	held, ok := manager.held[binding]
	delete(manager.held, binding)
	delete(manager.generation, binding)
	manager.mu.Unlock()
	if !ok {
		return
	}
	held.cancel()
	manager.revoke(binding, held.token)
}

func (manager *credentials) revoke(binding string, token openbao.Token) {
	client := manager.openBaoClient()
	if client == nil {
		return
	}
	started := manager.now()
	ctx, cancel := context.WithTimeout(context.Background(), manager.timeout)
	defer cancel()
	manager.recordOutcome(events.OperationRevoke, binding, started, openbao.RevokeSelf(ctx, client, token))
}

// holding returns the bindings with a held token.
func (manager *credentials) holding() map[string]bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	result := make(map[string]bool, len(manager.held))
	for binding, held := range manager.held {
		result[binding] = held.token.Valid(manager.now())
	}
	return result
}

// stopAll stops renewal and revokes every held token, for shutdown. Tokens
// live only in memory, so a restarted agent could never use them again;
// revoking them leaves no live credential behind.
func (manager *credentials) stopAll() {
	manager.mu.Lock()
	held := manager.held
	manager.held = map[string]*heldToken{}
	manager.generation = map[string]uint64{}
	manager.mu.Unlock()
	var wait sync.WaitGroup
	for binding, token := range held {
		token.cancel()
		wait.Add(1)
		go func(binding string, token openbao.Token) {
			defer wait.Done()
			manager.revoke(binding, token)
		}(binding, token.token)
	}
	wait.Wait()
}

func (manager *credentials) recordOutcome(operation events.Operation, binding string, started time.Time, err error) {
	code := events.ErrorNone
	if err != nil {
		code = openBaoCode(err)
	}
	manager.record(events.Event{
		Operation: operation, Outcome: outcomeOf(code), ErrorCode: code, Binding: binding,
		ContainerKey: manager.keyOf(binding), Latency: manager.now().Sub(started),
	})
}

func openBaoCode(err error) events.ErrorCode {
	switch openbao.CategoryOf(err) {
	case openbao.CategoryDenied:
		return events.ErrorOpenBaoDenied
	case openbao.CategoryTimeout:
		return events.ErrorOpenBaoTimeout
	case openbao.CategoryInvalid, openbao.CategoryNotFound:
		return events.ErrorOpenBaoDenied
	default:
		return events.ErrorOpenBaoUnavailable
	}
}

func outcomeOf(code events.ErrorCode) events.Outcome {
	switch code {
	case events.ErrorNone:
		return events.OutcomeOK
	case events.ErrorOpenBaoDenied, events.ErrorPolicyDenied, events.ErrorRecreateNotAllowed, events.ErrorNotBound:
		return events.OutcomeDenied
	case events.ErrorOpenBaoTimeout:
		return events.OutcomeTimeout
	default:
		return events.OutcomeFailed
	}
}
