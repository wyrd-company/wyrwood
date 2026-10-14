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
type credentials struct {
	timeout time.Duration
	now     func() time.Time
	request func(binding string)
	record  func(events.Event)
	keyOf   func(binding string) string

	mu       sync.Mutex
	endpoint protocol.OpenBao
	client   *api.Client
	held     map[string]*heldToken
}

type heldToken struct {
	token  openbao.Token
	cancel context.CancelFunc
}

func newCredentials(timeout time.Duration, request func(string), record func(events.Event), keyOf func(string) string) *credentials {
	return &credentials{
		timeout: timeout, now: time.Now, request: request, record: record, keyOf: keyOf,
		held: map[string]*heldToken{},
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

// deliver unwraps a credential, logs in, and replaces the binding's token.
// The previous token is revoked once the new one is held.
func (manager *credentials) deliver(ctx context.Context, credential protocol.Credential) {
	client := manager.openBaoClient()
	started := manager.now()
	if client == nil {
		manager.recordOutcome(events.OperationLogin, credential.Binding, started, errNoEndpoint)
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
		return
	}
	renewCtx, renewCancel := context.WithCancel(context.Background())
	manager.mu.Lock()
	previous := manager.held[credential.Binding]
	manager.held[credential.Binding] = &heldToken{token: token, cancel: renewCancel}
	manager.mu.Unlock()
	if previous != nil {
		previous.cancel()
		go manager.revoke(credential.Binding, previous.token)
	}
	go manager.maintain(renewCtx, credential.Binding)
}

var errNoEndpoint = &openbao.Error{Category: openbao.CategoryUnavailable}

// maintain renews at half the remaining time-to-live and asks the
// controller for a fresh credential when renewal fails or runs short.
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
		previousTTL := held.token.TTL
		operation, cancel := context.WithTimeout(ctx, manager.timeout)
		renewed, err := openbao.RenewSelf(operation, client, held.token)
		cancel()
		if ctx.Err() != nil {
			return
		}
		manager.recordOutcome(events.OperationRenew, binding, started, err)
		if err != nil {
			manager.request(binding)
			if !held.token.Valid(manager.now()) {
				manager.mu.Lock()
				if manager.held[binding] == held {
					delete(manager.held, binding)
				}
				manager.mu.Unlock()
				return
			}
			continue
		}
		manager.mu.Lock()
		if manager.held[binding] == held {
			held.token = renewed
		}
		manager.mu.Unlock()
		if renewed.TTL < previousTTL/2 || !renewed.Renewable {
			// The token approaches its maximum lifetime; replace it.
			manager.request(binding)
		}
	}
}

// retire stops renewal and revokes the binding's token.
func (manager *credentials) retire(binding string) {
	manager.mu.Lock()
	held, ok := manager.held[binding]
	delete(manager.held, binding)
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

// stopAll stops renewal and forgets every held token, for shutdown. Tokens
// are not revoked so a restart within their lifetime needs no controller.
func (manager *credentials) stopAll() {
	manager.mu.Lock()
	held := manager.held
	manager.held = map[string]*heldToken{}
	manager.mu.Unlock()
	for _, token := range held {
		token.cancel()
	}
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
