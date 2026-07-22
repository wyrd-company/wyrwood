// ---
// relationships:
//   implements: linux-per-user-agent-proxy
//   uses: operational-events
// ---

// Package agentpolicy filters one downstream SSH-agent connection through the
// active policy for its consumer socket.
package agentpolicy

import (
	"errors"
	"time"

	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/runtime"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const sessionBindExtension = "session-bind@openssh.com"

var (
	// ErrPolicyDenied means the current consumer policy does not authorize an operation.
	ErrPolicyDenied = errors.New("agent operation denied by current policy")
	// ErrMutationDenied means the downstream endpoint does not expose agent mutation operations.
	ErrMutationDenied = errors.New("agent mutation operation denied")
)

// PolicySource resolves the currently active policy for a consumer socket.
type PolicySource interface {
	Policy(socket string) (runtime.Policy, bool)
}

// Agent exposes the permitted SSH-agent operations for one consumer and one
// paired upstream connection.
type Agent struct {
	policies PolicySource
	socket   string
	upstream agent.ExtendedAgent
	observer observer
}

type observer struct {
	consumerID events.ConsumerID
	record     func(events.Event)
}

// New constructs a policy agent. The upstream must belong only to this
// downstream connection because session bindings are connection-scoped.
func New(policies PolicySource, socket string, upstream agent.ExtendedAgent) (*Agent, error) {
	return newAgent(policies, socket, upstream, observer{})
}

// NewObserved constructs a policy agent whose closed operational records never
// contain request payloads, signatures, public-key bytes, comments, or paths.
func NewObserved(
	policies PolicySource,
	socket string,
	upstream agent.ExtendedAgent,
	consumerID events.ConsumerID,
	record func(events.Event),
) (*Agent, error) {
	if err := (events.Event{
		Timestamp: time.Now(), ConsumerID: consumerID, Operation: events.OperationConsumerConnect,
		Outcome: events.OutcomeSucceeded, ErrorCode: events.ErrorNone,
	}).Validate(); err != nil {
		return nil, errors.New("operational event identity is invalid")
	}
	if record == nil {
		return nil, errors.New("operational event recorder is required")
	}
	return newAgent(policies, socket, upstream, observer{consumerID: consumerID, record: record})
}

func newAgent(policies PolicySource, socket string, upstream agent.ExtendedAgent, observer observer) (*Agent, error) {
	if policies == nil {
		return nil, errors.New("policy source is required")
	}
	if socket == "" {
		return nil, errors.New("consumer socket is required")
	}
	if upstream == nil {
		return nil, errors.New("upstream agent is required")
	}
	return &Agent{policies: policies, socket: socket, upstream: upstream, observer: observer}, nil
}

// List returns only identities authorized by the policy active after the
// upstream enumeration completes. Agent comments are copied only as display data.
func (policyAgent *Agent) List() ([]*agent.Key, error) {
	started := time.Now()
	keys, err := policyAgent.upstream.List()
	if err != nil {
		policyAgent.record(events.OperationListIdentities, nil, events.OutcomeFailed, operationalErrorCode(err, events.ErrorUpstreamProtocol), started)
		return nil, err
	}
	policy, exists := policyAgent.policies.Policy(policyAgent.socket)
	if !exists {
		policyAgent.record(events.OperationListIdentities, nil, events.OutcomeDenied, events.ErrorPolicyDenied, started)
		return nil, ErrPolicyDenied
	}

	allowed := make([]*agent.Key, 0, len(keys))
	for _, key := range keys {
		if key != nil && policy.Allows(ssh.FingerprintSHA256(key)) {
			allowed = append(allowed, key)
		}
	}
	policyAgent.record(events.OperationListIdentities, nil, events.OutcomeSucceeded, events.ErrorNone, started)
	return allowed, nil
}

// Sign re-evaluates the active policy immediately before forwarding the request.
func (policyAgent *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return policyAgent.SignWithFlags(key, data, 0)
}

// SignWithFlags preserves inspectable SSH-agent signature flag semantics.
func (policyAgent *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	started := time.Now()
	if key == nil || !policyAgent.allows(key) {
		policyAgent.record(events.OperationSign, fingerprint(key), events.OutcomeDenied, events.ErrorPolicyDenied, started)
		return nil, ErrPolicyDenied
	}
	signature, err := policyAgent.upstream.SignWithFlags(key, data, flags)
	if err != nil {
		policyAgent.record(events.OperationSign, fingerprint(key), events.OutcomeFailed, operationalErrorCode(err, events.ErrorUpstreamProtocol), started)
		return nil, err
	}
	policyAgent.record(events.OperationSign, fingerprint(key), events.OutcomeSucceeded, events.ErrorNone, started)
	return signature, nil
}

// Extension permits only a correctly framed OpenSSH session binding. The
// opaque contents are forwarded byte-for-byte so the upstream owns validation
// and connection-scoped destination-restriction state.
func (policyAgent *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	started := time.Now()
	if extensionType != sessionBindExtension {
		return nil, agent.ErrExtensionUnsupported
	}
	if _, exists := policyAgent.policies.Policy(policyAgent.socket); !exists {
		policyAgent.record(events.OperationSessionBind, nil, events.OutcomeDenied, events.ErrorPolicyDenied, started)
		return nil, ErrPolicyDenied
	}
	if !validSessionBind(contents) {
		policyAgent.record(events.OperationSessionBind, nil, events.OutcomeFailed, events.ErrorConsumerProtocol, started)
		return nil, errors.New("invalid session-bind framing")
	}
	response, err := policyAgent.upstream.Extension(extensionType, contents)
	if err != nil {
		policyAgent.record(events.OperationSessionBind, nil, events.OutcomeFailed, operationalErrorCode(err, events.ErrorUpstreamProtocol), started)
		return nil, err
	}
	policyAgent.record(events.OperationSessionBind, nil, events.OutcomeSucceeded, events.ErrorNone, started)
	return response, nil
}

func (policyAgent *Agent) record(operation events.Operation, key *events.Fingerprint, outcome events.Outcome, code events.ErrorCode, started time.Time) {
	if policyAgent.observer.record == nil {
		return
	}
	policyAgent.observer.record(events.Event{
		Timestamp: time.Now(), ConsumerID: policyAgent.observer.consumerID, Operation: operation,
		Fingerprint: key, Outcome: outcome, Latency: time.Since(started), ErrorCode: code,
	})
}

func fingerprint(key ssh.PublicKey) *events.Fingerprint {
	if key == nil {
		return nil
	}
	value := events.Fingerprint(ssh.FingerprintSHA256(key))
	return &value
}

func operationalErrorCode(err error, fallback events.ErrorCode) events.ErrorCode {
	var categorized interface {
		OperationalEventErrorCode() events.ErrorCode
	}
	if errors.As(err, &categorized) {
		code := categorized.OperationalEventErrorCode()
		switch code {
		case events.ErrorUpstreamUnavailable, events.ErrorUpstreamTimeout,
			events.ErrorUpstreamProtocol, events.ErrorResourceLimit:
			return code
		}
	}
	return fallback
}

func (policyAgent *Agent) allows(key ssh.PublicKey) bool {
	policy, exists := policyAgent.policies.Policy(policyAgent.socket)
	return exists && policy.Allows(ssh.FingerprintSHA256(key))
}

func validSessionBind(contents []byte) bool {
	var request struct {
		HostKey      []byte
		SessionID    []byte
		Signature    []byte
		IsForwarding bool
	}
	return ssh.Unmarshal(contents, &request) == nil
}

// Add is unavailable on consumer endpoints.
func (policyAgent *Agent) Add(agent.AddedKey) error { return ErrMutationDenied }

// Remove is unavailable on consumer endpoints.
func (policyAgent *Agent) Remove(ssh.PublicKey) error { return ErrMutationDenied }

// RemoveAll is unavailable on consumer endpoints.
func (policyAgent *Agent) RemoveAll() error { return ErrMutationDenied }

// Lock is unavailable on consumer endpoints.
func (policyAgent *Agent) Lock([]byte) error { return ErrMutationDenied }

// Unlock is unavailable on consumer endpoints.
func (policyAgent *Agent) Unlock([]byte) error { return ErrMutationDenied }

// Signers is unavailable because it would create long-lived signing handles
// whose authorization could outlive the policy snapshot that produced them.
func (policyAgent *Agent) Signers() ([]ssh.Signer, error) { return nil, ErrPolicyDenied }

var _ agent.ExtendedAgent = (*Agent)(nil)
