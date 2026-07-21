// ---
// relationships:
//   implements: linux-per-user-agent-proxy
// ---

// Package agentpolicy filters one downstream SSH-agent connection through the
// active policy for its consumer socket.
package agentpolicy

import (
	"errors"

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
}

// New constructs a policy agent. The upstream must belong only to this
// downstream connection because session bindings are connection-scoped.
func New(policies PolicySource, socket string, upstream agent.ExtendedAgent) (*Agent, error) {
	if policies == nil {
		return nil, errors.New("policy source is required")
	}
	if socket == "" {
		return nil, errors.New("consumer socket is required")
	}
	if upstream == nil {
		return nil, errors.New("upstream agent is required")
	}
	return &Agent{policies: policies, socket: socket, upstream: upstream}, nil
}

// List returns only identities authorized by the policy active after the
// upstream enumeration completes. Agent comments are copied only as display data.
func (policyAgent *Agent) List() ([]*agent.Key, error) {
	keys, err := policyAgent.upstream.List()
	if err != nil {
		return nil, err
	}
	policy, exists := policyAgent.policies.Policy(policyAgent.socket)
	if !exists {
		return nil, ErrPolicyDenied
	}

	allowed := make([]*agent.Key, 0, len(keys))
	for _, key := range keys {
		if key != nil && policy.Allows(ssh.FingerprintSHA256(key)) {
			allowed = append(allowed, key)
		}
	}
	return allowed, nil
}

// Sign re-evaluates the active policy immediately before forwarding the request.
func (policyAgent *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return policyAgent.SignWithFlags(key, data, 0)
}

// SignWithFlags preserves inspectable SSH-agent signature flag semantics.
func (policyAgent *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if key == nil || !policyAgent.allows(key) {
		return nil, ErrPolicyDenied
	}
	return policyAgent.upstream.SignWithFlags(key, data, flags)
}

// Extension permits only a correctly framed OpenSSH session binding. The
// opaque contents are forwarded byte-for-byte so the upstream owns validation
// and connection-scoped destination-restriction state.
func (policyAgent *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType != sessionBindExtension {
		return nil, agent.ErrExtensionUnsupported
	}
	if _, exists := policyAgent.policies.Policy(policyAgent.socket); !exists {
		return nil, ErrPolicyDenied
	}
	if !validSessionBind(contents) {
		return nil, errors.New("invalid session-bind framing")
	}
	return policyAgent.upstream.Extension(extensionType, contents)
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
