// ---
// relationships:
//   implements: linux-per-user-agent-proxy
// ---

// Package runtime owns immutable active configuration state and apply planning.
package runtime

import (
	"slices"

	"github.com/wyrd-company/wyrwood/internal/config"
)

// Snapshot is one immutable, validated runtime configuration.
//
// Snapshot values may be shared by concurrent readers. All methods return
// immutable values or defensive copies.
type Snapshot struct {
	configuration config.Config
	consumers     map[string]Consumer
}

// Consumer is the immutable runtime view of one socket-path security principal.
type Consumer struct {
	name         string
	socket       string
	accessGroup  uint32
	hasGroup     bool
	fingerprints []string
	policy       Policy
}

// Policy is an immutable exact fingerprint allowlist.
type Policy struct {
	fingerprints map[string]struct{}
}

func newSnapshot(configuration config.Config) (*Snapshot, error) {
	owned := cloneConfig(configuration)
	if err := config.Validate(owned); err != nil {
		return nil, err
	}

	snapshot := &Snapshot{
		configuration: owned,
		consumers:     make(map[string]Consumer, len(owned.Consumers)),
	}
	for _, configured := range owned.Consumers {
		fingerprints := slices.Clone(configured.Fingerprints)
		policy := Policy{fingerprints: make(map[string]struct{}, len(fingerprints))}
		for _, fingerprint := range fingerprints {
			policy.fingerprints[fingerprint] = struct{}{}
		}
		consumer := Consumer{
			name:         configured.Name,
			socket:       configured.Socket,
			fingerprints: fingerprints,
			policy:       policy,
		}
		if configured.AccessGroup != nil {
			consumer.accessGroup = *configured.AccessGroup
			consumer.hasGroup = true
		}
		snapshot.consumers[consumer.socket] = consumer
	}
	return snapshot, nil
}

// Config returns a defensive copy of the complete validated configuration.
func (snapshot *Snapshot) Config() config.Config {
	return cloneConfig(snapshot.configuration)
}

// Upstream returns the configured upstream SSH-agent socket path.
func (snapshot *Snapshot) Upstream() string {
	return snapshot.configuration.Upstream
}

// Timeouts returns the configured upstream operation deadlines.
func (snapshot *Snapshot) Timeouts() config.Timeouts {
	return snapshot.configuration.Timeouts
}

// Consumer returns the consumer identified by socket path.
func (snapshot *Snapshot) Consumer(socket string) (Consumer, bool) {
	consumer, exists := snapshot.consumers[socket]
	return consumer, exists
}

// Policy returns the exact allowlist for the consumer identified by socket path.
func (snapshot *Snapshot) Policy(socket string) (Policy, bool) {
	consumer, exists := snapshot.Consumer(socket)
	if !exists {
		return Policy{}, false
	}
	return consumer.Policy(), true
}

// Name returns the consumer's display name.
func (consumer Consumer) Name() string {
	return consumer.name
}

// Socket returns the consumer's immutable security-principal identity.
func (consumer Consumer) Socket() string {
	return consumer.socket
}

// AccessGroup returns the optional Linux numeric access group.
func (consumer Consumer) AccessGroup() (uint32, bool) {
	return consumer.accessGroup, consumer.hasGroup
}

// Fingerprints returns a defensive copy of the configured exact allowlist.
func (consumer Consumer) Fingerprints() []string {
	return slices.Clone(consumer.fingerprints)
}

// Policy returns the consumer's immutable exact allowlist.
func (consumer Consumer) Policy() Policy {
	return consumer.policy
}

// Allows reports whether the exact fingerprint is present in the allowlist.
func (policy Policy) Allows(fingerprint string) bool {
	_, allowed := policy.fingerprints[fingerprint]
	return allowed
}

// Fingerprints returns the allowlist in deterministic lexical order.
func (policy Policy) Fingerprints() []string {
	fingerprints := make([]string, 0, len(policy.fingerprints))
	for fingerprint := range policy.fingerprints {
		fingerprints = append(fingerprints, fingerprint)
	}
	slices.Sort(fingerprints)
	return fingerprints
}

func cloneConfig(configuration config.Config) config.Config {
	clone := configuration
	clone.Consumers = make([]config.Consumer, len(configuration.Consumers))
	for index, consumer := range configuration.Consumers {
		clone.Consumers[index] = consumer
		clone.Consumers[index].Fingerprints = slices.Clone(consumer.Fingerprints)
		if consumer.AccessGroup != nil {
			group := *consumer.AccessGroup
			clone.Consumers[index].AccessGroup = &group
		}
	}
	return clone
}
