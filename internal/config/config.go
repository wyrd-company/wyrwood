// ---
// relationships: {}
// ---

// Package config owns Wyrwood's persisted configuration contract.
package config

import "time"

const (
	// MaximumDocumentBytes bounds configuration input before YAML decoding.
	MaximumDocumentBytes = 1024 * 1024
	// MaximumConsumerNameCharacters keeps configured display data bounded while
	// preserving accepted names exactly across management surfaces.
	MaximumConsumerNameCharacters = 256

	DefaultConnectTimeout = 5 * time.Second
	DefaultListTimeout    = 5 * time.Second
	DefaultReplayTimeout  = 5 * time.Second
	DefaultSignTimeout    = 2 * time.Minute

	minimumShortTimeout = 100 * time.Millisecond
	maximumShortTimeout = 30 * time.Second
	minimumSignTimeout  = time.Second
	maximumSignTimeout  = 10 * time.Minute
)

// Config is the complete durable Wyrwood configuration.
type Config struct {
	Upstream  string     `yaml:"upstream"`
	Consumers []Consumer `yaml:"consumers"`
	Timeouts  Timeouts   `yaml:"timeouts"`
}

// Consumer defines one filesystem security principal and its exact key policy.
type Consumer struct {
	Name         string   `yaml:"name"`
	Socket       string   `yaml:"socket"`
	AccessGroup  *uint32  `yaml:"access-group,omitempty"`
	Fingerprints []string `yaml:"fingerprints"`
}

// Timeouts bounds operations against the upstream SSH agent.
type Timeouts struct {
	Connect time.Duration `yaml:"connect"`
	List    time.Duration `yaml:"list"`
	Replay  time.Duration `yaml:"replay"`
	Sign    time.Duration `yaml:"sign"`
}

// DefaultTimeouts returns the deadlines persisted by initialization.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		Connect: DefaultConnectTimeout,
		List:    DefaultListTimeout,
		Replay:  DefaultReplayTimeout,
		Sign:    DefaultSignTimeout,
	}
}
