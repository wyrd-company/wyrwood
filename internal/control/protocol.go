//go:build linux

// ---
// relationships:
//   implements: control-interface
// ---

// Package control owns Wyrwood's closed local daemon control protocol.
package control

import (
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
)

const (
	Version                       = 1
	MaximumRequestBytes           = 64 * 1024
	MaximumResponseBytes          = 1024 * 1024
	MaximumEventLimit             = 1000
	MaximumProjectedKeys          = 1024
	MaximumProjectedConsumers     = 512
	MaximumConfigurationPageSize  = 16
	MaximumDisplayBytes           = 256
	MaximumConcurrentPeers        = 64
	MaximumConsumerNameCharacters = config.MaximumConsumerNameCharacters
)

type Operation string

const (
	OperationApply          Operation = "apply"
	OperationKeys           Operation = "keys"
	OperationStatus         Operation = "status"
	OperationEvents         Operation = "events"
	OperationConfiguration  Operation = "configuration"
	OperationSetUpstream    Operation = "set-upstream"
	OperationSetTimeouts    Operation = "set-timeouts"
	OperationPutConsumer    Operation = "put-consumer"
	OperationRetireConsumer Operation = "retire-consumer"
)

type ErrorCode string

const (
	ErrorNone                             ErrorCode = "none"
	ErrorBadRequest                       ErrorCode = "bad-request"
	ErrorUnsupportedVersion               ErrorCode = "unsupported-version"
	ErrorApplyInvalid                     ErrorCode = "apply-invalid"
	ErrorApplyFailed                      ErrorCode = "apply-failed"
	ErrorConfigurationInvalid             ErrorCode = "configuration-invalid"
	ErrorConfigurationConflict            ErrorCode = "configuration-conflict"
	ErrorConfigurationNotFound            ErrorCode = "configuration-not-found"
	ErrorConfigurationFailed              ErrorCode = "configuration-failed"
	ErrorConfigurationDurabilityUncertain ErrorCode = "configuration-durability-uncertain"
	ErrorUpstreamUnavailable              ErrorCode = "upstream-unavailable"
	ErrorResourceLimit                    ErrorCode = "resource-limit"
	ErrorInternal                         ErrorCode = "internal"
)

// Request is the complete v1 request envelope. Operation-specific fields are
// validated as a closed union before dispatch.
type Request struct {
	Version          int                         `json:"version"`
	Operation        Operation                   `json:"operation"`
	Limit            *int                        `json:"limit,omitempty"`
	Offset           *int                        `json:"offset,omitempty"`
	ExpectedRevision *string                     `json:"expected_revision,omitempty"`
	Upstream         *string                     `json:"upstream,omitempty"`
	Timeouts         *ConfigurationTimeouts      `json:"timeouts,omitempty"`
	ConsumerID       *string                     `json:"consumer_id,omitempty"`
	Consumer         *ConfigurationConsumerInput `json:"consumer,omitempty"`
}

// Response is the complete v1 response envelope. Exactly one operation result
// is present on success and no operation result is present on failure.
type Response struct {
	Version             int                        `json:"version"`
	OK                  bool                       `json:"ok"`
	Error               ErrorCode                  `json:"error"`
	Apply               *ApplyResult               `json:"apply,omitempty"`
	Keys                *KeysResult                `json:"keys,omitempty"`
	Status              *StatusResult              `json:"status,omitempty"`
	Events              *EventsResult              `json:"events,omitempty"`
	Configuration       *ConfigurationResult       `json:"configuration,omitempty"`
	ConfigurationChange *ConfigurationChangeResult `json:"configuration_change,omitempty"`
}

type ApplyResult struct {
	Revision           string `json:"revision"`
	Committed          bool   `json:"committed"`
	Degraded           bool   `json:"degraded"`
	PendingCleanup     int    `json:"pending_cleanup"`
	PendingPermissions int    `json:"pending_permissions"`
}

type Key struct {
	Fingerprint string `json:"fingerprint"`
	Display     string `json:"display"`
}

type KeysResult struct {
	Keys []Key `json:"keys"`
}

type HealthCategory string

const (
	HealthHealthy     HealthCategory = "healthy"
	HealthDegraded    HealthCategory = "degraded"
	HealthUnavailable HealthCategory = "unavailable"
)

type ConsumerStatus struct {
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	Listener          HealthCategory `json:"listener"`
	ActiveConnections int            `json:"active_connections"`
}

type StatusResult struct {
	ActiveRevision string           `json:"active_revision"`
	Daemon         HealthCategory   `json:"daemon"`
	Upstream       HealthCategory   `json:"upstream"`
	Consumers      []ConsumerStatus `json:"consumers"`
	Truncated      bool             `json:"truncated"`
}

type Event struct {
	Timestamp   time.Time `json:"timestamp"`
	ConsumerID  string    `json:"consumer_id"`
	Operation   string    `json:"operation"`
	Fingerprint *string   `json:"fingerprint,omitempty"`
	Outcome     string    `json:"outcome"`
	LatencyNS   int64     `json:"latency_ns"`
	ErrorCode   string    `json:"error_code"`
}

type EventsResult struct {
	Events []Event `json:"events"`
}

// ConfigurationTimeouts is the exact persisted duration spelling accepted by
// Go's duration parser and projected canonically by the daemon.
type ConfigurationTimeouts struct {
	Connect string `json:"connect"`
	List    string `json:"list"`
	Replay  string `json:"replay"`
	Sign    string `json:"sign"`
}

type ConfigurationConsumerInput struct {
	Name         string   `json:"name"`
	Socket       string   `json:"socket"`
	AccessGroup  *uint32  `json:"access_group,omitempty"`
	Fingerprints []string `json:"fingerprints"`
}

type ConfigurationConsumer struct {
	ID string `json:"id"`
	ConfigurationConsumerInput
}

type ConfigurationResult struct {
	Revision       string                  `json:"revision"`
	Upstream       string                  `json:"upstream"`
	Timeouts       ConfigurationTimeouts   `json:"timeouts"`
	TotalConsumers int                     `json:"total_consumers"`
	Offset         int                     `json:"offset"`
	Consumers      []ConfigurationConsumer `json:"consumers"`
	Complete       bool                    `json:"complete"`
}

type ConfigurationChangeResult struct {
	Operation  Operation `json:"operation"`
	Revision   string    `json:"revision"`
	Changed    bool      `json:"changed"`
	ConsumerID *string   `json:"consumer_id,omitempty"`
}
