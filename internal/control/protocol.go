//go:build linux

// ---
// relationships:
//   implements: control-interface
// ---

// Package control owns Wyrwood's closed local daemon control protocol.
package control

import "time"

const (
	Version                = 1
	MaximumRequestBytes    = 64 * 1024
	MaximumResponseBytes   = 1024 * 1024
	MaximumEventLimit      = 1000
	MaximumProjectedKeys   = 1024
	MaximumProjectedPeers  = 1024
	MaximumDisplayBytes    = 256
	MaximumConcurrentPeers = 64
)

type Operation string

const (
	OperationApply  Operation = "apply"
	OperationKeys   Operation = "keys"
	OperationStatus Operation = "status"
	OperationEvents Operation = "events"
)

type ErrorCode string

const (
	ErrorNone                ErrorCode = "none"
	ErrorBadRequest          ErrorCode = "bad-request"
	ErrorUnsupportedVersion  ErrorCode = "unsupported-version"
	ErrorApplyInvalid        ErrorCode = "apply-invalid"
	ErrorApplyFailed         ErrorCode = "apply-failed"
	ErrorUpstreamUnavailable ErrorCode = "upstream-unavailable"
	ErrorResourceLimit       ErrorCode = "resource-limit"
	ErrorInternal            ErrorCode = "internal"
)

// Request is the complete v1 request envelope. Limit is valid only for events.
type Request struct {
	Version   int       `json:"version"`
	Operation Operation `json:"operation"`
	Limit     *int      `json:"limit,omitempty"`
}

// Response is the complete v1 response envelope. Exactly one operation result
// is present on success and no operation result is present on failure.
type Response struct {
	Version int           `json:"version"`
	OK      bool          `json:"ok"`
	Error   ErrorCode     `json:"error"`
	Apply   *ApplyResult  `json:"apply,omitempty"`
	Keys    *KeysResult   `json:"keys,omitempty"`
	Status  *StatusResult `json:"status,omitempty"`
	Events  *EventsResult `json:"events,omitempty"`
}

type ApplyResult struct {
	Committed          bool `json:"committed"`
	Degraded           bool `json:"degraded"`
	PendingCleanup     int  `json:"pending_cleanup"`
	PendingPermissions int  `json:"pending_permissions"`
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
	Daemon    HealthCategory   `json:"daemon"`
	Upstream  HealthCategory   `json:"upstream"`
	Consumers []ConsumerStatus `json:"consumers"`
	Truncated bool             `json:"truncated"`
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
