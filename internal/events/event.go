// ---
// relationships:
//   implements: operational-events
// ---

// Package events owns Wyrwood's closed operational-event vocabulary,
// persistence, and health projections.
package events

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	maximumConsumerIDBytes  = 128
	maximumFingerprintBytes = 128
)

var (
	consumerIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	fingerprintPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]$`)
)

// ConsumerID is an opaque, non-path identifier for one configured consumer.
type ConsumerID string

// Fingerprint is the canonical OpenSSH SHA-256 identity of a public key.
type Fingerprint string

// Operation is the closed vocabulary of observable daemon operations.
type Operation string

const (
	OperationConsumerConnect Operation = "consumer-connect"
	OperationListIdentities  Operation = "list-identities"
	OperationSign            Operation = "sign"
	OperationSessionBind     Operation = "session-bind"
	OperationUpstreamConnect Operation = "upstream-connect"
	OperationReplay          Operation = "replay"
	OperationReconcile       Operation = "reconcile"
)

// Outcome is the closed result vocabulary for an operation.
type Outcome string

const (
	OutcomeSucceeded Outcome = "succeeded"
	OutcomeDenied    Outcome = "denied"
	OutcomeFailed    Outcome = "failed"
)

// ErrorCode categorizes failures without retaining raw error data.
type ErrorCode string

const (
	ErrorNone                ErrorCode = "none"
	ErrorPolicyDenied        ErrorCode = "policy-denied"
	ErrorUpstreamUnavailable ErrorCode = "upstream-unavailable"
	ErrorUpstreamTimeout     ErrorCode = "upstream-timeout"
	ErrorUpstreamProtocol    ErrorCode = "upstream-protocol"
	ErrorConsumerProtocol    ErrorCode = "consumer-protocol"
	ErrorResourceLimit       ErrorCode = "resource-limit"
	ErrorInternal            ErrorCode = "internal"
)

// Event is the complete and closed durable operational-event type.
// It deliberately has no metadata, attributes, map, byte-slice, or raw-error
// field through which additional information could escape the closed schema.
type Event struct {
	Timestamp   time.Time
	ConsumerID  ConsumerID
	Operation   Operation
	Fingerprint *Fingerprint
	Outcome     Outcome
	Latency     time.Duration
	ErrorCode   ErrorCode
}

// Validate verifies the complete event vocabulary and cross-field invariants.
func (event Event) Validate() error {
	if _, err := normalizeTimestamp(event.Timestamp); err != nil {
		return err
	}
	if len(event.ConsumerID) > maximumConsumerIDBytes || !consumerIDPattern.MatchString(string(event.ConsumerID)) {
		return fmt.Errorf("consumer identifier is not an opaque identifier")
	}
	if !validOperation(event.Operation) {
		return fmt.Errorf("operation %q is not supported", event.Operation)
	}
	if event.Fingerprint != nil {
		value := string(*event.Fingerprint)
		if len(value) > maximumFingerprintBytes || !fingerprintPattern.MatchString(value) {
			return errors.New("fingerprint is not a canonical OpenSSH SHA-256 fingerprint")
		}
	}
	if !validOutcome(event.Outcome) {
		return fmt.Errorf("outcome %q is not supported", event.Outcome)
	}
	if event.Latency < 0 {
		return errors.New("latency must not be negative")
	}
	if !validErrorCode(event.ErrorCode) {
		return fmt.Errorf("error code %q is not supported", event.ErrorCode)
	}
	if event.Outcome == OutcomeSucceeded && event.ErrorCode != ErrorNone {
		return errors.New("successful event must use the none error code")
	}
	if event.Outcome != OutcomeSucceeded && event.ErrorCode == ErrorNone {
		return errors.New("non-successful event must use a categorical error code")
	}
	return nil
}

func normalizeEvent(event Event) (Event, error) {
	if err := event.Validate(); err != nil {
		return Event{}, err
	}
	normalized := cloneEvent(event)
	var err error
	normalized.Timestamp, err = normalizeTimestamp(event.Timestamp)
	if err != nil {
		return Event{}, err
	}
	return normalized, nil
}

func normalizeTimestamp(timestamp time.Time) (time.Time, error) {
	if timestamp.IsZero() {
		return time.Time{}, errors.New("timestamp is required")
	}
	representation := timestamp.UTC().Format(time.RFC3339Nano)
	normalized, err := time.Parse(time.RFC3339Nano, representation)
	if err != nil || !normalized.Equal(timestamp) || normalized.Format(time.RFC3339Nano) != representation {
		return time.Time{}, errors.New("timestamp must round-trip through RFC 3339 with a four-digit year")
	}
	return normalized, nil
}

func validOperation(operation Operation) bool {
	switch operation {
	case OperationConsumerConnect, OperationListIdentities, OperationSign,
		OperationSessionBind, OperationUpstreamConnect, OperationReplay,
		OperationReconcile:
		return true
	default:
		return false
	}
}

func validOutcome(outcome Outcome) bool {
	switch outcome {
	case OutcomeSucceeded, OutcomeDenied, OutcomeFailed:
		return true
	default:
		return false
	}
}

func validErrorCode(code ErrorCode) bool {
	switch code {
	case ErrorNone, ErrorPolicyDenied, ErrorUpstreamUnavailable,
		ErrorUpstreamTimeout, ErrorUpstreamProtocol, ErrorConsumerProtocol,
		ErrorResourceLimit, ErrorInternal:
		return true
	default:
		return false
	}
}

func cloneEvent(event Event) Event {
	clone := event
	if event.Fingerprint != nil {
		fingerprint := *event.Fingerprint
		clone.Fingerprint = &fingerprint
	}
	return clone
}
