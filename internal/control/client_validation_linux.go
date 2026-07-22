//go:build linux

// ---
// relationships:
//   implements: control-interface
// ---

package control

import (
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf8"
)

func validateResponse(request Request, response Response) error {
	if response.Version != Version {
		return errors.New("daemon control protocol version mismatch")
	}
	results := responseResultCount(response)
	if !response.OK {
		if !validErrorCode(response.Error) || response.Error == ErrorNone || results != 0 {
			return errors.New("invalid daemon error response")
		}
		return nil
	}
	if response.Error != ErrorNone || results != 1 {
		return errors.New("invalid daemon success response")
	}
	valid := request.Operation == OperationApply && response.Apply != nil ||
		request.Operation == OperationKeys && response.Keys != nil ||
		request.Operation == OperationStatus && response.Status != nil ||
		request.Operation == OperationEvents && response.Events != nil
	if !valid {
		return errors.New("daemon returned the wrong operation result")
	}
	if response.Keys != nil && len(response.Keys.Keys) > MaximumProjectedKeys ||
		response.Status != nil && len(response.Status.Consumers) > MaximumProjectedConsumers ||
		response.Events != nil && (request.Limit == nil || len(response.Events.Events) > *request.Limit) {
		return errors.New("daemon response exceeds the operation bound")
	}
	return validateOperationResult(response)
}

func responseResultCount(response Response) int {
	results := 0
	for _, present := range []bool{response.Apply != nil, response.Keys != nil, response.Status != nil, response.Events != nil} {
		if present {
			results++
		}
	}
	return results
}

func validateOperationResult(response Response) error {
	if response.Apply != nil && (response.Apply.PendingCleanup < 0 || response.Apply.PendingPermissions < 0) {
		return errors.New("daemon returned an invalid apply result")
	}
	if response.Keys != nil {
		if response.Keys.Keys == nil {
			return errors.New("daemon returned an invalid key projection")
		}
		for _, key := range response.Keys.Keys {
			if !validFingerprint(key.Fingerprint) || !utf8.ValidString(key.Display) || len(key.Display) > MaximumDisplayBytes {
				return errors.New("daemon returned an invalid key projection")
			}
		}
	}
	if response.Status != nil {
		if err := validateStatus(*response.Status); err != nil {
			return err
		}
	}
	if response.Events != nil {
		if response.Events.Events == nil {
			return errors.New("daemon returned an invalid event projection")
		}
		for _, event := range response.Events.Events {
			if !validEvent(event) {
				return errors.New("daemon returned an invalid event projection")
			}
		}
	}
	return nil
}

func validateStatus(status StatusResult) error {
	if status.Consumers == nil {
		return errors.New("daemon returned an invalid status projection")
	}
	if !validHealth(status.Daemon) || !validHealth(status.Upstream) {
		return errors.New("daemon returned an invalid health category")
	}
	for _, consumer := range status.Consumers {
		if !utf8.ValidString(consumer.ID) || len(consumer.ID) > 128 ||
			consumer.Name == "" || !utf8.ValidString(consumer.Name) || utf8.RuneCountInString(consumer.Name) > MaximumConsumerNameCharacters ||
			!validHealth(consumer.Listener) || consumer.ActiveConnections < 0 {
			return errors.New("daemon returned an invalid consumer status")
		}
	}
	return nil
}

func validFingerprint(value string) bool {
	const prefix = "SHA256:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	encoded := strings.TrimPrefix(value, prefix)
	decoded, err := base64.RawStdEncoding.Strict().DecodeString(encoded)
	return err == nil && len(decoded) == 32 && base64.RawStdEncoding.EncodeToString(decoded) == encoded
}

func validEvent(event Event) bool {
	if event.Timestamp.Year() < 1 || event.Timestamp.Year() > 9999 ||
		!utf8.ValidString(event.ConsumerID) || len(event.ConsumerID) > 128 || event.LatencyNS < 0 {
		return false
	}
	if event.Fingerprint != nil && !validFingerprint(*event.Fingerprint) {
		return false
	}
	switch event.Operation {
	case "consumer-connect", "list-identities", "sign", "session-bind", "upstream-connect", "replay", "reconcile":
	default:
		return false
	}
	switch event.Outcome {
	case "succeeded", "denied", "failed":
	default:
		return false
	}
	switch event.ErrorCode {
	case "none", "policy-denied", "upstream-unavailable", "upstream-timeout", "upstream-protocol", "consumer-protocol", "resource-limit", "internal":
		return true
	default:
		return false
	}
}

func validHealth(health HealthCategory) bool {
	switch health {
	case HealthHealthy, HealthDegraded, HealthUnavailable:
		return true
	default:
		return false
	}
}

func validErrorCode(code ErrorCode) bool {
	switch code {
	case ErrorNone, ErrorBadRequest, ErrorUnsupportedVersion, ErrorApplyInvalid,
		ErrorApplyFailed, ErrorUpstreamUnavailable, ErrorResourceLimit, ErrorInternal:
		return true
	default:
		return false
	}
}
