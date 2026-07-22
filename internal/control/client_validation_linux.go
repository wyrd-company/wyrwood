//go:build linux

// ---
// relationships:
//   implements: control-interface
// ---

package control

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	revisionPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	durationPattern = regexp.MustCompile(`^\+?(?:(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:ns|us|µs|μs|ms|s|m|h))+$`)
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
		request.Operation == OperationEvents && response.Events != nil ||
		request.Operation == OperationConfiguration && response.Configuration != nil ||
		isConfigurationMutation(request.Operation) && response.ConfigurationChange != nil
	if !valid {
		return errors.New("daemon returned the wrong operation result")
	}
	if response.Keys != nil && len(response.Keys.Keys) > MaximumProjectedKeys ||
		response.Status != nil && len(response.Status.Consumers) > MaximumProjectedConsumers ||
		response.Events != nil && (request.Limit == nil || len(response.Events.Events) > *request.Limit) ||
		response.Configuration != nil && len(response.Configuration.Consumers) > MaximumConfigurationPageSize {
		return errors.New("daemon response exceeds the operation bound")
	}
	if response.Configuration != nil && (request.Offset == nil || request.Limit == nil || response.Configuration.Offset != *request.Offset || len(response.Configuration.Consumers) > *request.Limit) {
		return errors.New("daemon returned a mismatched configuration page")
	}
	if response.ConfigurationChange != nil && response.ConfigurationChange.Operation != request.Operation {
		return errors.New("daemon returned the wrong configuration mutation result")
	}
	return validateOperationResult(response)
}

func responseResultCount(response Response) int {
	results := 0
	for _, present := range []bool{response.Apply != nil, response.Keys != nil, response.Status != nil, response.Events != nil,
		response.Configuration != nil, response.ConfigurationChange != nil} {
		if present {
			results++
		}
	}
	return results
}

func validateOperationResult(response Response) error {
	if response.Apply != nil && (!validRevision(response.Apply.Revision) || response.Apply.PendingCleanup < 0 || response.Apply.PendingPermissions < 0) {
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
	if response.Configuration != nil {
		if err := validateConfigurationResult(*response.Configuration); err != nil {
			return err
		}
	}
	if response.ConfigurationChange != nil {
		if err := validateConfigurationChange(*response.ConfigurationChange); err != nil {
			return err
		}
	}
	return nil
}

func validateStatus(status StatusResult) error {
	if status.Consumers == nil {
		return errors.New("daemon returned an invalid status projection")
	}
	if !validRevision(status.ActiveRevision) || !validHealth(status.Daemon) || !validHealth(status.Upstream) {
		return errors.New("daemon returned an invalid health category")
	}
	for _, consumer := range status.Consumers {
		if !validRevision(consumer.ID) ||
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
	if event.Timestamp.Year() < 1 || event.Timestamp.Year() > 9999 || !validRevision(event.ConsumerID) || event.LatencyNS < 0 {
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
		ErrorApplyFailed, ErrorConfigurationInvalid, ErrorConfigurationConflict,
		ErrorConfigurationNotFound, ErrorConfigurationFailed, ErrorConfigurationDurabilityUncertain,
		ErrorUpstreamUnavailable, ErrorResourceLimit, ErrorInternal:
		return true
	default:
		return false
	}
}

func validRevision(value string) bool { return revisionPattern.MatchString(value) }

func validRevisionPointer(value *string) bool { return value != nil && validRevision(*value) }

func validWirePath(value string) bool {
	return utf8.ValidString(value) && strings.HasPrefix(value, "/") && len(value) >= 2 &&
		len(value) <= 107 && utf8.RuneCountInString(value) <= 107
}

func validWireTimeouts(value ConfigurationTimeouts) bool {
	return validWireDuration(value.Connect) && validWireDuration(value.List) &&
		validWireDuration(value.Replay) && validWireDuration(value.Sign)
}

func validWireDuration(value string) bool {
	if len(value) == 0 || len(value) > 64 || !durationPattern.MatchString(value) {
		return false
	}
	_, err := time.ParseDuration(value)
	return err == nil
}

func validWireConsumer(value ConfigurationConsumerInput) bool {
	if value.Name == "" || !utf8.ValidString(value.Name) || utf8.RuneCountInString(value.Name) > MaximumConsumerNameCharacters ||
		!validWirePath(value.Socket) || value.Fingerprints == nil || len(value.Fingerprints) > 1024 {
		return false
	}
	seen := make(map[string]struct{}, len(value.Fingerprints))
	for _, fingerprint := range value.Fingerprints {
		if !validFingerprint(fingerprint) {
			return false
		}
		if _, exists := seen[fingerprint]; exists {
			return false
		}
		seen[fingerprint] = struct{}{}
	}
	return true
}

func validateConfigurationResult(result ConfigurationResult) error {
	if !validRevision(result.Revision) || !validWirePath(result.Upstream) || !validWireTimeouts(result.Timeouts) ||
		result.TotalConsumers < 0 || result.Offset < 0 || result.Offset > result.TotalConsumers || result.Consumers == nil ||
		result.Offset+len(result.Consumers) > result.TotalConsumers || result.Complete != (result.Offset+len(result.Consumers) == result.TotalConsumers) {
		return errors.New("daemon returned an invalid configuration projection")
	}
	previousSocket := ""
	for _, consumer := range result.Consumers {
		if !validRevision(consumer.ID) || consumer.ID != consumerIDForPath(consumer.Socket) || !validWireConsumer(consumer.ConfigurationConsumerInput) ||
			previousSocket != "" && strings.Compare(previousSocket, consumer.Socket) >= 0 {
			return errors.New("daemon returned an invalid configuration projection")
		}
		previousSocket = consumer.Socket
	}
	return nil
}

func consumerIDForPath(path string) string {
	digest := sha256.Sum256([]byte(path))
	return hex.EncodeToString(digest[:])
}

func validateConfigurationChange(result ConfigurationChangeResult) error {
	if !isConfigurationMutation(result.Operation) || !validRevision(result.Revision) {
		return errors.New("daemon returned an invalid configuration change result")
	}
	requiresID := result.Operation == OperationPutConsumer || result.Operation == OperationRetireConsumer
	if requiresID != (result.ConsumerID != nil) || result.ConsumerID != nil && !validRevision(*result.ConsumerID) {
		return errors.New("daemon returned an invalid configuration change result")
	}
	return nil
}

func isConfigurationMutation(operation Operation) bool {
	switch operation {
	case OperationSetUpstream, OperationSetTimeouts, OperationPutConsumer, OperationRetireConsumer:
		return true
	default:
		return false
	}
}
