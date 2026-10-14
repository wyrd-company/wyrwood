// ---
// relationships:
//   implements: operational-events
// ---

// Package events owns Wyrwood's closed operational-event vocabulary,
// persistence, and health projections for the agent and the controller.
package events

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maximumAgentBytes        = 253
	maximumContainerKeyBytes = 512
	maximumPolicyBytes       = 64
	maximumOperatorBytes     = 255
)

var (
	bindingPattern     = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	fingerprintPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]$`)
)

// Operation is the closed vocabulary of observable agent and controller operations.
type Operation string

const (
	OperationContainerObserved Operation = "container-observed"
	OperationContainerGone     Operation = "container-gone"
	OperationBindingReceived   Operation = "binding-received"
	OperationBindingRetired    Operation = "binding-retired"
	OperationContractChecked   Operation = "contract-checked"
	OperationRecreateBegun     Operation = "recreate-begun"
	OperationRecreateFinished  Operation = "recreate-finished"
	OperationLogin             Operation = "login"
	OperationRenew             Operation = "renew"
	OperationRevoke            Operation = "revoke"
	OperationVaultRequest      Operation = "vault-request"
	OperationSSHList           Operation = "ssh-list"
	OperationSSHSign           Operation = "ssh-sign"
	OperationSSHCertificate    Operation = "ssh-certificate"
	OperationSSHSessionBind    Operation = "ssh-session-bind"
	OperationAgentApproved     Operation = "agent-approved"
	OperationAgentRejected     Operation = "agent-rejected"
	OperationSessionOpened     Operation = "session-opened"
	OperationSessionClosed     Operation = "session-closed"
	OperationPolicySaved       Operation = "policy-saved"
	OperationBindingCreated    Operation = "binding-created"
	OperationBindingChanged    Operation = "binding-changed"
	OperationBindingDeleted    Operation = "binding-deleted"
	OperationCredentialIssued  Operation = "credential-issued"
	OperationRecreateRequested Operation = "recreate-requested"
	OperationOperatorSignedIn  Operation = "operator-signed-in"
	OperationOperatorSignedOut Operation = "operator-signed-out"
)

// Operations lists the complete operation vocabulary in schema order.
var Operations = []Operation{
	OperationContainerObserved, OperationContainerGone, OperationBindingReceived, OperationBindingRetired,
	OperationContractChecked, OperationRecreateBegun, OperationRecreateFinished,
	OperationLogin, OperationRenew, OperationRevoke, OperationVaultRequest,
	OperationSSHList, OperationSSHSign, OperationSSHCertificate, OperationSSHSessionBind,
	OperationAgentApproved, OperationAgentRejected, OperationSessionOpened, OperationSessionClosed,
	OperationPolicySaved, OperationBindingCreated, OperationBindingChanged, OperationBindingDeleted,
	OperationCredentialIssued, OperationRecreateRequested,
	OperationOperatorSignedIn, OperationOperatorSignedOut,
}

// Outcome is the closed result vocabulary for an operation.
type Outcome string

const (
	OutcomeOK      Outcome = "ok"
	OutcomeDenied  Outcome = "denied"
	OutcomeFailed  Outcome = "failed"
	OutcomeTimeout Outcome = "timeout"
)

// Outcomes lists the complete outcome vocabulary in schema order.
var Outcomes = []Outcome{OutcomeOK, OutcomeDenied, OutcomeFailed, OutcomeTimeout}

// ErrorCode categorizes failures without retaining raw error data. The empty
// code means no error and is only valid with the ok outcome.
type ErrorCode string

const (
	ErrorNone                        ErrorCode = ""
	ErrorEngineUnavailable           ErrorCode = "engine-unavailable"
	ErrorControllerUnavailable       ErrorCode = "controller-unavailable"
	ErrorOpenBaoUnavailable          ErrorCode = "openbao-unavailable"
	ErrorOpenBaoDenied               ErrorCode = "openbao-denied"
	ErrorOpenBaoTimeout              ErrorCode = "openbao-timeout"
	ErrorNoToken                     ErrorCode = "no-token"
	ErrorNotBound                    ErrorCode = "not-bound"
	ErrorPolicyDenied                ErrorCode = "policy-denied"
	ErrorRecreateNotAllowed          ErrorCode = "recreate-not-allowed"
	ErrorIdentityProviderUnavailable ErrorCode = "identity-provider-unavailable"
	ErrorOperatorNotAllowed          ErrorCode = "operator-not-allowed"
	ErrorSignInInvalid               ErrorCode = "sign-in-invalid"
	ErrorProtocol                    ErrorCode = "protocol"
	ErrorInternal                    ErrorCode = "internal"
)

// ErrorCodes lists every non-empty error code in schema order.
var ErrorCodes = []ErrorCode{
	ErrorEngineUnavailable, ErrorControllerUnavailable, ErrorOpenBaoUnavailable, ErrorOpenBaoDenied,
	ErrorOpenBaoTimeout, ErrorNoToken, ErrorNotBound, ErrorPolicyDenied, ErrorRecreateNotAllowed,
	ErrorIdentityProviderUnavailable, ErrorOperatorNotAllowed, ErrorSignInInvalid, ErrorProtocol, ErrorInternal,
}

// Mount is the OpenBao mount category of a vault request.
type Mount string

const (
	MountNone    Mount = ""
	MountKV      Mount = "kv"
	MountTransit Mount = "transit"
	MountSSH     Mount = "ssh"
	MountSys     Mount = "sys"
	MountAuth    Mount = "auth"
	MountOther   Mount = "other"
)

// Mounts lists every non-empty mount category in schema order.
var Mounts = []Mount{MountKV, MountTransit, MountSSH, MountSys, MountAuth, MountOther}

// Method is the HTTP method category of a vault request.
type Method string

const (
	MethodNone   Method = ""
	MethodGet    Method = "GET"
	MethodList   Method = "LIST"
	MethodPost   Method = "POST"
	MethodPut    Method = "PUT"
	MethodDelete Method = "DELETE"
)

// Methods lists every non-empty method in schema order.
var Methods = []Method{MethodGet, MethodList, MethodPost, MethodPut, MethodDelete}

// Event is the complete and closed durable operational-event type. It
// deliberately has no metadata, attribute, map, byte-slice, or raw-error
// field through which additional information could escape the closed schema.
// Empty string fields are absent.
type Event struct {
	Time         time.Time
	Operation    Operation
	Outcome      Outcome
	Latency      time.Duration
	ErrorCode    ErrorCode
	Agent        string
	Binding      string
	ContainerKey string
	Policy       string
	Operator     string
	Fingerprint  string
	Mount        Mount
	Method       Method
}

// ContainerKey projects a container key into its event form. Name and
// compose keys are recorded as kind and value. A devcontainer key is derived
// from host paths, so its value is recorded only as a short digest that stays
// correlatable without revealing the path.
func ContainerKey(kind, value string) string {
	if kind == "devcontainer" {
		sum := sha256.Sum256([]byte(value))
		return "devcontainer:" + hex.EncodeToString(sum[:8])
	}
	projected := kind + ":" + value
	if len(projected) > maximumContainerKeyBytes || !utf8.ValidString(projected) {
		sum := sha256.Sum256([]byte(value))
		return kind + ":" + hex.EncodeToString(sum[:8])
	}
	return projected
}

// Validate verifies the complete event vocabulary and cross-field invariants.
func (event Event) Validate() error {
	if _, err := normalizeTimestamp(event.Time); err != nil {
		return err
	}
	if !contains(Operations, event.Operation) {
		return fmt.Errorf("operation %q is not supported", event.Operation)
	}
	if !contains(Outcomes, event.Outcome) {
		return fmt.Errorf("outcome %q is not supported", event.Outcome)
	}
	if event.Latency < 0 {
		return errors.New("latency must not be negative")
	}
	if event.ErrorCode != ErrorNone && !contains(ErrorCodes, event.ErrorCode) {
		return fmt.Errorf("error code %q is not supported", event.ErrorCode)
	}
	if event.Outcome == OutcomeOK && event.ErrorCode != ErrorNone {
		return errors.New("successful event must not carry an error code")
	}
	if event.Outcome != OutcomeOK && event.ErrorCode == ErrorNone {
		return errors.New("non-successful event must carry a categorical error code")
	}
	if err := boundedText("agent", event.Agent, maximumAgentBytes); err != nil {
		return err
	}
	if event.Binding != "" && !bindingPattern.MatchString(event.Binding) {
		return errors.New("binding is not a binding identifier")
	}
	if err := boundedText("container key", event.ContainerKey, maximumContainerKeyBytes); err != nil {
		return err
	}
	if strings.Contains(event.ContainerKey, "/") && !strings.HasPrefix(event.ContainerKey, "compose:") {
		return errors.New("container key must not carry a path")
	}
	if err := boundedText("policy", event.Policy, maximumPolicyBytes); err != nil {
		return err
	}
	if err := boundedText("operator", event.Operator, maximumOperatorBytes); err != nil {
		return err
	}
	if event.Fingerprint != "" && !fingerprintPattern.MatchString(event.Fingerprint) {
		return errors.New("fingerprint is not a canonical OpenSSH SHA-256 fingerprint")
	}
	if event.Mount != MountNone && !contains(Mounts, event.Mount) {
		return fmt.Errorf("mount %q is not supported", event.Mount)
	}
	if event.Method != MethodNone && !contains(Methods, event.Method) {
		return fmt.Errorf("method %q is not supported", event.Method)
	}
	return nil
}

func boundedText(name, value string, maximum int) error {
	if len(value) > maximum {
		return fmt.Errorf("%s exceeds %d bytes", name, maximum)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("%s contains a control character", name)
		}
	}
	return nil
}

func contains[T comparable](values []T, value T) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func normalizeEvent(event Event) (Event, error) {
	if err := event.Validate(); err != nil {
		return Event{}, err
	}
	normalized := event
	var err error
	normalized.Time, err = normalizeTimestamp(event.Time)
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
