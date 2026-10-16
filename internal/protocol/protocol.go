// ---
// relationships:
//   implements: agent-controller-protocol
// ---

// Package protocol owns the newline-delimited JSON messages agents and the
// controller exchange over the wyrwood SSH subsystem.
package protocol

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"

	"github.com/wyrd-company/wyrwood/internal/policy"
)

// Version is the only protocol version.
const Version = 1

// SubsystemName is the SSH subsystem agents open.
const SubsystemName = "wyrwood"

// MaximumLineBytes bounds one encoded message including its newline.
const MaximumLineBytes = 1 << 20

const (
	maximumKeyValueBytes = 512
	maximumNameBytes     = 256
	maximumImageBytes    = 512
	maximumContainers    = 1024
	maximumKeys          = 3
)

var (
	idPattern          = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	accessorPattern    = regexp.MustCompile(`^[A-Za-z0-9.]{1,128}$`)
	containerIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Type is the closed message type vocabulary.
type Type string

const (
	TypeHello             Type = "hello"
	TypeInventory         Type = "inventory"
	TypeContractResult    Type = "contract-result"
	TypeCredentialRequest Type = "credential-request"
	TypePolicySet         Type = "policy-set"
	TypeCredential        Type = "credential"
	TypeRecreateRequest   Type = "recreate-request"
	TypeUnbind            Type = "unbind"
	TypeResultRecorded    Type = "result-recorded"
	TypeTokenAccessor     Type = "token-accessor"
	TypeAccessorRecorded  Type = "accessor-recorded"
)

// Types lists every message type in schema order.
var Types = []Type{
	TypeHello, TypeInventory, TypeContractResult, TypeCredentialRequest,
	TypePolicySet, TypeCredential, TypeRecreateRequest, TypeUnbind,
	TypeResultRecorded, TypeTokenAccessor, TypeAccessorRecorded,
}

// Message is one protocol message.
type Message interface {
	MessageType() Type
	Validate() error
}

// KeyKind is a container key kind in precedence order.
type KeyKind string

const (
	KeyDevcontainer KeyKind = "devcontainer"
	KeyCompose      KeyKind = "compose"
	KeyName         KeyKind = "name"
)

// KeyKinds lists every key kind in precedence order.
var KeyKinds = []KeyKind{KeyDevcontainer, KeyCompose, KeyName}

// Key is one candidate container key.
type Key struct {
	Kind  KeyKind `json:"kind"`
	Value string  `json:"value"`
}

// Validate checks the key kind and value bounds.
func (key Key) Validate() error {
	switch key.Kind {
	case KeyDevcontainer, KeyCompose, KeyName:
	default:
		return fmt.Errorf("key kind %q is not supported", key.Kind)
	}
	if key.Value == "" || len(key.Value) > maximumKeyValueBytes {
		return errors.New("key value must be 1 to 512 bytes")
	}
	return nil
}

// State is an engine container state.
type State string

const (
	StateCreated    State = "created"
	StateRunning    State = "running"
	StatePaused     State = "paused"
	StateRestarting State = "restarting"
	StateExited     State = "exited"
	StateDead       State = "dead"
)

// States lists every container state in schema order.
var States = []State{StateCreated, StateRunning, StatePaused, StateRestarting, StateExited, StateDead}

// Mount is one container mount as the contract check needs it.
type Mount struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// Container is one inventory entry.
type Container struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	State    State    `json:"state"`
	Image    string   `json:"image,omitempty"`
	Keys     []Key    `json:"keys"`
	Mounts   []Mount  `json:"mounts,omitempty"`
	EnvNames []string `json:"env-names,omitempty"`
}

// Validate checks one inventory entry.
func (container Container) Validate() error {
	if !containerIDPattern.MatchString(container.ID) {
		return errors.New("container identifier must be 64 lowercase hexadecimal characters")
	}
	if len(container.Name) > maximumNameBytes {
		return errors.New("container name exceeds 256 bytes")
	}
	if !contains(States, container.State) {
		return fmt.Errorf("container state %q is not supported", container.State)
	}
	if len(container.Image) > maximumImageBytes {
		return errors.New("container image exceeds 512 bytes")
	}
	if len(container.Keys) < 1 || len(container.Keys) > maximumKeys {
		return errors.New("container must carry one to three keys")
	}
	for _, key := range container.Keys {
		if err := key.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Hello opens an agent session.
type Hello struct {
	AgentVersion  string `json:"agent-version,omitempty"`
	AllowRecreate bool   `json:"allow-recreate"`
}

// Inventory carries the complete current container list.
type Inventory struct {
	Containers []Container `json:"containers"`
}

// Outcome is a contract-result outcome.
type Outcome string

const (
	OutcomeConforming     Outcome = "conforming"
	OutcomeNonConforming  Outcome = "non-conforming"
	OutcomeRecreating     Outcome = "recreating"
	OutcomeRecreated      Outcome = "recreated"
	OutcomeRecreateFailed Outcome = "recreate-failed"
)

// Outcomes lists every contract outcome in schema order.
var Outcomes = []Outcome{OutcomeConforming, OutcomeNonConforming, OutcomeRecreating, OutcomeRecreated, OutcomeRecreateFailed}

// FailedItem is a contract item that did not conform.
type FailedItem string

const (
	FailedConsumerDirectory  FailedItem = "consumer-directory"
	FailedSocketAccess       FailedItem = "socket-access"
	FailedMount              FailedItem = "mount"
	FailedEnv                FailedItem = "env"
	FailedAccessGroup        FailedItem = "access-group"
	FailedRecreateNotAllowed FailedItem = "recreate-not-allowed"
)

// FailedItems lists every failed-item name in schema order.
var FailedItems = []FailedItem{FailedMount, FailedEnv, FailedAccessGroup, FailedConsumerDirectory, FailedSocketAccess, FailedRecreateNotAllowed}

// Reason is a categorical recreate failure reason.
type Reason string

const (
	ReasonEngineError  Reason = "engine-error"
	ReasonCreateFailed Reason = "create-failed"
	ReasonStartFailed  Reason = "start-failed"
)

// Reasons lists every recreate failure reason in schema order.
var Reasons = []Reason{ReasonEngineError, ReasonCreateFailed, ReasonStartFailed}

// ContractResult reports one bound container's conformance.
type ContractResult struct {
	Binding     string       `json:"binding"`
	Outcome     Outcome      `json:"outcome"`
	FailedItems []FailedItem `json:"failed-items,omitempty"`
	ContainerID string       `json:"container-id,omitempty"`
	Reason      Reason       `json:"reason,omitempty"`
}

// CredentialRequest names a binding whose token must be replaced.
type CredentialRequest struct {
	Binding string `json:"binding"`
}

// OpenBao is the OpenBao endpoint agents use.
type OpenBao struct {
	Address   string `json:"address"`
	CAPEM     string `json:"ca-pem,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	// TransitMount and SSHMount name the mounts the policy's Transit keys
	// and SSH-engine roles live under.
	TransitMount string `json:"transit-mount,omitempty"`
	SSHMount     string `json:"ssh-mount,omitempty"`
}

// Binding is one binding that matches a container in the latest inventory.
type Binding struct {
	Binding string        `json:"binding"`
	Key     Key           `json:"key"`
	Policy  policy.Policy `json:"policy"`
}

// PolicySet carries every binding matching the latest inventory.
type PolicySet struct {
	OpenBao  OpenBao   `json:"openbao"`
	Bindings []Binding `json:"bindings"`
}

// Credential carries one binding's AppRole role and wrapped secret identifier.
type Credential struct {
	Binding         string `json:"binding"`
	AppRoleMount    string `json:"approle-mount"`
	RoleID          string `json:"role-id"`
	WrappedSecretID string `json:"wrapped-secret-id"`
}

// String never reveals the wrapped secret identifier.
func (credential Credential) String() string {
	return "credential(" + credential.Binding + ")"
}

// GoString never reveals the wrapped secret identifier.
func (credential Credential) GoString() string { return credential.String() }

// RecreateRequest names a binding for an operator-requested recreate.
type RecreateRequest struct {
	Binding string `json:"binding"`
}

// Unbind names a binding to retire.
type Unbind struct {
	Binding string `json:"binding"`
}

// TokenAccessor reports the accessor of the token an agent obtained for a
// binding, so the controller can revoke that token when the binding is
// deleted. It replaces any accessor reported for the binding before.
type TokenAccessor struct {
	Binding  string `json:"binding"`
	Accessor string `json:"accessor"`
}

// AccessorRecorded acknowledges a token accessor the controller has stored,
// revoked because its binding was already retired, or discarded because the
// binding never belonged to the agent. It echoes the report.
type AccessorRecorded struct {
	Binding  string `json:"binding"`
	Accessor string `json:"accessor"`
}

// Acknowledge returns the acknowledgement of report.
func (report TokenAccessor) Acknowledge() AccessorRecorded {
	return AccessorRecorded(report)
}

// ResultRecorded acknowledges a contract result the controller has stored,
// or discarded because its binding no longer belongs to the agent. It
// echoes the result's binding, outcome, and reason.
type ResultRecorded struct {
	Binding string  `json:"binding"`
	Outcome Outcome `json:"outcome"`
	Reason  Reason  `json:"reason,omitempty"`
}

// Acknowledge returns the acknowledgement of result.
func (result ContractResult) Acknowledge() ResultRecorded {
	return ResultRecorded{Binding: result.Binding, Outcome: result.Outcome, Reason: result.Reason}
}

func (Hello) MessageType() Type             { return TypeHello }
func (Inventory) MessageType() Type         { return TypeInventory }
func (ContractResult) MessageType() Type    { return TypeContractResult }
func (CredentialRequest) MessageType() Type { return TypeCredentialRequest }
func (PolicySet) MessageType() Type         { return TypePolicySet }
func (Credential) MessageType() Type        { return TypeCredential }
func (RecreateRequest) MessageType() Type   { return TypeRecreateRequest }
func (Unbind) MessageType() Type            { return TypeUnbind }
func (ResultRecorded) MessageType() Type    { return TypeResultRecorded }
func (TokenAccessor) MessageType() Type     { return TypeTokenAccessor }
func (AccessorRecorded) MessageType() Type  { return TypeAccessorRecorded }

// Validate checks the hello message.
func (message Hello) Validate() error { return nil }

// Validate checks every inventory entry and the inventory bound.
func (message Inventory) Validate() error {
	if len(message.Containers) > maximumContainers {
		return errors.New("inventory exceeds 1024 containers")
	}
	for _, container := range message.Containers {
		if err := container.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks the contract result's closed vocabularies.
func (message ContractResult) Validate() error {
	if err := validateID(message.Binding); err != nil {
		return err
	}
	if !contains(Outcomes, message.Outcome) {
		return fmt.Errorf("contract outcome %q is not supported", message.Outcome)
	}
	for _, item := range message.FailedItems {
		if !contains(FailedItems, item) {
			return fmt.Errorf("failed item %q is not supported", item)
		}
	}
	if message.ContainerID != "" && !containerIDPattern.MatchString(message.ContainerID) {
		return errors.New("container identifier must be 64 lowercase hexadecimal characters")
	}
	if message.Reason != "" && !contains(Reasons, message.Reason) {
		return fmt.Errorf("reason %q is not supported", message.Reason)
	}
	return nil
}

// Validate checks the binding identifier.
func (message CredentialRequest) Validate() error { return validateID(message.Binding) }

// Validate checks the OpenBao address and each binding.
func (message PolicySet) Validate() error {
	parsed, err := url.Parse(message.OpenBao.Address)
	if err != nil || parsed.Scheme == "" || !parsed.IsAbs() {
		return errors.New("OpenBao address must be an absolute URI")
	}
	for _, binding := range message.Bindings {
		if err := validateID(binding.Binding); err != nil {
			return err
		}
		if err := binding.Key.Validate(); err != nil {
			return err
		}
		if err := binding.Policy.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks the credential fields are present.
func (message Credential) Validate() error {
	if err := validateID(message.Binding); err != nil {
		return err
	}
	if message.AppRoleMount == "" || message.RoleID == "" || message.WrappedSecretID == "" {
		return errors.New("credential must carry an AppRole mount, role identifier, and wrapped secret identifier")
	}
	return nil
}

// Validate checks the binding identifier.
func (message RecreateRequest) Validate() error { return validateID(message.Binding) }

// Validate checks the binding identifier.
func (message Unbind) Validate() error { return validateID(message.Binding) }

// Validate checks the binding identifier and the accessor's form.
func (message TokenAccessor) Validate() error {
	if err := validateID(message.Binding); err != nil {
		return err
	}
	if !ValidAccessor(message.Accessor) {
		return errors.New("token accessor is invalid")
	}
	return nil
}

// Validate checks the acknowledged report.
func (message AccessorRecorded) Validate() error { return TokenAccessor(message).Validate() }

// ValidAccessor reports whether value has the form of an OpenBao token
// accessor, including a namespace suffix.
func ValidAccessor(value string) bool { return accessorPattern.MatchString(value) }

// Validate checks the acknowledged result's closed vocabularies.
func (message ResultRecorded) Validate() error {
	return ContractResult{Binding: message.Binding, Outcome: message.Outcome, Reason: message.Reason}.Validate()
}

func validateID(value string) error {
	if !idPattern.MatchString(value) {
		return errors.New("binding identifier is invalid")
	}
	return nil
}

// ValidID reports whether value is a valid binding identifier.
func ValidID(value string) bool { return idPattern.MatchString(value) }

func contains[T comparable](values []T, value T) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
