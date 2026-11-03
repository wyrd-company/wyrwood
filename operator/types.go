// ---
// relationships:
//   implements: operator-interface
//   uses: authenticate-operator-keys-over-ssh
// ---

// Package operator is the public Go client for managing policies and bindings
// on a Wyrwood controller over SSH. The wyrwood operator commands are a thin
// layer over this package, so a program can do what they do without spawning
// them.
//
// An operator key is separate from an agent key. It opens its own SSH
// subsystem, it appears in its own approval list, and an operator who signed in
// through OIDC approves it and sets its grant. A key never leaves the machine:
// it is a file this package generates, or one key of an SSH agent.
package operator

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// SubsystemName is the SSH subsystem operator keys open.
const SubsystemName = "wyrwood-operator"

// ProtocolVersion is the only operator protocol version.
const ProtocolVersion = 1

// MaximumLineBytes bounds one encoded request, including its newline.
const MaximumLineBytes = 1 << 20

// MaximumResponseBytes bounds one encoded response, including its newline.
const MaximumResponseBytes = 16 << 20

// userPrefix starts the SSH username of an operator connection. A colon cannot
// occur in an agent's hostname, so no agent name can read as an operator.
const userPrefix = "operator:"

const maximumLabelBytes = 64

var labelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ValidLabel reports whether label is an acceptable operator key label.
func ValidLabel(label string) bool {
	return len(label) <= maximumLabelBytes && labelPattern.MatchString(label)
}

// User returns the SSH username that presents label.
func User(label string) string { return userPrefix + label }

// ParseUser reports whether an SSH username is an operator connection, and the
// label it presents. The second result is false for any other username.
func ParseUser(user string) (string, bool) {
	label, ok := strings.CutPrefix(user, userPrefix)
	if !ok || !ValidLabel(label) {
		return "", false
	}
	return label, true
}

// Action is one thing a grant permits.
type Action string

const (
	// ActionRead reads policies and bindings inside the grant.
	ActionRead Action = "read"
	// ActionBind creates and removes bindings inside the grant.
	ActionBind Action = "bind"
	// ActionPolicyWrite creates and changes policies inside the grant.
	ActionPolicyWrite Action = "policy-write"
)

// Actions lists every action.
var Actions = []Action{ActionRead, ActionBind, ActionPolicyWrite}

// AllNames, as the only entry of a list in a grant, permits every name.
const AllNames = "*"

const maximumGrantEntries = 256

// Grant is what one operator key may do. An empty list permits nothing.
type Grant struct {
	Agents   []string `json:"agents"`
	Policies []string `json:"policies"`
	Actions  []Action `json:"actions"`
}

// Validate checks the shape of a grant. It needs at least one action, since a
// key with none has no use. validAgent and validPolicy check each name.
func (grant Grant) Validate(validAgent, validPolicy func(string) bool) error {
	if len(grant.Actions) == 0 {
		return errors.New("select at least one action")
	}
	for _, action := range grant.Actions {
		if !slices.Contains(Actions, action) {
			return fmt.Errorf("action %q is not supported", action)
		}
	}
	check := func(what string, names []string, valid func(string) bool) error {
		if len(names) > maximumGrantEntries {
			return fmt.Errorf("the %s list has more than %d entries", what, maximumGrantEntries)
		}
		if slices.Contains(names, AllNames) && len(names) != 1 {
			return fmt.Errorf("the %s list must hold only %q or only names", what, AllNames)
		}
		for _, name := range names {
			if name != AllNames && !valid(name) {
				return fmt.Errorf("%s name %q is invalid", what, name)
			}
		}
		return nil
	}
	if err := check("agent", grant.Agents, validAgent); err != nil {
		return err
	}
	return check("policy", grant.Policies, validPolicy)
}

// Can reports whether the grant permits an action.
func (grant Grant) Can(action Action) bool { return slices.Contains(grant.Actions, action) }

// AllowsAgent reports whether the grant covers an agent.
func (grant Grant) AllowsAgent(name string) bool { return listAllows(grant.Agents, name) }

// AllowsPolicy reports whether the grant covers a policy.
func (grant Grant) AllowsPolicy(name string) bool { return listAllows(grant.Policies, name) }

// Covers reports whether the grant covers a binding: its agent and every policy
// it holds. A binding that holds any policy outside the list is outside the
// grant, so a key cannot reach a binding that gives more than the key may give.
func (grant Grant) Covers(agent string, policies []string) bool {
	if !grant.AllowsAgent(agent) {
		return false
	}
	for _, name := range policies {
		if !grant.AllowsPolicy(name) {
			return false
		}
	}
	return true
}

func listAllows(list []string, name string) bool {
	return slices.Equal(list, []string{AllNames}) || slices.Contains(list, name)
}

// Identity is what the controller knows about the connected key.
type Identity struct {
	Label       string `json:"label"`
	Fingerprint string `json:"fingerprint"`
	Grant       Grant  `json:"grant"`
}

// PolicySSH names the identities a policy's ssh-agent endpoint offers.
type PolicySSH struct {
	TransitKeys []string `json:"transit-keys,omitempty"`
	CARoles     []string `json:"ca-roles,omitempty"`
}

// PolicyPut sets one policy's source. A policy that exists keeps its contract.
// It also keeps its SSH identities when SSH is nil.
type PolicyPut struct {
	Name string     `json:"name"`
	HCL  string     `json:"hcl"`
	SSH  *PolicySSH `json:"ssh,omitempty"`
}

// Policy is one stored policy.
type Policy struct {
	Name     string     `json:"name"`
	Revision int        `json:"revision"`
	HCL      string     `json:"hcl"`
	SSH      *PolicySSH `json:"ssh,omitempty"`
	// ValueNames lists the values a binding of this policy must set.
	ValueNames []string `json:"value-names,omitempty"`
}

// PolicyName identifies one policy in a request.
type PolicyName struct {
	Name string `json:"name"`
}

// Policies is a policy list.
type Policies struct {
	Policies []Policy `json:"policies"`
}

// KeyKind is a container key kind.
type KeyKind string

const (
	KeyDevcontainer KeyKind = "devcontainer"
	KeyCompose      KeyKind = "compose"
	KeyName         KeyKind = "name"
)

// Key is the container key a binding matches.
type Key struct {
	Kind  KeyKind `json:"kind"`
	Value string  `json:"value"`
}

// ParseKey reads a key written as kind:value.
func ParseKey(text string) (Key, error) {
	kind, value, found := strings.Cut(text, ":")
	key := Key{Kind: KeyKind(kind), Value: value}
	if !found || value == "" || !slices.Contains([]KeyKind{KeyDevcontainer, KeyCompose, KeyName}, key.Kind) {
		return Key{}, errors.New("a key is devcontainer:VALUE, compose:VALUE, or name:VALUE")
	}
	return key, nil
}

// Settings are one binding's runtime settings. An empty field takes the
// controller's default.
type Settings struct {
	TokenTTL    string            `json:"token-ttl,omitempty"`
	TokenMaxTTL string            `json:"token-max-ttl,omitempty"`
	AccessGroup *uint32           `json:"access-group,omitempty"`
	Enforcement string            `json:"enforcement,omitempty"`
	Values      map[string]string `json:"values,omitempty"`
}

// BindRequest asks for a binding on one agent's container key. Asking again
// with the same selection returns the same binding. Asking with another
// selection fails with ErrBindingDiffers and changes nothing.
type BindRequest struct {
	Agent    string   `json:"agent"`
	Key      Key      `json:"key"`
	Policies []string `json:"policies"`
	Settings Settings `json:"settings"`
}

// Binding is one binding with its readiness.
type Binding struct {
	ID       string        `json:"id"`
	Agent    string        `json:"agent"`
	Key      Key           `json:"key"`
	Policies []string      `json:"policies"`
	Settings Settings      `json:"settings"`
	Revision int           `json:"revision"`
	Applied  bool          `json:"applied"`
	Status   BindingStatus `json:"status"`
}

// BindingList selects bindings. An empty Agent selects every agent in the grant.
type BindingList struct {
	Agent string `json:"agent,omitempty"`
}

// Bindings is a binding list.
type Bindings struct {
	Bindings []Binding `json:"bindings"`
}

// BindingID identifies one binding in a request.
type BindingID struct {
	ID string `json:"id"`
}

// UnbindRequest selects a binding by its ID, or by its agent and key.
type UnbindRequest struct {
	ID    string `json:"id,omitempty"`
	Agent string `json:"agent,omitempty"`
	Key   *Key   `json:"key,omitempty"`
}

// UnbindResult says what an unbind did. A binding that did not exist is a
// success with Removed false.
type UnbindResult struct {
	Removed bool `json:"removed"`
	// TokenLive means the container's token may stay valid until it expires.
	TokenLive bool `json:"token-live,omitempty"`
	// Warning is fixed text about a part of the removal that did not finish.
	Warning string `json:"warning,omitempty"`
}

// Readiness says whether a binding's consumers can use their sockets now.
type Readiness string

const (
	ReadinessReady   Readiness = "ready"
	ReadinessWaiting Readiness = "waiting"
	ReadinessFailed  Readiness = "failed"
	ReadinessUnknown Readiness = "unknown"
)

// BindingStatus is a binding's readiness. It holds no token or secret.
type BindingStatus struct {
	Binding        string             `json:"binding"`
	Agent          string             `json:"agent"`
	Key            Key                `json:"key"`
	AgentConnected bool               `json:"agent-connected"`
	LastReport     string             `json:"last-report,omitempty"`
	Readiness      Readiness          `json:"readiness"`
	Reasons        []string           `json:"reasons,omitempty"`
	Containers     []BindingContainer `json:"containers"`
	Consumers      []ConsumerStatus   `json:"consumers"`
	Token          string             `json:"token,omitempty"`
	Outcome        string             `json:"outcome,omitempty"`
	FailedItems    []string           `json:"failed-items,omitempty"`
	Reason         string             `json:"reason,omitempty"`
	LastError      string             `json:"last-error,omitempty"`
}

// BindingContainer is one reported container a binding governs.
type BindingContainer struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
}

// ConsumerStatus is one consumer directory of a binding.
type ConsumerStatus struct {
	Directory   string   `json:"directory,omitempty"`
	ContainerID string   `json:"container-id,omitempty"`
	AccessGroup *uint32  `json:"access-group,omitempty"`
	Sockets     []string `json:"sockets,omitempty"`
	Failed      string   `json:"failed,omitempty"`
}

// Operation is the closed request vocabulary.
type Operation string

const (
	OperationWhoami      Operation = "whoami"
	OperationPolicyList  Operation = "policy-list"
	OperationPolicyGet   Operation = "policy-get"
	OperationPolicyPut   Operation = "policy-put"
	OperationBindingList Operation = "binding-list"
	OperationBindingGet  Operation = "binding-get"
	OperationBind        Operation = "bind"
	OperationUnbind      Operation = "unbind"
)
