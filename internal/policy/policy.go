// ---
// relationships:
//   implements: policy
// ---

// Package policy owns the Wyrwood policy document: an OpenBao HCL policy,
// the identities the ssh-agent endpoint offers, and a container contract.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maximumNameBytes      = 64
	maximumHCLBytes       = 65536
	maximumIdentityNames  = 64
	maximumIdentityBytes  = 128
	maximumEnvEntries     = 64
	maximumEnvValueBytes  = 4096
	maximumAccessGroup    = 4294967294
	maximumDocumentBytes  = 1 << 20
	defaultTokenTTL       = "1h"
	defaultTokenMaxTTL    = "8h"
	defaultMountTarget    = "/run/wyrwood"
	mountTargetToken      = "{mount-target}"
	openBaoPolicyPrefix   = "wyrwood-"
	maximumTokenTTLAmount = 1 << 20
)

var (
	namePattern     = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	ttlPattern      = regexp.MustCompile(`^[0-9]+(m|h)$`)
	identityPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	envNamePattern  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
)

// Enforcement selects how the agent applies a contract.
type Enforcement string

const (
	EnforcementReport   Enforcement = "report"
	EnforcementRecreate Enforcement = "recreate"
)

// Policy is one named Wyrwood policy document.
type Policy struct {
	Name     string   `json:"name"`
	Revision int      `json:"revision,omitempty"`
	OpenBao  OpenBao  `json:"openbao"`
	SSH      *SSH     `json:"ssh,omitempty"`
	Contract Contract `json:"contract"`
}

// OpenBao carries the HCL policy and the AppRole token time-to-live.
type OpenBao struct {
	Policy   string `json:"policy"`
	TokenTTL string `json:"token-ttl,omitempty"`
	// TokenMaxTTL is the longest a token lives through renewal before the
	// agent must log in again with a fresh credential from the controller.
	TokenMaxTTL string `json:"token-max-ttl,omitempty"`
}

// SSH names the Transit keys and SSH-engine roles the ssh-agent endpoint offers.
type SSH struct {
	TransitKeys    []string          `json:"transit-keys,omitempty"`
	CARoles        []string          `json:"ca-roles,omitempty"`
	NotForwardable *SSHIdentityNames `json:"not-forwardable,omitempty"`
}

// SSHIdentityNames selects identities separately for each OpenBao source.
type SSHIdentityNames struct {
	TransitKeys []string `json:"transit-keys,omitempty"`
	CARoles     []string `json:"ca-roles,omitempty"`
}

// Contract defines what a bound container must look like to reach its sockets.
type Contract struct {
	MountTarget string            `json:"mount-target"`
	Env         map[string]string `json:"env,omitempty"`
	AccessGroup *uint32           `json:"access-group,omitempty"`
	Enforcement Enforcement       `json:"enforcement"`
}

// DefaultContract returns the contract every new policy starts with.
func DefaultContract() Contract {
	return Contract{
		MountTarget: defaultMountTarget,
		Env: map[string]string{
			"SSH_AUTH_SOCK": mountTargetToken + "/ssh-agent.sock",
			"VAULT_ADDR":    "unix://" + mountTargetToken + "/vault.sock",
		},
		Enforcement: EnforcementReport,
	}
}

// New returns a policy with the given name, HCL, and the default contract.
func New(name, hcl string) Policy {
	return Policy{Name: name, OpenBao: OpenBao{Policy: hcl, TokenTTL: defaultTokenTTL, TokenMaxTTL: defaultTokenMaxTTL}, Contract: DefaultContract()}
}

// Decode strictly parses one JSON policy document and validates it.
func Decode(data []byte) (Policy, error) {
	if len(data) > maximumDocumentBytes {
		return Policy{}, errors.New("policy document exceeds 1 MiB")
	}
	var result Policy
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return Policy{}, fmt.Errorf("decode policy: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Policy{}, errors.New("decode policy: trailing data")
	}
	if err := result.Validate(); err != nil {
		return Policy{}, err
	}
	return result, nil
}

// Validate checks every structural constraint of the policy schema plus the
// Go-side canonical form of the mount target.
func (policy Policy) Validate() error {
	if len(policy.Name) > maximumNameBytes || !namePattern.MatchString(policy.Name) {
		return errors.New("policy name must be a lower-kebab-case slug of at most 64 bytes")
	}
	if policy.Revision < 0 {
		return errors.New("policy revision must be positive")
	}
	if len(policy.OpenBao.Policy) > maximumHCLBytes {
		return errors.New("OpenBao policy exceeds 65536 bytes")
	}
	if policy.OpenBao.TokenTTL != "" {
		if _, err := parseTTL("token time-to-live", policy.OpenBao.TokenTTL); err != nil {
			return err
		}
	}
	if policy.OpenBao.TokenMaxTTL != "" {
		if _, err := parseTTL("token maximum lifetime", policy.OpenBao.TokenMaxTTL); err != nil {
			return err
		}
	}
	if policy.TokenMaxTTL() < policy.TokenTTL() {
		return errors.New("token maximum lifetime must be at least the token time-to-live")
	}
	if policy.SSH != nil {
		if err := validateIdentities("transit key", policy.SSH.TransitKeys); err != nil {
			return err
		}
		if err := validateIdentities("SSH role", policy.SSH.CARoles); err != nil {
			return err
		}
		if selected := policy.SSH.NotForwardable; selected != nil {
			if err := validateIdentities("not-forwardable transit key", selected.TransitKeys); err != nil {
				return err
			}
			if err := validateIdentities("not-forwardable SSH role", selected.CARoles); err != nil {
				return err
			}
		}
	}
	return policy.Contract.Validate()
}

// Validate checks the contract fields.
func (contract Contract) Validate() error {
	target := contract.MountTarget
	if !strings.HasPrefix(target, "/") || path.Clean(target) != target || target == "/" || strings.ContainsAny(target, "\x00:,") {
		return errors.New("contract mount target must be a canonical absolute path below the root")
	}
	if len(contract.Env) > maximumEnvEntries {
		return errors.New("contract environment has more than 64 entries")
	}
	for name, value := range contract.Env {
		if !envNamePattern.MatchString(name) {
			return fmt.Errorf("contract environment name %q is invalid", name)
		}
		if len(value) > maximumEnvValueBytes || strings.ContainsRune(value, 0) {
			return fmt.Errorf("contract environment value for %s is invalid", name)
		}
	}
	if contract.AccessGroup != nil && *contract.AccessGroup > maximumAccessGroup {
		return errors.New("contract access group is out of range")
	}
	switch contract.Enforcement {
	case EnforcementReport, EnforcementRecreate:
	default:
		return errors.New("contract enforcement must be report or recreate")
	}
	return nil
}

// ExpandedEnv returns the contract environment with the mount-target token
// replaced, sorted by name.
func (contract Contract) ExpandedEnv() []EnvEntry {
	names := make([]string, 0, len(contract.Env))
	for name := range contract.Env {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := make([]EnvEntry, 0, len(names))
	for _, name := range names {
		entries = append(entries, EnvEntry{Name: name, Value: strings.ReplaceAll(contract.Env[name], mountTargetToken, contract.MountTarget)})
	}
	return entries
}

// EnvEntry is one expanded contract environment value.
type EnvEntry struct {
	Name  string
	Value string
}

// OpenBaoPolicyName is the name the controller writes the HCL under.
func (policy Policy) OpenBaoPolicyName() string { return openBaoPolicyPrefix + policy.Name }

// TokenTTL returns the AppRole token time-to-live, defaulting to one hour.
func (policy Policy) TokenTTL() time.Duration {
	return durationOr(policy.OpenBao.TokenTTL, defaultTokenTTL)
}

// TokenMaxTTL returns the AppRole token maximum lifetime, defaulting to
// eight hours.
func (policy Policy) TokenMaxTTL() time.Duration {
	return durationOr(policy.OpenBao.TokenMaxTTL, defaultTokenMaxTTL)
}

func durationOr(value, fallback string) time.Duration {
	if value == "" {
		value = fallback
	}
	duration, err := parseTTL("", value)
	if err != nil {
		duration, _ = parseTTL("", fallback)
	}
	return duration
}

// TransitKeys returns the Transit key names the policy offers.
func (policy Policy) TransitKeys() []string {
	if policy.SSH == nil {
		return nil
	}
	return append([]string(nil), policy.SSH.TransitKeys...)
}

// CARoles returns the SSH-engine role names the policy offers.
func (policy Policy) CARoles() []string {
	if policy.SSH == nil {
		return nil
	}
	return append([]string(nil), policy.SSH.CARoles...)
}

// Clone returns a deep copy.
func (policy Policy) Clone() Policy {
	clone := policy
	if policy.SSH != nil {
		ssh := SSH{TransitKeys: policy.TransitKeys(), CARoles: policy.CARoles()}
		if selected := policy.SSH.NotForwardable; selected != nil {
			ssh.NotForwardable = &SSHIdentityNames{
				TransitKeys: append([]string(nil), selected.TransitKeys...),
				CARoles:     append([]string(nil), selected.CARoles...),
			}
		}
		clone.SSH = &ssh
	}
	if policy.Contract.Env != nil {
		clone.Contract.Env = make(map[string]string, len(policy.Contract.Env))
		for name, value := range policy.Contract.Env {
			clone.Contract.Env[name] = value
		}
	}
	if policy.Contract.AccessGroup != nil {
		group := *policy.Contract.AccessGroup
		clone.Contract.AccessGroup = &group
	}
	return clone
}

func parseTTL(field, value string) (time.Duration, error) {
	if !ttlPattern.MatchString(value) {
		return 0, fmt.Errorf("%s must be minutes or hours, such as 30m or 1h", field)
	}
	amount, err := strconv.Atoi(value[:len(value)-1])
	if err != nil || amount <= 0 || amount > maximumTokenTTLAmount {
		return 0, fmt.Errorf("%s is out of range", field)
	}
	if strings.HasSuffix(value, "h") {
		return time.Duration(amount) * time.Hour, nil
	}
	return time.Duration(amount) * time.Minute, nil
}

func validateIdentities(kind string, names []string) error {
	if len(names) > maximumIdentityNames {
		return fmt.Errorf("more than 64 %s names", kind)
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if len(name) > maximumIdentityBytes || !identityPattern.MatchString(name) {
			return fmt.Errorf("%s name %q is invalid", kind, name)
		}
		if seen[name] {
			return fmt.Errorf("%s name %q is repeated", kind, name)
		}
		seen[name] = true
	}
	return nil
}
