// ---
// relationships:
//   implements: composable-policy-bindings
// ---

package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// StarterHCL makes token lifecycle requirements visible to each policy author.
const StarterHCL = `path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
`

// Settings belongs to a container binding, never to a reusable policy.
type Settings struct {
	TokenTTL    string      `json:"token-ttl"`
	TokenMaxTTL string      `json:"token-max-ttl"`
	AccessGroup *uint32     `json:"access-group,omitempty"`
	Enforcement Enforcement `json:"enforcement"`
}

// Selection is a complete binding edit, with an optimistic binding revision.
type Selection struct {
	Policies []string `json:"policies"`
	Settings Settings `json:"settings"`
	Revision int      `json:"revision"`
}

func DefaultSettings() Settings {
	return Settings{TokenTTL: defaultTokenTTL, TokenMaxTTL: defaultTokenMaxTTL, Enforcement: EnforcementReport}
}

func (s Settings) Defaults() Settings {
	if s.TokenTTL == "" {
		s.TokenTTL = defaultTokenTTL
	}
	if s.TokenMaxTTL == "" {
		s.TokenMaxTTL = defaultTokenMaxTTL
	}
	if s.Enforcement == "" {
		s.Enforcement = EnforcementReport
	}
	return s
}

func (s Settings) Validate() error {
	s = s.Defaults()
	ttl, err := parseTTL("token time-to-live", s.TokenTTL)
	if err != nil {
		return err
	}
	max, err := parseTTL("token maximum lifetime", s.TokenMaxTTL)
	if err != nil {
		return err
	}
	if max < ttl {
		return errors.New("token maximum lifetime must be at least the token time-to-live")
	}
	return (Contract{MountTarget: defaultMountTarget, AccessGroup: s.AccessGroup, Enforcement: s.Enforcement}).Validate()
}

func (s Settings) TTL() time.Duration    { return durationOr(s.TokenTTL, defaultTokenTTL) }
func (s Settings) MaxTTL() time.Duration { return durationOr(s.TokenMaxTTL, defaultTokenMaxTTL) }

type Source struct {
	Name     string `json:"name"`
	Revision int    `json:"revision"`
	HCL      string `json:"hcl"`
}

// Effective is a resolved binding assignment, with its source provenance.
type Effective struct {
	Sources  []Source `json:"sources"`
	OpenBao  OpenBao  `json:"openbao"`
	SSH      *SSH     `json:"ssh,omitempty"`
	Contract Contract `json:"contract"`
	Settings Settings `json:"settings"`
}

func (e Effective) Names() []string {
	names := make([]string, 0, len(e.Sources))
	for _, s := range e.Sources {
		names = append(names, s.Name)
	}
	return names
}
func (e Effective) OpenBaoPolicies() []string {
	names := e.Names()
	for i := range names {
		names[i] = openBaoPolicyPrefix + names[i]
	}
	return names
}
func (e Effective) Identity() string {
	data, _ := json.Marshal(e)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func (e Effective) TransitKeys() []string {
	if e.SSH == nil {
		return nil
	}
	return append([]string(nil), e.SSH.TransitKeys...)
}
func (e Effective) CARoles() []string {
	if e.SSH == nil {
		return nil
	}
	return append([]string(nil), e.SSH.CARoles...)
}
func (e Effective) Validate() error {
	if len(e.Sources) == 0 {
		return errors.New("a binding requires at least one policy")
	}
	if err := e.Settings.Validate(); err != nil {
		return err
	}
	if err := e.Contract.Validate(); err != nil {
		return err
	}
	if e.Contract.Enforcement != e.Settings.Defaults().Enforcement || !equalGroup(e.Contract.AccessGroup, e.Settings.AccessGroup) {
		return errors.New("effective contract and binding settings disagree")
	}
	identities := New("effective", "")
	identities.SSH = e.SSH
	if err := identities.Validate(); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, s := range e.Sources {
		if seen[s.Name] {
			return errors.New("policy selection is repeated")
		}
		seen[s.Name] = true
		p := New(s.Name, s.HCL)
		p.Revision = s.Revision
		if err := p.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Runtime resolves a single policy without modifying the reusable document.
// Validation remains explicit at the composition/transport boundary.
func (p Policy) Runtime(settings Settings) Effective {
	settings = settings.Defaults()
	return Effective{Sources: []Source{{Name: p.Name, Revision: p.Revision, HCL: p.OpenBao.Policy}}, OpenBao: p.OpenBao, SSH: p.Clone().SSH,
		Contract: Contract{MountTarget: p.Contract.MountTarget, Env: p.Clone().Contract.Env, AccessGroup: settings.AccessGroup, Enforcement: settings.Enforcement}, Settings: settings}
}

// Compose unions sources in stable name order. A conflict never chooses a winner.
func Compose(policies []Policy, settings Settings) (Effective, error) {
	if len(policies) == 0 {
		return Effective{}, errors.New("select at least one policy")
	}
	policies = append([]Policy(nil), policies...)
	sort.Slice(policies, func(i, j int) bool { return policies[i].Name < policies[j].Name })
	result := policies[0].Runtime(settings)
	result.Sources = nil
	result.Contract.Env = map[string]string{}
	result.SSH = &SSH{NotForwardable: &SSHIdentityNames{}}
	keys, roles, restrictedKeys, restrictedRoles := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	envSource := map[string]string{}
	seen := map[string]bool{}
	var hcl strings.Builder
	for _, p := range policies {
		if err := p.Validate(); err != nil {
			return Effective{}, err
		}
		if seen[p.Name] {
			return Effective{}, fmt.Errorf("policy %s is selected more than once", p.Name)
		}
		seen[p.Name] = true
		if p.Contract.MountTarget != result.Contract.MountTarget {
			return Effective{}, fmt.Errorf("mount-target conflicts between %s and %s", policies[0].Name, p.Name)
		}
		for name, value := range p.Contract.Env {
			value = strings.ReplaceAll(value, mountTargetToken, p.Contract.MountTarget)
			if old, ok := result.Contract.Env[name]; ok && old != value {
				return Effective{}, fmt.Errorf("environment %s conflicts between %s and %s", name, envSource[name], p.Name)
			}
			result.Contract.Env[name] = value
			envSource[name] = p.Name
		}
		result.Sources = append(result.Sources, Source{Name: p.Name, Revision: p.Revision, HCL: p.OpenBao.Policy})
		fmt.Fprintf(&hcl, "# Policy %s (revision %d)\n%s\n", p.Name, p.Revision, p.OpenBao.Policy)
		for _, k := range p.TransitKeys() {
			keys[k] = true
		}
		for _, r := range p.CARoles() {
			roles[r] = true
		}
		if p.SSH != nil && p.SSH.NotForwardable != nil {
			for _, k := range p.SSH.NotForwardable.TransitKeys {
				restrictedKeys[k] = true
			}
			for _, r := range p.SSH.NotForwardable.CARoles {
				restrictedRoles[r] = true
			}
		}
	}
	result.OpenBao.Policy = hcl.String()
	result.SSH.TransitKeys = namesOf(keys)
	result.SSH.CARoles = namesOf(roles)
	for k := range restrictedKeys {
		if !keys[k] {
			delete(restrictedKeys, k)
		}
	}
	for r := range restrictedRoles {
		if !roles[r] {
			delete(restrictedRoles, r)
		}
	}
	result.SSH.NotForwardable.TransitKeys = namesOf(restrictedKeys)
	result.SSH.NotForwardable.CARoles = namesOf(restrictedRoles)
	if len(keys) > maximumIdentityNames || len(roles) > maximumIdentityNames {
		return Effective{}, errors.New("effective policy has more than 64 identities of one source type")
	}
	if err := result.Validate(); err != nil {
		return Effective{}, err
	}
	return result, nil
}

func namesOf(set map[string]bool) []string {
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Clone detaches an effective assignment from mutable caller data.
func (e Effective) Clone() Effective {
	data, _ := json.Marshal(e)
	var clone Effective
	_ = json.Unmarshal(data, &clone)
	return clone
}

func equalGroup(a, b *uint32) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
