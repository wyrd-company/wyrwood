// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package policy

import (
	"reflect"
	"strings"
	"testing"
)

func TestCompositionUnionsSourcesAndRetainsRestrictions(t *testing.T) {
	a, b := New("alpha", StarterHCL), New("beta", `path "kv/data/example" { capabilities=["read"] }`)
	a.Revision, b.Revision = 2, 3
	a.SSH = &SSH{TransitKeys: []string{"shared", "first"}, CARoles: []string{"shared"}, NotForwardable: &SSHIdentityNames{TransitKeys: []string{"shared", "not-offered"}}}
	b.SSH = &SSH{TransitKeys: []string{"shared", "second"}, NotForwardable: &SSHIdentityNames{CARoles: []string{"shared"}}}
	b.Contract.Env["SSH_AUTH_SOCK"] = "/run/wyrwood/ssh-agent.sock"
	b.Contract.Env["EXAMPLE"] = "value"
	zero := uint32(0)
	settings := Settings{TokenTTL: "20m", TokenMaxTTL: "2h", AccessGroup: &zero, Enforcement: EnforcementRecreate}
	result, err := Compose([]Policy{b, a}, settings)
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := Compose([]Policy{a, b}, settings)
	if err != nil || result.Identity() != reverse.Identity() {
		t.Fatal("selection order changes the assignment")
	}
	if !reflect.DeepEqual(result.OpenBaoPolicies(), []string{"wyrwood-alpha", "wyrwood-beta"}) {
		t.Fatal(result.OpenBaoPolicies())
	}
	if !reflect.DeepEqual(result.TransitKeys(), []string{"first", "second", "shared"}) {
		t.Fatal(result.TransitKeys())
	}
	if !reflect.DeepEqual(result.SSH.NotForwardable.TransitKeys, []string{"shared"}) || !reflect.DeepEqual(result.SSH.NotForwardable.CARoles, []string{"shared"}) {
		t.Fatal("restriction union lost or added an identity")
	}
	if result.Contract.Env["EXAMPLE"] != "value" || result.Contract.AccessGroup == nil || *result.Contract.AccessGroup != 0 || result.Contract.Enforcement != EnforcementRecreate {
		t.Fatal("binding settings or environment lost")
	}
	if !strings.Contains(result.OpenBao.Policy, a.OpenBao.Policy) || !strings.Contains(result.OpenBao.Policy, b.OpenBao.Policy) {
		t.Fatal("source HCL lost")
	}
	if a.Contract.Env["EXAMPLE"] != "" {
		t.Fatal("composition mutated a source")
	}
}

func TestCompositionRejectsConflictsAndEmptySelections(t *testing.T) {
	a, b := New("alpha", ""), New("beta", "")
	for _, scenario := range []string{"mount", "env", "duplicate", "empty"} {
		t.Run(scenario, func(t *testing.T) {
			second := b.Clone()
			sources := []Policy{a, second}
			switch scenario {
			case "mount":
				sources[1].Contract.MountTarget = "/opt/example"
				sources[0].Contract.Env = nil
				sources[1].Contract.Env = nil
			case "env":
				sources[1].Contract.Env["VAULT_ADDR"] = "other"
			case "duplicate":
				sources = []Policy{a, a}
			case "empty":
				sources = nil
			}
			if _, err := Compose(sources, DefaultSettings()); err == nil {
				t.Fatal("invalid selection accepted")
			}
		})
	}
}

func TestRenewalDefaultsAndComposition(t *testing.T) {
	newPolicy := New("alpha", "")
	if !newPolicy.AgentRenewal() {
		t.Fatal("new policies must enable renewal")
	}
	runtime := newPolicy.Runtime(DefaultSettings())
	if runtime.OpenBao.AgentTokenRenewal == nil || !runtime.AgentRenewal() {
		t.Fatal("runtime lost the explicit renewal choice")
	}
	old := newPolicy.Clone()
	old.OpenBao.AgentTokenRenewal = nil
	if old.AgentRenewal() {
		t.Fatal("missing legacy permission enabled renewal")
	}
	old.OpenBao.Policy = `path "auth/token/renew-self" { capabilities=["update"] }`
	if !old.AgentRenewal() {
		t.Fatal("legacy renewal permission lost")
	}
	disabled := false
	old.OpenBao.AgentTokenRenewal = &disabled
	if old.AgentRenewal() {
		t.Fatal("explicit disable did not override authored lifecycle rule")
	}
	clone := old.Clone()
	*clone.OpenBao.AgentTokenRenewal = true
	if old.AgentRenewal() {
		t.Fatal("clone changed original renewal choice")
	}
	off, err := Compose([]Policy{old}, DefaultSettings())
	if err != nil || off.AgentRenewal() {
		t.Fatalf("disabled composition = %#v, %v", off, err)
	}
	old.Name = "beta"
	mixed, err := Compose([]Policy{old, newPolicy}, DefaultSettings())
	if err != nil || !mixed.AgentRenewal() {
		t.Fatalf("mixed composition = %#v, %v", mixed, err)
	}
	if !strings.Contains(mixed.OpenBao.Policy, LifecycleHCL(true)) || !strings.Contains(off.OpenBao.Policy, LifecycleHCL(false)) {
		t.Fatal("effective preview lost lifecycle grants")
	}
}
