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

func TestRenewalWarningParsesAuthoredHCL(t *testing.T) {
	for name, document := range map[string]string{"empty": "", "comment": "# " + strings.ReplaceAll(StarterHCL, "\n", "\n# "), "read-only": `path "auth/token/renew-self" { capabilities=["read"] }`, "deny": StarterHCL + `path "auth/token/renew-self" { capabilities=["deny"] }`} {
		t.Run(name, func(t *testing.T) {
			if len(Warnings(document)) == 0 {
				t.Fatal("missing renewal warning")
			}
		})
	}
	if warnings := Warnings(StarterHCL); len(warnings) != 0 {
		t.Fatalf("starter cannot be recognized: %v", warnings)
	}
}
