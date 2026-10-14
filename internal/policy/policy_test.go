// ---
// relationships:
//   verifies: policy
// ---

package policy

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/schematest"
)

func samplePolicy() Policy {
	group := uint32(1000)
	result := New("teal-team", `path "kv/data/teams/teal/*" { capabilities = ["read"] }`)
	result.Revision = 3
	result.SSH = &SSH{TransitKeys: []string{"teal-signing"}, CARoles: []string{"teal-hosts"}}
	result.Contract.AccessGroup = &group
	result.Contract.Enforcement = EnforcementRecreate
	return result
}

func TestPoliciesValidateAgainstSchemaAndRoundTrip(t *testing.T) {
	schema := schematest.Compile(t, schematest.Policy)
	for _, candidate := range []Policy{New("minimal", ""), samplePolicy()} {
		if err := candidate.Validate(); err != nil {
			t.Fatalf("Validate(%s) = %v", candidate.Name, err)
		}
		data, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if err := schematest.Validate(schema, data); err != nil {
			t.Fatalf("%s does not validate: %v", data, err)
		}
		decoded, err := Decode(data)
		if err != nil {
			t.Fatalf("Decode(%s) = %v", data, err)
		}
		if !reflect.DeepEqual(decoded, candidate) {
			t.Fatalf("round trip = %#v, want %#v", decoded, candidate)
		}
	}
}

func TestDefaultContractMatchesSpecification(t *testing.T) {
	contract := DefaultContract()
	if contract.MountTarget != "/run/wyrwood" || contract.Enforcement != EnforcementReport || contract.AccessGroup != nil {
		t.Fatalf("DefaultContract() = %#v", contract)
	}
	want := []EnvEntry{
		{Name: "SSH_AUTH_SOCK", Value: "/run/wyrwood/ssh-agent.sock"},
		{Name: "VAULT_ADDR", Value: "unix:///run/wyrwood/vault.sock"},
	}
	if got := contract.ExpandedEnv(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ExpandedEnv() = %#v", got)
	}
}

func TestInvalidPoliciesAreRejectedByGoAndSchema(t *testing.T) {
	schema := schematest.Compile(t, schematest.Policy)
	cases := map[string]string{
		"name":           `{"name":"Teal","openbao":{"policy":""},"contract":{"mount-target":"/run/wyrwood","enforcement":"report"}}`,
		"unknown-field":  `{"name":"teal","secret":"x","openbao":{"policy":""},"contract":{"mount-target":"/run/wyrwood","enforcement":"report"}}`,
		"ttl":            `{"name":"teal","openbao":{"policy":"","token-ttl":"10s"},"contract":{"mount-target":"/run/wyrwood","enforcement":"report"}}`,
		"relative-mount": `{"name":"teal","openbao":{"policy":""},"contract":{"mount-target":"run","enforcement":"report"}}`,
		"enforcement":    `{"name":"teal","openbao":{"policy":""},"contract":{"mount-target":"/run/wyrwood","enforcement":"always"}}`,
		"env-name":       `{"name":"teal","openbao":{"policy":""},"contract":{"mount-target":"/run/wyrwood","env":{"lower":"x"},"enforcement":"report"}}`,
		"duplicate-key":  `{"name":"teal","openbao":{"policy":""},"ssh":{"transit-keys":["a","a"]},"contract":{"mount-target":"/run/wyrwood","enforcement":"report"}}`,
		"key-name":       `{"name":"teal","openbao":{"policy":""},"ssh":{"ca-roles":["a b"]},"contract":{"mount-target":"/run/wyrwood","enforcement":"report"}}`,
		"group":          `{"name":"teal","openbao":{"policy":""},"contract":{"mount-target":"/run/wyrwood","access-group":4294967295,"enforcement":"report"}}`,
		"missing":        `{"name":"teal","openbao":{"policy":""}}`,
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(document)); err == nil {
				t.Fatal("Decode() accepted an invalid policy")
			}
			if err := schematest.Validate(schema, []byte(document)); err == nil {
				t.Fatal("schema accepted an invalid policy")
			}
		})
	}
}

func TestGoValidationIsStricterThanSchemaForMountTarget(t *testing.T) {
	for _, target := range []string{"/", "/run/../etc", "/run/wyrwood/"} {
		contract := DefaultContract()
		contract.MountTarget = target
		if err := contract.Validate(); err == nil {
			t.Errorf("Validate(%q) = nil", target)
		}
	}
}

func TestTokenTTLAndNames(t *testing.T) {
	candidate := samplePolicy()
	if candidate.TokenTTL() != time.Hour || candidate.OpenBaoPolicyName() != "wyrwood-teal-team" {
		t.Fatalf("TokenTTL() = %v, name = %q", candidate.TokenTTL(), candidate.OpenBaoPolicyName())
	}
	candidate.OpenBao.TokenTTL = "15m"
	if candidate.TokenTTL() != 15*time.Minute {
		t.Fatalf("TokenTTL() = %v", candidate.TokenTTL())
	}
	clone := candidate.Clone()
	clone.SSH.TransitKeys[0] = "changed"
	clone.Contract.Env["VAULT_ADDR"] = "changed"
	if candidate.SSH.TransitKeys[0] == "changed" || strings.Contains(candidate.Contract.Env["VAULT_ADDR"], "changed") {
		t.Fatal("Clone() shares state")
	}
}
