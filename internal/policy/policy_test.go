// ---
// relationships:
//   verifies: policy
// ---

package policy

import (
	"encoding/json"
	"fmt"
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
	result.SSH.NotForwardable = &SSHIdentityNames{TransitKeys: []string{"teal-signing"}, CARoles: []string{"teal-hosts"}}
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
		"max-ttl":        `{"name":"teal","openbao":{"policy":"","token-max-ttl":"10s"},"contract":{"mount-target":"/run/wyrwood","enforcement":"report"}}`,
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
	clone.SSH.NotForwardable.TransitKeys[0] = "changed"
	clone.SSH.NotForwardable.CARoles[0] = "changed"
	if candidate.SSH.NotForwardable.TransitKeys[0] == "changed" || candidate.SSH.NotForwardable.CARoles[0] == "changed" {
		t.Fatal("Clone() shares forwarding selectors")
	}
	if candidate.SSH.TransitKeys[0] == "changed" || strings.Contains(candidate.Contract.Env["VAULT_ADDR"], "changed") {
		t.Fatal("Clone() shares state")
	}
}

func TestTokenMaxTTL(t *testing.T) {
	candidate := samplePolicy()
	if candidate.TokenMaxTTL() != 8*time.Hour {
		t.Fatalf("TokenMaxTTL() = %v, want the 8h default", candidate.TokenMaxTTL())
	}
	if New("teal", "").OpenBao.TokenMaxTTL != "8h" {
		t.Fatal("New() does not write the 8h default")
	}
	candidate.OpenBao.TokenTTL, candidate.OpenBao.TokenMaxTTL = "2h", "3h"
	if err := candidate.Validate(); err != nil || candidate.TokenMaxTTL() != 3*time.Hour {
		t.Fatalf("Validate(3h) = %v, TokenMaxTTL() = %v", err, candidate.TokenMaxTTL())
	}
	candidate.OpenBao.TokenMaxTTL = "2h"
	if err := candidate.Validate(); err != nil {
		t.Fatalf("Validate(maximum equal to time-to-live) = %v", err)
	}
	candidate.OpenBao.TokenMaxTTL = "90m"
	if err := candidate.Validate(); err == nil || !strings.Contains(err.Error(), "at least the token time-to-live") {
		t.Fatalf("Validate(maximum below time-to-live) = %v", err)
	}
	// An omitted maximum takes the default, which a longer time-to-live exceeds.
	candidate.OpenBao.TokenTTL, candidate.OpenBao.TokenMaxTTL = "12h", ""
	if err := candidate.Validate(); err == nil {
		t.Fatal("Validate(12h time-to-live under the default maximum) = nil")
	}
	candidate.OpenBao.TokenTTL, candidate.OpenBao.TokenMaxTTL = "1h", "8"
	if err := candidate.Validate(); err == nil || !strings.Contains(err.Error(), "token maximum lifetime") {
		t.Fatalf("Validate(malformed maximum) = %v", err)
	}
}

func TestInvalidNotForwardableSelectors(t *testing.T) {
	schema := schematest.Compile(t, schematest.Policy)
	manyNames := make([]string, 65)
	for index := range manyNames {
		manyNames[index] = fmt.Sprintf("sample-%d", index)
	}
	for _, source := range []string{"transit-keys", "ca-roles"} {
		for name, names := range map[string][]string{
			"invalid-name": {"a b"}, "duplicate": {"sample", "sample"},
			"long-name": {strings.Repeat("x", 129)}, "too-many": manyNames,
		} {
			t.Run(source+"/"+name, func(t *testing.T) {
				selected, _ := json.Marshal(map[string][]string{source: names})
				data := []byte(`{"name":"sample","openbao":{"policy":""},"ssh":{"not-forwardable":` + string(selected) + `},"contract":{"mount-target":"/run/wyrwood","enforcement":"report"}}`)
				if _, err := Decode(data); err == nil {
					t.Fatal("Go accepted invalid selectors")
				}
				if err := schematest.Validate(schema, data); err == nil {
					t.Fatal("schema accepted invalid selectors")
				}
			})
		}
	}
}
