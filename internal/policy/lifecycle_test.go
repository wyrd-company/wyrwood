// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package policy

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl"
)

func TestManagedLifecycleKeepsWorkloadHCL(t *testing.T) {
	for _, source := range []string{
		`# retain example
path "kv/data/example/*" { capabilities = ["read"] allowed_parameters = { "value" = [] } }
path "/auth/token/lookup-self" { capabilities = ["deny"] }
path "auth/token/renew-self" { capabilities = ["read"] }
path "auth/token/revoke-self" { capabilities = ["deny"] }
path "auth/token/renew-self*" { capabilities = ["read"] }`,
		`{"path":{"kv/data/example/*":{"capabilities":["read"],"allowed_parameters":{"value":[]}},"/auth/token/lookup-self":{"capabilities":["deny"]},"auth/token/renew-self":{"capabilities":["read"]},"auth/token/revoke-self":{"capabilities":["deny"]},"auth/token/renew-self*":{"capabilities":["read"]}}}`,
	} {
		for _, renew := range []bool{false, true} {
			compiled := WorkloadHCL(source) + "\n" + LifecycleHCL(renew)
			var parsed struct {
				Paths []struct {
					Name         string           `hcl:",key"`
					Capabilities []string         `hcl:"capabilities"`
					Allowed      map[string][]any `hcl:"allowed_parameters"`
				} `hcl:"path"`
			}
			if err := hcl.Decode(&parsed, compiled); err != nil {
				t.Fatal(err)
			}
			if len(parsed.Paths) != 5 {
				t.Fatalf("managed lifecycle stanzas were not replaced: %#v", parsed.Paths)
			}
			found := map[string]string{}
			for _, path := range parsed.Paths {
				found[path.Name] = strings.Join(path.Capabilities, ",")
				if path.Name == "kv/data/example/*" && path.Allowed["value"] == nil {
					t.Fatal("workload constraints lost")
				}
			}
			if found["auth/token/lookup-self"] != "read" || found["auth/token/revoke-self"] != "update" || (found["auth/token/renew-self"] == "update") != renew || found["kv/data/example/*"] != "read" || found["auth/token/renew-self*"] != "read" {
				t.Fatalf("compiled paths = %v", found)
			}
		}
	}
}

func TestWorkloadHCLPreservesNativeSourceOutsideLifecycle(t *testing.T) {
	source := "# preserve comment\npath \"kv/data/sample\" { capabilities = [\"read\"] }\n"
	if WorkloadHCL(source) != source {
		t.Fatal("unrelated source changed")
	}
	malformed := `path "broken" {`
	if WorkloadHCL(malformed) != malformed {
		t.Fatal("malformed HCL was hidden from OpenBao validation")
	}
}
