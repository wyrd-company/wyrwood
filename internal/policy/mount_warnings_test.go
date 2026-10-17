// ---
// relationships:
//   verifies: policy
// ---

package policy

import (
	"fmt"
	"strings"
	"testing"
)

func TestMountWarnings(t *testing.T) {
	mounts := []string{"auth/sample-role", "sample-transit", "sample-ssh", "sample-data", "sample-certs", "nested/engine"}
	for _, sample := range []struct {
		path string
		warn bool
	}{
		{"sample-data", false}, {"sample-data/*", false}, {"sample-data/data/+/entry", false},
		{"sample-data/+/+/*", false}, {"sample-data/data/pre*", false},
		{"sample-transit/sign/+", false}, {"sample-ssh/sign/*", false},
		{"auth/sample-role/role/*", false}, {"sample-certs/issue/sample", false},
		{"nested/engine/+/*", false}, {"/sample-data/*", false},
		{"auth/token/lookup-self", false}, {"auth/token/renew-self", false}, {"auth/token/revoke-self", false},
		{"*", true}, {"+", true}, {"+/data/*", true}, {"auth/+/role/*", true},
		{"auth/*", true}, {"sample-data*", true}, {"sample-*", true},
		{"sample-data-extra/*", true}, {"unlisted/data/*", true}, {"sys/*", true},
		{"auth/token/renew-self*", true}, {"auth/token/lookup-self/extra", true},
		{"auth/token/+", true}, {"auth/token/*", true}, {"auth/sample-role*", true},
		{"nested/*", true}, {"nested/+/data", true}, {"nested/engine*", true},
	} {
		t.Run(sample.path, func(t *testing.T) {
			document := fmt.Sprintf("path %q { capabilities = [\"read\"] }", sample.path)
			warnings := MountWarnings(document, mounts)
			if (len(warnings) > 0) != sample.warn {
				t.Fatalf("MountWarnings(%q) = %v, want warning %v", sample.path, warnings, sample.warn)
			}
		})
	}
	if got := MountWarnings(StarterHCL, nil); len(got) != 0 {
		t.Fatalf("token self-path warnings = %v", got)
	}
}

func TestMountWarningsParseHCL(t *testing.T) {
	document := `# path "*" { capabilities = ["read"] }
/* path "sys/*" { capabilities = ["update"] } */
path "sample-data/data/+/entry" {
  capabilities = ["read"]
  allowed_parameters = { "sample" = ["path \"*\" {}"] }
}
path "\u0073ys/*" { capabilities = ["read"] }
path "sys/*" { capabilities = ["update"] }
`
	warnings := MountWarnings(document, []string{"sample-data"})
	if len(warnings) != 1 || !strings.Contains(warnings[0], `"sys/*"`) {
		t.Fatalf("parsed warnings = %v", warnings)
	}
	jsonPolicy := `{"path":{"sample-data/*":{"capabilities":["read"]},"sys/*":{"capabilities":["read"]}}}`
	if warnings := MountWarnings(jsonPolicy, []string{"sample-data"}); len(warnings) != 1 || !strings.Contains(warnings[0], `"sys/*"`) {
		t.Fatalf("JSON policy warnings = %v", warnings)
	}
	for _, document := range []string{`path "sys/*" {`, `path "sys/*" { capabilities = [ }`} {
		if warnings := MountWarnings(document, nil); len(warnings) != 1 || warnings[0] != MountAnalysisUnavailable {
			t.Fatalf("malformed HCL warnings = %v", warnings)
		}
	}
}
