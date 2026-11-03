// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package policy

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const templatedHCL = `# {{binding.only_in_a_comment}} is not read.
path "kv/data/sample/{{binding.slug}}" { capabilities = ["read"] }
path "kv/data/{{binding.area}}/{{binding.slug}}/*" { capabilities = ["list"] }
`

func TestValueNamesReadsOnlyPathStanzaNames(t *testing.T) {
	if got := New("sample", templatedHCL).ValueNames(); !reflect.DeepEqual(got, []string{"area", "slug"}) {
		t.Fatalf("names = %v", got)
	}
	json := `{"path": {"kv/data/{{binding.slug}}": {"capabilities": ["read"]}}}`
	if got := New("sample", json).ValueNames(); !reflect.DeepEqual(got, []string{"slug"}) {
		t.Fatalf("JSON dialect names = %v", got)
	}
	if got := New("sample", `path "kv/data/x" { capabilities = ["read"] }`).ValueNames(); len(got) != 0 {
		t.Fatalf("plain names = %v", got)
	}
}

func TestPolicyRefusesAPlaceholderOpenBaoWouldNeverResolve(t *testing.T) {
	for name, hcl := range map[string]string{
		"spaces":     `path "kv/{{ binding.slug }}" { capabilities = ["read"] }`,
		"upper case": `path "kv/{{binding.Slug}}" { capabilities = ["read"] }`,
		"hyphen":     `path "kv/{{binding.a-b}}" { capabilities = ["read"] }`,
		"no name":    `path "kv/{{binding}}" { capabilities = ["read"] }`,
		"parameter":  `path "kv/x" { capabilities = ["update"] allowed_parameters = { "key" = ["{{binding.slug}}"] } }`,
		"key":        `path "kv/x" { capabilities = ["update"] allowed_parameters = { "{{binding.slug}}" = [] } }`,
		"other":      `other "{{binding.slug}}" { capabilities = ["read"] }`,
	} {
		t.Run(name, func(t *testing.T) {
			err := New("sample", hcl).Validate()
			if err == nil || PartOf(err) != PartOpenBao {
				t.Fatalf("Validate() = %v", err)
			}
		})
	}
	for name, hcl := range map[string]string{
		"comment":     "# {{ binding.note }}\npath \"kv/x\" { capabilities = [\"read\"] }",
		"unparseable": `path "kv/{{binding.slug}}`,
		"identity":    `path "kv/{{identity.entity.id}}" { capabilities = ["read"] }`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := New("sample", hcl).Validate(); err != nil {
				t.Fatalf("Validate() = %v", err)
			}
		})
	}
}

func TestPolicyRefusesTooManyPlaceholders(t *testing.T) {
	var hcl strings.Builder
	for _, name := range strings.Fields("a b c d e f g h i j k l m n o p q") {
		hcl.WriteString(`path "kv/{{binding.` + name + `}}" { capabilities = ["read"] }` + "\n")
	}
	if err := New("sample", hcl.String()).Validate(); err == nil || !strings.Contains(err.Error(), "at most 16") {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestSettingsRefuseAValueThatCouldWidenAGrant(t *testing.T) {
	for _, value := range []string{"*", "al*", "+", "a/b", "..", "../beta", "a.b", "a b", "", "{{identity.entity.id}}", "\n", strings.Repeat("a", 129)} {
		settings := DefaultSettings()
		settings.Values = map[string]string{"slug": value}
		if err := settings.Validate(); err == nil || PartOf(err) != PartSelection {
			t.Fatalf("value %q: Validate() = %v", value, err)
		}
	}
	for _, name := range []string{"", "Slug", "a-b", "1a", "a.b", strings.Repeat("a", 65)} {
		settings := DefaultSettings()
		settings.Values = map[string]string{name: "alpha"}
		if err := settings.Validate(); err == nil || PartOf(err) != PartSelection {
			t.Fatalf("name %q: Validate() = %v", name, err)
		}
	}
	settings := DefaultSettings()
	settings.Values = map[string]string{"slug": "Alpha_1-2", "b": strings.Repeat("a", 128)}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestComposeRefusesAnUnsetValueAndExpandsTheResult(t *testing.T) {
	document := New("sample", templatedHCL)
	settings := DefaultSettings()
	settings.Values = map[string]string{"area": "alpha"}
	_, err := Compose([]Policy{document}, settings)
	if err == nil || PartOf(err) != PartSelection || !strings.Contains(err.Error(), "{{binding.slug}}") || !strings.Contains(err.Error(), "sample") {
		t.Fatalf("Compose() without slug = %v", err)
	}
	settings.Values["slug"] = "beta"
	effective, err := Compose([]Policy{document}, settings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(effective.OpenBao.Policy, `path "kv/data/alpha/beta/*"`) || !strings.Contains(effective.OpenBao.Policy, `path "kv/data/sample/beta"`) {
		t.Fatalf("preview = %s", effective.OpenBao.Policy)
	}
	if effective.Sources[0].HCL != templatedHCL {
		t.Fatal("the source lost its authored text")
	}
}

func TestSettingsWithoutValuesKeepTheirBytes(t *testing.T) {
	data, err := json.Marshal(DefaultSettings())
	if err != nil || strings.Contains(string(data), "values") {
		t.Fatalf("settings = %s, %v", data, err)
	}
	if DefaultSettings().IdentityMetadata() != nil {
		t.Fatal("a binding without values produced metadata")
	}
}

func TestIdentityCompilationAndMetadataAgree(t *testing.T) {
	compiled := IdentityTemplates(`path "kv/{{binding.role_name}}" {}`, "auth_approle_1")
	if compiled != `path "kv/{{identity.entity.aliases.auth_approle_1.metadata.binding_role_name}}" {}` {
		t.Fatalf("compiled = %s", compiled)
	}
	settings := Settings{Values: map[string]string{"role_name": "alpha"}}
	metadata := settings.IdentityMetadata()
	if !reflect.DeepEqual(metadata, map[string]string{"binding_role_name": "alpha"}) {
		t.Fatalf("metadata = %v", metadata)
	}
	for key := range metadata {
		if !strings.Contains(compiled, ".metadata."+key+"}}") {
			t.Fatalf("template does not read key %s", key)
		}
	}
}

func TestMountWarningsCopeWithPlaceholders(t *testing.T) {
	mounts := []string{"kv"}
	if got := MountWarnings(`path "kv/data/{{binding.slug}}/*" { capabilities = ["read"] }`, mounts); len(got) != 0 {
		t.Fatalf("contained path warned: %v", got)
	}
	for _, path := range []string{"{{binding.slug}}/data/x", "kv{{binding.slug}}/data", "auth/{{binding.slug}}/role"} {
		if got := MountWarnings(`path "`+path+`" { capabilities = ["read"] }`, mounts); len(got) != 1 {
			t.Fatalf("path %s warnings = %v", path, got)
		}
	}
}
