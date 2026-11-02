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

func TestValidationNamesThePartItIsAbout(t *testing.T) {
	valid := func(change func(*Policy)) Policy {
		document := New("sample", "")
		change(&document)
		return document
	}
	for _, test := range []struct {
		name     string
		document Policy
		want     Part
	}{
		{"name", valid(func(p *Policy) { p.Name = "Not Valid" }), PartName},
		{"HCL size", valid(func(p *Policy) { p.OpenBao.Policy = strings.Repeat("#", maximumHCLBytes+1) }), PartOpenBao},
		{"transit key", valid(func(p *Policy) { p.SSH = &SSH{TransitKeys: []string{"not/valid"}} }), PartSSH},
		{"SSH role", valid(func(p *Policy) { p.SSH = &SSH{CARoles: []string{"not/valid", "not/valid"}} }), PartSSH},
		{"not forwardable", valid(func(p *Policy) { p.SSH = &SSH{NotForwardable: &SSHIdentityNames{TransitKeys: []string{"not/valid"}}} }), PartSSH},
		{"mount target", valid(func(p *Policy) { p.Contract.MountTarget = "relative" }), PartContract},
		{"environment", valid(func(p *Policy) { p.Contract.Env = map[string]string{"1BAD": "value"} }), PartContract},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := PartOf(test.document.Validate()); got != test.want {
				t.Fatalf("part = %q, want %q", got, test.want)
			}
		})
	}
	for _, test := range []Settings{{TokenTTL: "soon"}, {TokenMaxTTL: "soon"}, {TokenTTL: "9h", TokenMaxTTL: "1h"}, {Enforcement: "other"}} {
		if got := PartOf(test.Validate()); got != PartSettings {
			t.Fatalf("%#v part = %q", test, got)
		}
	}
}

func TestCompositionNamesThePartItIsAbout(t *testing.T) {
	elsewhere := New("elsewhere", "")
	elsewhere.Contract.MountTarget = "/run/elsewhere"
	envA, envB := New("env-a", ""), New("env-b", "")
	envA.Contract.Env, envB.Contract.Env = map[string]string{"SHARED": "a"}, map[string]string{"SHARED": "b"}
	first, second := New("first", ""), New("second", "")
	first.SSH, second.SSH = &SSH{}, &SSH{}
	for index := range maximumIdentityNames {
		first.SSH.TransitKeys = append(first.SSH.TransitKeys, fmt.Sprintf("first-%d", index))
		second.SSH.TransitKeys = append(second.SSH.TransitKeys, fmt.Sprintf("second-%d", index))
	}
	for _, test := range []struct {
		name     string
		policies []Policy
		want     Part
	}{
		{"nothing selected", nil, PartSelection},
		{"selected twice", []Policy{New("sample", ""), New("sample", "")}, PartSelection},
		{"mount conflict", []Policy{New("sample", ""), elsewhere}, PartContract},
		{"environment conflict", []Policy{envA, envB}, PartContract},
		{"too many identities", []Policy{first, second}, PartSSH},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compose(test.policies, Settings{})
			if got := PartOf(err); got != test.want {
				t.Fatalf("part = %q, want %q (%v)", got, test.want, err)
			}
		})
	}
}

func TestPartOfAnotherErrorIsEmpty(t *testing.T) {
	if got := PartOf(fmt.Errorf("wrapped: %w", partError(PartKey, "sample"))); got != PartKey {
		t.Fatalf("wrapped part = %q", got)
	}
	if got := PartOf(fmt.Errorf("sample")); got != "" {
		t.Fatalf("part = %q", got)
	}
}
