// ---
// relationships:
//   verifies: configuration
// ---

package config

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/schematest"
	"gopkg.in/yaml.v3"
)

func withSecretMounts(entries string) []byte {
	return []byte(strings.Replace(minimalController, "  approle:\n", "  secret-mounts: "+entries+"\n  approle:\n", 1))
}

func TestControllerSecretMounts(t *testing.T) {
	for _, sample := range []struct {
		name, entries string
		want          []SecretMount
	}{
		{"empty", "[]", nil},
		{"configured", "[{path: sample-data, type: kv-v2}, {path: sample-certs, type: other}]", []SecretMount{{Path: "sample-data", Type: SecretMountKVV2}, {Path: "sample-certs", Type: SecretMountOther}}},
	} {
		t.Run(sample.name, func(t *testing.T) {
			document := withSecretMounts(sample.entries)
			parsed, err := ParseController(document)
			if err != nil {
				t.Fatal(err)
			}
			if got := parsed.OpenBao.SecretEngineMounts(); !reflect.DeepEqual(got, sample.want) {
				t.Fatalf("SecretEngineMounts() = %#v, want %#v", got, sample.want)
			}
			if len(sample.want) > 0 {
				copy := parsed.OpenBao.SecretEngineMounts()
				copy[0].Path = "changed"
				if !reflect.DeepEqual(parsed.OpenBao.SecretEngineMounts(), sample.want) {
					t.Fatal("accessor exposed mutable catalog")
				}
			}
			var value any
			if err := yaml.Unmarshal(document, &value); err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(value)
			if err := schematest.Validate(schematest.Compile(t, schematest.ControllerConfiguration), data); err != nil {
				t.Fatal(err)
			}
		})
	}
	parsed, err := ParseController([]byte(minimalController))
	if err != nil || len(parsed.OpenBao.SecretEngineMounts()) != 0 {
		t.Fatalf("default secret mounts = %#v, %v", parsed.OpenBao.SecretEngineMounts(), err)
	}
}

func TestControllerRejectsInvalidSecretMounts(t *testing.T) {
	for name, entries := range map[string]string{
		"empty-path":               "[{path: '', type: kv-v2}]",
		"missing-path":             "[{type: kv-v2}]",
		"leading-slash":            "[{path: /sample, type: kv-v2}]",
		"trailing-slash":           "[{path: sample/, type: kv-v2}]",
		"internal-slash":           "[{path: sample/data, type: kv-v2}]",
		"dot":                      "[{path: '.', type: kv-v2}]",
		"dot-dot":                  "[{path: '..', type: kv-v2}]",
		"embedded-double-dot":      "[{path: sample..data, type: kv-v2}]",
		"space":                    "[{path: 'sample data', type: kv-v2}]",
		"glob":                     "[{path: 'sample*', type: kv-v2}]",
		"wildcard":                 "[{path: '+', type: kv-v2}]",
		"missing-type":             "[{path: sample}]",
		"unknown-type":             "[{path: sample, type: kv-v1}]",
		"unknown-field":            "[{path: sample, type: kv-v2, unexpected: true}]",
		"duplicate":                "[{path: sample, type: kv-v2}, {path: sample, type: kv-v2}]",
		"duplicate-different-type": "[{path: sample, type: kv-v2}, {path: sample, type: other}]",
	} {
		t.Run(name, func(t *testing.T) {
			document := withSecretMounts(entries)
			if _, err := ParseController(document); !errors.Is(err, ErrInvalid) {
				t.Fatalf("ParseController() = %v, want ErrInvalid", err)
			}
			// JSON Schema cannot express uniqueness of one field across objects.
			if name == "duplicate-different-type" {
				return
			}
			var value any
			if err := yaml.Unmarshal(document, &value); err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(value)
			if err := schematest.Validate(schematest.Compile(t, schematest.ControllerConfiguration), data); err == nil {
				t.Fatal("schema accepted invalid secret mounts")
			}
		})
	}
}
