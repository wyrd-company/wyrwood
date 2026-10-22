// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package policy

import (
	"encoding/json"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
)

func TestLegacyRenewalMatchesOpenBao(t *testing.T) {
	bao := baotest.Start(t)
	for name, source := range map[string]string{
		"absent":                   `path "kv/data/sample" {capabilities=["read"]}`,
		"explicit":                 `path "auth/token/renew-self" {capabilities=["update"]}`,
		"leading-slash":            `path "/auth/token/renew-self" {capabilities=["update"]}`,
		"read":                     `path "auth/token/renew-self" {capabilities=["read"]}`,
		"deny":                     `path "auth/token/renew-self" {capabilities=["deny"]}`,
		"comment":                  `# path "auth/token/renew-self" {capabilities=["update"]}`,
		"glob":                     `path "auth/*" {capabilities=["update"]}`,
		"segment":                  `path "auth/+/renew-self" {capabilities=["update"]}`,
		"specific-deny":            `path "auth/*" {capabilities=["update"]} path "auth/token/renew-self" {capabilities=["deny"]}`,
		"specific-read":            `path "auth/*" {capabilities=["update"]} path "auth/token/renew-self" {capabilities=["read"]}`,
		"specific-allow":           `path "auth/*" {capabilities=["deny"]} path "auth/token/renew-self" {capabilities=["update"]}`,
		"identical-union":          `path "auth/token/renew-self" {capabilities=["read"]} path "auth/token/renew-self" {capabilities=["update"]}`,
		"identical-deny":           `path "auth/token/renew-self" {capabilities=["update"]} path "auth/token/renew-self" {capabilities=["deny"]}`,
		"legacy-write":             `path "auth/token/renew-self" {policy="write"}`,
		"legacy-sudo":              `path "auth/token/renew-self" {policy="sudo"}`,
		"json":                     `{"path":{"auth/token/renew-self":{"capabilities":["update"]}}}`,
		"prefix-priority":          `path "auth/token/*" {capabilities=["update"]} path "auth/+/renew-self" {capabilities=["deny"]}`,
		"segment-priority":         `path "auth/token/+" {capabilities=["update"]} path "auth/token/*" {capabilities=["deny"]}`,
		"literal-plus-prefix":      `path "a+th/token/renew-self" {capabilities=["update"]}`,
		"literal-plus-suffix":      `path "auth/token/renew-sel+" {capabilities=["update"]}`,
		"literal-double-plus":      `path "auth/++/renew-self" {capabilities=["update"]}`,
		"literal-plus-deny":        `path "*" {capabilities=["update"]} path "a+th/token/renew-self" {capabilities=["deny"]}`,
		"literal-plus-before-glob": `path "auth/to+en/*" {capabilities=["update"]}`,
		"segment-and-glob":         `path "auth/+/renew-*" {capabilities=["update"]}`,
		"multiple-segments":        `path "+/+/renew-self" {capabilities=["update"]}`,
		"segment-glob-priority":    `path "auth/+/+" {capabilities=["update"]} path "auth/+/renew-*" {capabilities=["deny"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := bao.Root.Sys().PutPolicy("wyrwood-legacy", source); err != nil {
				t.Fatal(err)
			}
			secret, err := bao.Root.Auth().Token().Create(&api.TokenCreateRequest{Policies: []string{"wyrwood-legacy"}, NoDefaultPolicy: true, TTL: "2m"})
			if err != nil {
				t.Fatal(err)
			}
			caps, err := bao.Root.Sys().Capabilities(secret.Auth.ClientToken, "auth/token/renew-self")
			if err != nil {
				t.Fatal(err)
			}
			allowed := false
			for _, cap := range caps {
				allowed = allowed || cap == "update"
			}
			encoded, _ := json.Marshal(map[string]any{"name": "legacy", "openbao": map[string]any{"policy": source}, "contract": map[string]string{"mount-target": "/run/wyrwood"}})
			p, err := Decode(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if p.AgentRenewal() != allowed {
				t.Fatalf("inferred renewal=%v, OpenBao=%v", p.AgentRenewal(), caps)
			}
			// Publishing the compatible setting must retain actual renewal permission.
			if err := bao.Root.Sys().PutPolicy("wyrwood-legacy", p.PublishedHCL()); err != nil {
				t.Fatal(err)
			}
			caps, err = bao.Root.Sys().Capabilities(secret.Auth.ClientToken, "auth/token/renew-self")
			if err != nil {
				t.Fatal(err)
			}
			published := false
			for _, cap := range caps {
				published = published || cap == "update"
			}
			if published != allowed {
				t.Fatalf("publication changed renewal permission: %v => %v", allowed, caps)
			}
		})
	}
}
