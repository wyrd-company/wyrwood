// ---
// relationships:
//   verifies:
//     - policy
//     - web-interface
// ---

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/web/oidctest"
)

func TestPolicyWarningsAPIAndNonblockingSave(t *testing.T) {
	h := startConfiguredHarness(t, time.Hour, func(c *config.Controller) {
		c.OpenBao.SecretMounts = []config.SecretMount{{Path: "sample-data", Type: config.SecretMountKVV2}, {Path: "sample-certs", Type: config.SecretMountOther}}
	})
	client := browser(t)
	h.signIn(t, client, operator, oidctest.TamperNone)
	page := get(t, client, h.site.URL+"/policies/edit")
	token := csrf(t, page.body)
	before := len(h.controller.Events().Recent(100))
	analyze := func(document string) []string {
		t.Helper()
		response, err := client.PostForm(h.site.URL+"/policies/warnings", url.Values{"csrf": {token}, "hcl": {document}})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("API response = %s, %s", response.Status, response.Header.Get("Content-Type"))
		}
		var result struct {
			Warnings []string `json:"warnings"`
		}
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		if result.Warnings == nil {
			t.Fatal("warnings must be a JSON array")
		}
		return result.Warnings
	}
	allowed := policy.StarterHCL + `
path "auth/approle/role/*" { capabilities = ["read"] }
path "transit/sign/+" { capabilities = ["update"] }
path "ssh/sign/*" { capabilities = ["update"] }
path "sample-data/data/+/entry" { capabilities = ["read"] }
path "sample-certs/*" { capabilities = ["read"] }
`
	if warnings := analyze(allowed); len(warnings) != 0 {
		t.Fatalf("expected mount warnings = %v", warnings)
	}
	document := policy.StarterHCL + `path "*" { capabilities = ["read"] }`
	warnings := analyze(document)
	if len(warnings) != 1 || !strings.Contains(warnings[0], `"*"`) {
		t.Fatalf("broad policy warnings = %v", warnings)
	}
	for _, path := range []string{"sys/*", "unlisted/data/*", "sample-data*", "auth/+/role/*", "auth/token/renew-self*"} {
		if warnings := analyze(policy.StarterHCL + `path "` + path + `" { capabilities = ["read"] }`); len(warnings) != 1 {
			t.Fatalf("warnings for %q = %v", path, warnings)
		}
	}
	malformed := policy.StarterHCL + `path "sys/*" {`
	if warnings := analyze(malformed); len(warnings) == 0 || warnings[len(warnings)-1] != policy.MountAnalysisUnavailable {
		t.Fatalf("malformed HCL advice = %v", warnings)
	}
	if len(h.controller.Events().Recent(100)) != before {
		t.Fatal("advisory API recorded an operation")
	}
	policies, err := h.controller.Store().Policies(context.Background())
	if err != nil || len(policies) != 0 {
		t.Fatalf("advisory API changed policies: %v, %v", policies, err)
	}
	form := url.Values{"csrf": {token}, "new": {"yes"}, "name": {"sample"}, "hcl": {document}, "mount-target": {"/run/sample"}}
	saved := post(t, client, h.site.URL+"/policies", form)
	if saved.status != http.StatusOK || !strings.Contains(saved.body, "Policy saved") || !strings.Contains(saved.body, "outside the configured mounts") {
		t.Fatalf("nonblocking save = %d %s", saved.status, saved.body)
	}
	stored, err := h.controller.Store().Policy(context.Background(), "sample")
	if err != nil || stored.Policy.OpenBao.Policy != document {
		t.Fatalf("saved policy = %#v, %v", stored, err)
	}
	var savedEvent bool
	for _, event := range h.controller.Events().Recent(100) {
		if event.Operation == events.OperationPolicySaved && event.Outcome == events.OutcomeOK {
			savedEvent = true
		}
	}
	if !savedEvent {
		t.Fatal("successful save did not retain policy-saved outcome ok")
	}
	// The initial page and API must use the same server-side warning computation.
	var data policyPage
	h.server.fillPolicyPage(&data, stored.Policy)
	if !reflect.DeepEqual(data.Warnings, warnings) {
		t.Fatalf("initial warnings = %v, API = %v", data.Warnings, warnings)
	}
	form.Set("hcl", malformed)
	invalid := post(t, client, h.site.URL+"/policies", form)
	if invalid.status != http.StatusUnprocessableEntity || !strings.Contains(invalid.body, "OpenBao rejected the HCL policy") {
		t.Fatalf("OpenBao validation = %d %s", invalid.status, invalid.body)
	}
	stored, err = h.controller.Store().Policy(context.Background(), "sample")
	if err != nil || stored.Policy.Revision != 1 || stored.Policy.OpenBao.Policy != document {
		t.Fatalf("rejected policy changed persisted source: %#v, %v", stored, err)
	}
	response, err := client.PostForm(h.site.URL+"/policies/warnings", url.Values{"hcl": {document}})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("API without CSRF = %s", response.Status)
	}
	anonymous := get(t, browser(t), h.site.URL+"/policies/warnings")
	if !strings.HasSuffix(anonymous.url, "/sign-in") {
		t.Fatalf("API without session = %s", anonymous.url)
	}
}
