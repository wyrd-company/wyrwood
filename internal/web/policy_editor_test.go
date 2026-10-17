// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/web/oidctest"
)

func TestPolicyEditorChoicesAndKVEndpoint(t *testing.T) {
	harness := startHarness(t, time.Hour)
	bao := harness.controller.Bao
	bao.WriteKV(t, "folder/nested", map[string]any{"value": "sample-value"})
	bao.CreateTransitKey(t, "sample-key", "ed25519")
	bao.CreateSSHRole(t, "sample-role", "sample", "30m")
	anonymous := get(t, browser(t), harness.site.URL+"/policies/kv?mount=kv")
	if !strings.Contains(anonymous.url, "/sign-in") || strings.Contains(anonymous.body, "folder/") {
		t.Fatal("KV paths exposed without an operator session")
	}
	client := browser(t)
	harness.signIn(t, client, operator, oidctest.TamperNone)
	response, err := client.Get(harness.site.URL + "/policies/edit")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	var model struct{ Data policyPage }
	match := pageDataPattern.FindStringSubmatch(string(data))
	if len(match) < 2 {
		t.Fatal("missing policy model")
	}
	if err := json.Unmarshal([]byte(match[1]), &model); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(model.Data.KVMounts, []string{"kv"}) || !reflect.DeepEqual(model.Data.AvailableTransitKeys, []string{"sample-key"}) || !reflect.DeepEqual(model.Data.AvailableCARoles, []string{"sample-role"}) {
		t.Fatalf("editor choices = %#v", model.Data)
	}
	for _, sample := range []struct {
		query  string
		status int
		names  []string
	}{
		{"mount=kv", 200, []string{"folder/"}}, {"mount=kv&prefix=folder%2F", 200, []string{"nested"}},
		{"mount=other", 422, nil}, {"mount=sys%2Fmounts", 422, nil}, {"mount=kv&prefix=..%2Fdata%2F", 422, nil},
	} {
		response, err := client.Get(harness.site.URL + "/policies/kv?" + sample.query)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != sample.status {
			t.Errorf("%s status = %d", sample.query, response.StatusCode)
		}
		if sample.status == http.StatusOK {
			var result struct{ Paths []string }
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(result.Paths, sample.names) {
				t.Errorf("%s paths = %v", sample.query, result.Paths)
			}
		}
		_ = response.Body.Close()
	}
}

func TestPolicyEditorRetainsArbitraryHCLAfterSaveAndValidationFailure(t *testing.T) {
	harness := startHarness(t, time.Hour)
	client := browser(t)
	harness.signIn(t, client, operator, oidctest.TamperNone)
	page := get(t, client, harness.site.URL+"/policies/edit")
	source := "# Hand-written policy\npath \"kv/data/example\" {\n capabilities = [\"read\"]\n min_wrapping_ttl = \"1s\"\n}\n"
	values := url.Values{"csrf": {csrf(t, page.body)}, "new": {"yes"}, "name": {"sample"}, "hcl": {source}, "mount-target": {"/run/wyrwood"}, "env": {"EXAMPLE=sample=value"}, "not-forwardable-transit-keys": {"missing-selector"}}
	saved := post(t, client, harness.site.URL+"/policies", values)
	if !strings.Contains(saved.body, "Policy saved") || !strings.Contains(saved.body, "graphical editor cannot represent") {
		t.Fatalf("save raw HCL: %s", saved.body)
	}
	stored, err := harness.controller.Store().Policy(context.Background(), "sample")
	if err != nil || stored.Policy.OpenBao.Policy != source {
		t.Fatalf("stored HCL = %#v, %v", stored, err)
	}
	if stored.Policy.SSH == nil || !reflect.DeepEqual(stored.Policy.SSH.NotForwardable.TransitKeys, []string{"missing-selector"}) {
		t.Fatal("selector-only identity lost")
	}
	invalid := source + "path \"unfinished\" {"
	values.Set("hcl", invalid)
	values.Set("name", "other")
	failed := post(t, client, harness.site.URL+"/policies", values)
	if failed.status != 422 || !strings.Contains(failed.body, invalid) || !strings.Contains(failed.body, "missing-selector") || !strings.Contains(failed.body, "EXAMPLE") {
		t.Fatalf("failed save lost submitted values: %s", failed.body)
	}
	// Losing catalogue LIST permission must not drop saved choices.
	if err := harness.controller.Bao.Root.Sys().PutPolicy("controller", `path "auth/token/renew-self" { capabilities = ["update"] }`); err != nil {
		t.Fatal(err)
	}
	unavailable := get(t, client, harness.site.URL+"/policies/edit?name=sample")
	if !strings.Contains(unavailable.body, "could not be listed") || !strings.Contains(unavailable.body, "missing-selector") {
		t.Fatalf("unavailable editor lost selectors: %s", unavailable.body)
	}
	response, err := client.Get(harness.site.URL + "/policies/kv?mount=kv")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 422 {
		t.Errorf("denied LIST status = %d", response.StatusCode)
	}
}

func TestPolicyEditorWithoutSecretMounts(t *testing.T) {
	harness := startConfiguredHarness(t, time.Hour, func(configuration *config.Controller) {
		configuration.OpenBao.SecretMounts = nil
	})
	client := browser(t)
	harness.signIn(t, client, operator, oidctest.TamperNone)
	page := get(t, client, harness.site.URL+"/policies/edit")
	if len(harness.controller.Controller.OpenBao().Mounts().KV) != 0 {
		t.Fatal("unconfigured KV mounts available")
	}
	if !strings.Contains(page.body, "Configure kv-v2 entries in openbao.secret-mounts") || !strings.Contains(page.body, "New path") {
		t.Fatal("free-text paths unavailable without a configured catalog")
	}
	response, err := client.Get(harness.site.URL + "/policies/kv?mount=kv")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("unconfigured mount status = %d", response.StatusCode)
	}
}
