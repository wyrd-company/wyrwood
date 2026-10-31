// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/web/oidctest"
)

func TestSettingsProjectionExcludesCredentialsAndURLSecrets(t *testing.T) {
	c := config.Controller{
		HTTPListen: "127.0.0.1:8080", SSHListen: "0.0.0.0:2222", StateDirectory: "/var/lib/example", SessionTTL: time.Hour,
		OpenBao: config.ControllerOpenBao{
			Address: "https://url-user:url-password@bao.example.com/private-path?token=query-secret#fragment-secret",
			RoleID:  "private-role-id", SecretIDFile: "/private/secret-id", CAFile: "/private/ca-file",
			Namespace: "sample", AppRoleMount: "approle", TransitMount: "transit", SSHMount: "ssh",
			SecretMounts: []config.SecretMount{{Path: "kv", Type: "kv-v2"}},
		},
		OIDC:         config.OIDC{ProviderName: "Sample ID", Issuer: "https://issuer-user:issuer-password@id.example.com/issuer-private?token=issuer-query#issuer-fragment", ClientID: "public-client", ClientSecretFile: "/private/client-secret", RedirectURL: "https://redirect-user:redirect-password@admin.example.com/redirect-private?token=redirect-query#redirect-fragment", GroupsClaim: "groups", AllowedGroups: []string{"operators"}},
		UpdateChecks: config.UpdateChecks{Enabled: true, Interval: 24 * time.Hour, Timeout: 10 * time.Second},
	}
	body, err := json.Marshal(projectSettings(c, "sample-version"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-role-id", "/private/", "url-user", "url-password", "private-path", "query-secret", "fragment-secret", "issuer-user", "issuer-password", "issuer-private", "issuer-query", "issuer-fragment", "redirect-user", "redirect-password", "redirect-private", "redirect-query", "redirect-fragment", "SecretIDFile", "ClientSecretFile", "RoleID"} {
		if strings.Contains(string(body), secret) {
			t.Errorf("projection exposes %q", secret)
		}
	}
	for _, useful := range []string{"127.0.0.1:8080", "0.0.0.0:2222", "1h0m0s", "/var/lib/example", "https://bao.example.com", "https://id.example.com", "https://admin.example.com", "kv (kv-v2)", "public-client", "operators", "Enabled", "24h0m0s", "10s", "sample-version"} {
		if !strings.Contains(string(body), useful) {
			t.Errorf("projection omits %q", useful)
		}
	}
	disabled, _ := json.Marshal(projectSettings(config.Controller{}, "dev"))
	if !strings.Contains(string(disabled), "Disabled") {
		t.Fatal("disabled checks not reported")
	}
	for _, value := range []string{"", ":invalid", "file:///private/path", "javascript:alert(1)"} {
		if got := settingsOrigin(value); got != "" {
			t.Errorf("origin %q = %q", value, got)
		}
	}
}

func TestSettingsRequiresOperatorSessionAndDisplaysEffectiveConfiguration(t *testing.T) {
	h := startConfiguredHarness(t, time.Hour, func(c *config.Controller) {
		c.UpdateChecks = config.UpdateChecks{Interval: 48 * time.Hour, Timeout: 7 * time.Second}
		c.OpenBao.SecretMounts = []config.SecretMount{{Path: "sample", Type: "kv-v2"}}
	})
	client := browser(t)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		request, _ := http.NewRequest(method, h.site.URL+"/settings", nil)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if !strings.Contains(response.Request.URL.Path, "/sign-in") {
			t.Fatalf("%s admitted without a session", method)
		}
	}
	denied := operator
	denied.Groups = []string{"unrelated-group"}
	h.signIn(t, client, denied, oidctest.TamperNone)
	if result := get(t, client, h.site.URL+"/settings"); !strings.Contains(result.url, "/sign-in") {
		t.Fatal("non-operator admitted")
	}
	h.signIn(t, client, operator, oidctest.TamperNone)
	response, err := client.Get(h.site.URL + "/settings")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Request.URL.Path != "/settings" {
		t.Fatalf("settings = %d %s", response.StatusCode, response.Request.URL)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("settings may be cached")
	}
	c := h.controller.Configuration()
	for _, secret := range []string{c.OpenBao.RoleID, c.OpenBao.SecretIDFile, c.OIDC.ClientSecretFile, h.provider.ClientSecret} {
		if secret != "" && strings.Contains(string(raw), secret) {
			t.Fatal("credential exposed in raw response")
		}
	}
	body := renderedPage(t, raw)
	for _, text := range []string{"Settings", "read-only", c.HTTPListen, c.SSHListen, c.StateDirectory, "1h0m0s", "sample (kv-v2)", "platform-admins", "Disabled", "48h0m0s", "7s", `aria-current="page"`, `href="/settings"`} {
		if !strings.Contains(body, text) {
			t.Errorf("settings missing %q", text)
		}
	}
	if result := post(t, client, h.site.URL+"/settings", map[string][]string{"csrf": {csrf(t, body)}}); result.status != http.StatusMethodNotAllowed {
		t.Fatalf("settings POST = %d", result.status)
	}
	h.server.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if result := get(t, client, h.site.URL+"/settings"); !strings.Contains(result.url, "problem=expired") {
		t.Fatal("expired session admitted")
	}
}
