// ---
// relationships:
//   verifies:
//     - command-line-interface
//     - openbao-admin-access
// ---

package command

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func adminCLIInputs(t *testing.T, address string) (string, string) {
	t.Helper()
	directory := t.TempDir()
	configuration := fmt.Sprintf(`openbao:
  address: %s
  namespace: sample
  ui-url: https://vault.example/ui/openbao
  approle:
    role-id: sample
    secret-id-file: /nonexistent/runtime-secret
oidc:
  issuer: https://identity.example
  client-id: controller
  client-secret-file: /nonexistent/controller-client-secret
  redirect-url: https://controller.example/auth/callback
  allowed-groups: [operators]
`, address)
	configPath, tokenPath := filepath.Join(directory, "controller.yml"), filepath.Join(directory, "token")
	if err := os.WriteFile(configPath, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("sample-provisioning-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return configPath, tokenPath
}

func adminArgs(configPath, tokenPath string) []string {
	return []string{"controller", "openbao-admin", "configure", "--config", configPath, "--token-file", tokenPath,
		"--client-id", "sample-client", "--client-secret-stdin", "--kv-v2-mount", "kv", "--token-ttl", "1h", "--token-max-ttl", "8h", "--output", "json"}
}

func TestOpenBaoAdminCLIInputAndFailureRedaction(t *testing.T) {
	const secret = "sentinel-client-secret"
	var configRequests int
	rejectConfig := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Namespace") != "sample" || r.Header.Get("X-Vault-Token") != "sample-provisioning-token" {
			t.Error("wrong explicit provisioning identity")
		}
		switch {
		case r.URL.Path == "/v1/sys/capabilities-self":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"capabilities": []string{"root"}}})
		case r.URL.Path == "/v1/sys/mounts":
			_, _ = io.WriteString(w, `{"data":{"kv/":{"type":"kv","options":{"version":"2"}}}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/policies/acl/namespace-admin":
			w.WriteHeader(404)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/auth/admin-oidc":
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"errors":["No auth engine at admin-oidc/"]}`)
		case r.Method == http.MethodPut && r.URL.Path == "/v1/auth/admin-oidc/config":
			configRequests++
			var data map[string]any
			_ = json.NewDecoder(r.Body).Decode(&data)
			if data["oidc_client_secret"] != secret || data["oidc_client_id"] != "sample-client" {
				t.Error("missing separate OIDC credentials")
			}
			if data["namespace_in_state"] != true || data["oidc_discovery_url"] != "https://identity.example" {
				t.Error("incorrect public configuration")
			}
			if rejectConfig {
				w.WriteHeader(400)
				_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{secret + " sample-provisioning-token raw-upstream"}})
			} else {
				w.WriteHeader(204)
			}
		case r.Method == http.MethodPut && r.URL.Path == "/v1/auth/admin-oidc/role/admin":
			w.WriteHeader(204)
		case (r.Method == http.MethodPost && r.URL.Path == "/v1/sys/auth/admin-oidc") || (r.Method == http.MethodPut && r.URL.Path == "/v1/sys/policies/acl/namespace-admin"):
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected provisioning request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer server.Close()
	path, token := adminCLIInputs(t, server.URL)
	before, _ := os.ReadFile(path)
	var stdout, stderr bytes.Buffer
	status := run(adminArgs(path, token), strings.NewReader(secret+"\n"), &stdout, &stderr, defaultDependencies())
	want := "{\"version\":1,\"command\":\"controller openbao-admin configure\",\"error\":\"invalid\",\"stage\":\"config\",\"partial\":true}\n"
	if status != 1 || stdout.Len() != 0 || stderr.String() != want || configRequests != 1 {
		t.Fatalf("status=%d stdout=%q stderr=%q config-requests=%d", status, stdout.String(), stderr.String(), configRequests)
	}
	for _, value := range []string{secret, "sample-provisioning-token", "raw-upstream"} {
		if strings.Contains(stdout.String()+stderr.String(), value) {
			t.Fatal("credential or upstream body leaked")
		}
	}
	rejectConfig = false
	for _, format := range []string{"json", "human"} {
		stdout.Reset()
		stderr.Reset()
		args := adminArgs(path, token)
		args[len(args)-1] = format
		status = run(args, strings.NewReader(secret+"\n"), &stdout, &stderr, defaultDependencies())
		expected := "OpenBao admin access configure completed in namespace sample (auth admin-oidc, role admin, policy namespace-admin).\n"
		if format == "json" {
			expected = "{\"version\":1,\"action\":\"configure\",\"namespace\":\"sample\",\"auth-mount\":\"admin-oidc\",\"role\":\"admin\",\"policy\":\"namespace-admin\"}\n"
		}
		if status != 0 || stderr.Len() != 0 || stdout.String() != expected {
			t.Fatalf("configure %s = %d %q %q", format, status, stdout.String(), stderr.String())
		}
	}
	after, _ := os.ReadFile(path)
	files, _ := os.ReadDir(filepath.Dir(path))
	if !bytes.Equal(before, after) || len(files) != 2 {
		t.Fatal("CLI persisted state or modified configuration")
	}
}

func TestOpenBaoAdminCLIProjectionsAndTeardown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sys/capabilities-self":
			_, _ = io.WriteString(w, `{"data":{"capabilities":["root"]}}`)
		case "/v1/sys/policies/acl/namespace-admin":
			w.WriteHeader(404)
		case "/v1/sys/auth/admin-oidc":
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"errors":["No auth engine at admin-oidc/"]}`)
		default:
			t.Errorf("remove touched unrelated path %s", r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer server.Close()
	path, token := adminCLIInputs(t, server.URL)
	for _, format := range []string{"human", "json"} {
		status, stdout, stderr := runForTest(t, defaultDependencies(), "controller", "openbao-admin", "remove", "--config", path, "--token-file", token, "--output", format)
		want := "OpenBao admin access remove completed in namespace sample (auth admin-oidc, role admin, policy namespace-admin).\n"
		if format == "json" {
			want = "{\"version\":1,\"action\":\"remove\",\"namespace\":\"sample\",\"auth-mount\":\"admin-oidc\",\"role\":\"admin\",\"policy\":\"namespace-admin\"}\n"
		}
		if status != 0 || stderr != "" || stdout != want {
			t.Fatalf("remove %s = %d %q %q", format, status, stdout, stderr)
		}
	}
}

func TestOpenBaoAdminCLIRejectsMissingOrUnsafeInputs(t *testing.T) {
	base := []string{"configure", "--token-file", "/sample/token", "--client-id", "sample", "--client-secret-stdin", "--kv-v2-mount", "kv", "--token-ttl", "1h", "--token-max-ttl", "8h"}
	for _, args := range [][]string{
		{}, {"unknown"}, {"configure"}, {"remove"}, {"remove", "--token-file", "/sample/token", "--issuer="},
		append(append([]string{}, base...), "--client-secret", "do-not-print"),
		append(append([]string{}, base...), "--groups-claim="),
		append(append([]string{}, base...), "--issuer="),
		append(append([]string{}, base...), "--client-secret-stdin=false"),
		append(append([]string{}, base...), "--config="),
	} {
		var out, errs bytes.Buffer
		status := run(append([]string{"controller", "openbao-admin"}, args...), strings.NewReader("must-not-be-read"), &out, &errs, defaultDependencies())
		if status != 2 || out.Len() != 0 || strings.Contains(errs.String(), "do-not-print") {
			t.Fatalf("invalid usage returned %d %q", status, errs.String())
		}
	}
	for _, value := range []string{"", "\n", "a\nb", "a\x00b", strings.Repeat("a", (64<<10)+1)} {
		if _, err := readAdminSecret(strings.NewReader(value)); err == nil {
			t.Fatal("invalid secret input accepted")
		}
	}
	if got, err := readAdminSecret(strings.NewReader("sample\n")); err != nil || got != "sample" {
		t.Fatal("valid secret input refused")
	}
}
