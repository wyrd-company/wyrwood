// ---
// relationships:
//   verifies: configuration
// ---

package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/wyrd-company/wyrwood/internal/schematest"
)

const fullAgent = `controller:
  url: ssh://controller.example.internal:2222
engine:
  socket: /var/run/docker.sock
  allow-recreate: true
consumers:
  root: /run/wyrwood/containers/
timeouts:
  engine: 5s
  controller: 500ms
  openbao: 30s
  sign: 2m
`

const minimalController = `openbao:
  address: https://bao.example.internal:8200
  approle:
    role-id: controller-role
    secret-id-file: /run/secrets/openbao-secret-id
oidc:
  issuer: https://id.example.internal
  client-id: wyrwood
  client-secret-file: /run/secrets/oidc-client-secret
  redirect-url: https://wyrwood.example.internal/auth/callback
  allowed-groups: [wyrwood-operators]
`

func TestAgentDefaultsAndBounds(t *testing.T) {
	minimal, err := ParseAgent([]byte("controller:\n  url: ssh://controller\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := Agent{
		ControllerURL: "ssh://controller", ControllerAddress: "controller:22",
		EngineSocket: "/var/run/docker.sock", EngineProxySocket: DefaultEngineProxySocket, ConsumerRoot: "/run/wyrwood/containers",
		EngineTimeout: 10 * time.Second, ControllerTimeout: 10 * time.Second,
		OpenBaoTimeout: 10 * time.Second, SignTimeout: 30 * time.Second,
	}
	if !reflect.DeepEqual(minimal, want) {
		t.Fatalf("ParseAgent(minimal) = %#v", minimal)
	}
	full, err := ParseAgent([]byte(fullAgent))
	if err != nil {
		t.Fatal(err)
	}
	if !full.AllowRecreate || full.ControllerAddress != "controller.example.internal:2222" ||
		full.ConsumerRoot != "/run/wyrwood/containers" || full.SignTimeout != 2*time.Minute || full.ControllerTimeout != 500*time.Millisecond {
		t.Fatalf("ParseAgent(full) = %#v", full)
	}
}

func TestAgentRejections(t *testing.T) {
	for name, document := range map[string]string{
		"missing-controller": "engine:\n  allow-recreate: true\n",
		"url-scheme":         "controller:\n  url: https://controller\n",
		"url-path":           "controller:\n  url: ssh://controller/path\n",
		"url-user":           "controller:\n  url: ssh://root@controller\n",
		"unknown":            "controller:\n  url: ssh://controller\nupstream: /tmp/agent.sock\n",
		"relative-socket":    "controller:\n  url: ssh://controller\nengine:\n  socket: docker.sock\n",
		"short-timeout":      "controller:\n  url: ssh://controller\ntimeouts:\n  engine: 50ms\n",
		"long-timeout":       "controller:\n  url: ssh://controller\ntimeouts:\n  engine: 31s\n",
		"long-sign":          "controller:\n  url: ssh://controller\ntimeouts:\n  sign: 3m\n",
		"duration-syntax":    "controller:\n  url: ssh://controller\ntimeouts:\n  engine: 1h\n",
		"two-documents":      "controller:\n  url: ssh://controller\n---\ncontroller:\n  url: ssh://other\n",
		"empty":              "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAgent([]byte(document)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("ParseAgent() = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestControllerDefaults(t *testing.T) {
	controller, err := ParseController([]byte(minimalController))
	if err != nil {
		t.Fatal(err)
	}
	if controller.HTTPListen != "127.0.0.1:8080" || controller.SSHListen != "0.0.0.0:2222" ||
		controller.StateDirectory != "/var/lib/wyrwood" || controller.SessionTTL != 12*time.Hour ||
		controller.OpenBao.AppRoleMount != "approle" || controller.OpenBao.TransitMount != "transit" ||
		controller.OpenBao.SSHMount != "ssh" || controller.OIDC.GroupsClaim != "groups" ||
		controller.OIDC.ProviderName != "your identity provider" {
		t.Fatalf("ParseController() = %#v", controller)
	}
}

func TestControllerRejections(t *testing.T) {
	replace := func(old, new string) string { return strings.Replace(minimalController, old, new, 1) }
	for name, document := range map[string]string{
		"inline-secret-id":     replace("    secret-id-file: /run/secrets/openbao-secret-id\n", "    secret-id-file: /run/secrets/openbao-secret-id\n    secret-id: inline\n"),
		"inline-client-secret": replace("  client-id: wyrwood\n", "  client-id: wyrwood\n  client-secret: inline\n"),
		"no-allowed-groups":    replace("  allowed-groups: [wyrwood-operators]\n", "  allowed-groups: []\n"),
		"missing-groups":       replace("  allowed-groups: [wyrwood-operators]\n", ""),
		"duplicate-groups":     replace("[wyrwood-operators]", "[a, a]"),
		"relative-redirect":    replace("https://wyrwood.example.internal/auth/callback", "/auth/callback"),
		"redirect-path":        replace("/auth/callback", "/callback"),
		"missing-oidc":         strings.Split(minimalController, "oidc:")[0],
		"relative-secret-file": replace("/run/secrets/openbao-secret-id", "secret-id"),
		"session-ttl-short":    minimalController + "http:\n  session-ttl: 5m\n",
		"session-ttl-long":     minimalController + "http:\n  session-ttl: 25h\n",
		"listen":               minimalController + "ssh:\n  listen: nowhere\n",
		"mount":                replace("    role-id: controller-role\n", "    role-id: controller-role\n    mount: /approle/\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseController([]byte(document)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("ParseController() = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestControllerOpenBaoUIURL(t *testing.T) {
	withUI := func(namespace, uiURL string) string {
		return strings.Replace(minimalController, "  approle:\n",
			"  namespace: "+namespace+"\n  ui-url: "+uiURL+"\n  approle:\n", 1)
	}
	for name, sample := range map[string]struct {
		namespace, uiURL, base, secrets, callback string
	}{
		"internal-address-different-host": {"wyrwood", "https://vault.example/ui/openbao",
			"https://vault.example/ui/openbao",
			"https://vault.example/ui/openbao/secrets?namespace=wyrwood",
			"https://vault.example/ui/openbao/auth/admin-oidc/oidc/callback"},
		"prefix-port-trailing-slash": {"wyrwood", "https://proxy.example:8443/tools/bao/ui/cluster-a/",
			"https://proxy.example:8443/tools/bao/ui/cluster-a",
			"https://proxy.example:8443/tools/bao/ui/cluster-a/secrets?namespace=wyrwood",
			"https://proxy.example:8443/tools/bao/ui/cluster-a/auth/admin-oidc/oidc/callback"},
		"nested-namespace": {"/team/wyrwood/", "https://vault.example/ui/openbao",
			"https://vault.example/ui/openbao",
			"https://vault.example/ui/openbao/secrets?namespace=team%2Fwyrwood",
			"https://vault.example/ui/openbao/auth/admin-oidc/oidc/callback"},
		"loopback-http": {"wyrwood", "http://127.0.0.1:8200/ui/vault",
			"http://127.0.0.1:8200/ui/vault",
			"http://127.0.0.1:8200/ui/vault/secrets?namespace=wyrwood",
			"http://127.0.0.1:8200/ui/vault/auth/admin-oidc/oidc/callback"},
	} {
		t.Run(name, func(t *testing.T) {
			controller, err := ParseController([]byte(withUI(sample.namespace, sample.uiURL)))
			if err != nil {
				t.Fatal(err)
			}
			openbao := controller.OpenBao
			if openbao.Address != "https://bao.example.internal:8200" || openbao.UIURL != sample.base ||
				openbao.UISecretsURL() != sample.secrets || openbao.UICallbackURL() != sample.callback {
				t.Fatalf("UI URLs = %q, %q, %q", openbao.UIURL, openbao.UISecretsURL(), openbao.UICallbackURL())
			}
		})
	}
	for name, document := range map[string]string{
		"absent": minimalController,
		"empty":  withUI("wyrwood", `""`),
		"absent-keeps-unusual-namespace": strings.Replace(minimalController, "  approle:\n",
			"  namespace: root\n  approle:\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			controller, err := ParseController([]byte(document))
			if err != nil {
				t.Fatal(err)
			}
			if controller.OpenBao.UIURL != "" || controller.OpenBao.UISecretsURL() != "" || controller.OpenBao.UICallbackURL() != "" {
				t.Fatalf("UI URLs present for %#v", controller.OpenBao)
			}
		})
	}
	for name, document := range map[string]string{
		"public-http":        withUI("wyrwood", "http://vault.example/ui/openbao"),
		"relative":           withUI("wyrwood", "/ui/openbao"),
		"other-scheme":       withUI("wyrwood", "ftp://vault.example/ui/openbao"),
		"userinfo":           withUI("wyrwood", "https://user@vault.example/ui/openbao"),
		"query":              withUI("wyrwood", "https://vault.example/ui/openbao?namespace=other"),
		"empty-query":        withUI("wyrwood", "https://vault.example/ui/openbao?"),
		"fragment":           withUI("wyrwood", "https://vault.example/ui/openbao#secrets"),
		"percent-escape":     withUI("wyrwood", "https://vault.example/ui/open%2Fbao"),
		"dot-segment":        withUI("wyrwood", "https://vault.example/ui/../openbao"),
		"empty-segment":      withUI("wyrwood", "https://vault.example/ui//openbao"),
		"no-namespace":       strings.Replace(minimalController, "  approle:\n", "  ui-url: https://vault.example/ui/openbao\n  approle:\n", 1),
		"root-namespace":     withUI("root", "https://vault.example/ui/openbao"),
		"slash-namespace":    withUI("/", "https://vault.example/ui/openbao"),
		"traversal":          withUI("team/../wyrwood", "https://vault.example/ui/openbao"),
		"dot-namespace":      withUI("team/./wyrwood", "https://vault.example/ui/openbao"),
		"empty-ns-segment":   withUI("team//wyrwood", "https://vault.example/ui/openbao"),
		"percent-namespace":  withUI("team%2Fwyrwood", "https://vault.example/ui/openbao"),
		"query-in-namespace": withUI(`"wyrwood&namespace=root"`, "https://vault.example/ui/openbao"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseController([]byte(document)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("ParseController() = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestDocumentsValidateAgainstSchemas(t *testing.T) {
	for _, sample := range []struct {
		asset    schematest.Asset
		document string
	}{
		{schematest.AgentConfiguration, fullAgent},
		{schematest.AgentConfiguration, "controller:\n  url: ssh://controller\n"},
		{schematest.ControllerConfiguration, minimalController},
		{schematest.ControllerConfiguration, strings.Replace(minimalController, "  approle:\n",
			"  namespace: wyrwood\n  ui-url: https://vault.example/ui/openbao\n  approle:\n", 1)},
	} {
		schema := schematest.Compile(t, sample.asset)
		var value any
		if err := yaml.Unmarshal([]byte(sample.document), &value); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := schematest.Validate(schema, data); err != nil {
			t.Fatalf("%s does not validate: %v", data, err)
		}
	}
}

func TestReadSecretFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "secret")
	if err := os.WriteFile(path, []byte("value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if value, err := ReadSecretFile(path); err != nil || value != "value" {
		t.Fatalf("ReadSecretFile() = %q, %v", value, err)
	}
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecretFile(path); err == nil {
		t.Fatal("ReadSecretFile(empty) = nil")
	}
}

func TestWriteAgentControllerURLPreservesOtherFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "agent.yml")
	if err := WriteAgentControllerURL(path, "ssh://first:2222"); err != nil {
		t.Fatal(err)
	}
	created, err := LoadAgent(path)
	if err != nil || created.ControllerURL != "ssh://first:2222" {
		t.Fatalf("LoadAgent() = %#v, %v", created, err)
	}
	if err := os.WriteFile(path, []byte("# site settings\ncontroller:\n  url: ssh://first:2222\nengine:\n  allow-recreate: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteAgentControllerURL(path, "ssh://second"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	updated, err := ParseAgent(data)
	if err != nil || updated.ControllerURL != "ssh://second" || !updated.AllowRecreate || !strings.Contains(string(data), "# site settings") {
		t.Fatalf("updated document = %q, %#v, %v", data, updated, err)
	}
	if err := WriteAgentControllerURL(path, "http://bad"); err == nil {
		t.Fatal("WriteAgentControllerURL(invalid) = nil")
	}
}

func TestProxySocketConfiguration(t *testing.T) {
	for _, entry := range []string{"  proxy-socket: relative.sock\n", "  socket: /same.sock\n  proxy-socket: /same.sock\n"} {
		if _, err := ParseAgent([]byte("controller:\n  url: ssh://controller.example\nengine:\n" + entry)); err == nil {
			t.Fatal("accepted unsafe socket configuration")
		}
	}
	doc := []byte("controller:\n  url: ssh://controller.example\nengine:\n  socket: /custom/engine.sock\n  proxy-socket: /custom/proxy/engine.sock\n")
	cfg, err := ParseAgent(doc)
	if err != nil || cfg.EngineSocket != "/custom/engine.sock" || cfg.EngineProxySocket != "/custom/proxy/engine.sock" {
		t.Fatal(cfg, err)
	}
}
