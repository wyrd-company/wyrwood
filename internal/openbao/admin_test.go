// ---
// relationships:
//   verifies: openbao-admin-access
// ---

package openbao

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/web/oidctest"
)

const provisionPolicy = `
path "sys/mounts" { capabilities = ["read"] }
path "sys/capabilities-self" { capabilities = ["update"] }
path "sys/auth/admin-oidc" { capabilities = ["read", "update", "delete", "sudo"] }
path "sys/auth/admin-oidc/tune" { capabilities = ["read", "update", "sudo"] }
path "auth/admin-oidc/config" { capabilities = ["read", "create", "update"] }
path "auth/admin-oidc/role" { capabilities = ["list"] }
path "auth/admin-oidc/role/admin" { capabilities = ["read", "create", "update", "delete"] }
path "sys/policies/acl/namespace-admin" { capabilities = ["read", "create", "update", "delete"] }
`

func provisioner(t *testing.T, server *baotest.Server) *api.Client {
	t.Helper()
	if err := server.Root.Sys().PutPolicy("setup", provisionPolicy); err != nil {
		t.Fatal(err)
	}
	token, err := server.Root.Auth().Token().Create(&api.TokenCreateRequest{Policies: []string{"setup"}, NoDefaultPolicy: true, TTL: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewAdminClient(Endpoint{Address: server.Address, Namespace: server.Namespace}, token.Auth.ClientToken)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func adminSettings(provider *oidctest.Provider) AdminSettings {
	return AdminSettings{Issuer: provider.Issuer(), ClientID: provider.ClientID, GroupsClaim: "groups",
		RedirectURL: "https://vault.example/ui/openbao/auth/admin-oidc/oidc/callback", KVMounts: []string{"kv"}, TokenTTL: time.Hour, TokenMaxTTL: 8 * time.Hour}
}

func TestAdminPolicyOnlyGrantsSelectedKV(t *testing.T) {
	server := baotest.Start(t)
	ctx := context.Background()
	policy, err := AdminPolicy([]string{"kv"})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Root.Sys().PutPolicy(AdminPolicyName, policy); err != nil {
		t.Fatal(err)
	}
	issued, err := server.Root.Auth().Token().Create(&api.TokenCreateRequest{Policies: []string{AdminPolicyName}, NoDefaultPolicy: true, TTL: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	client, _ := withToken(server.Root, issued.Auth.ClientToken)
	for path, want := range map[string][]string{
		"kv/config": {"read"}, "kv/data/example": {"create", "read", "update", "delete"},
		"kv/metadata": {"list"}, "kv/metadata/example": {"create", "read", "update", "delete", "list"},
		"kv/delete/example": {"update"}, "kv/undelete/example": {"update"}, "kv/destroy/example": {"update"},
		"auth/token/lookup-self": {"read"}, "auth/token/renew-self": {"update"}, "auth/token/revoke-self": {"update"},
		"sys/capabilities-self": {"update"}, "sys/internal/ui/resultant-acl": {"read"},
	} {
		caps, err := client.Sys().CapabilitiesSelf(path)
		slices.Sort(caps)
		slices.Sort(want)
		if err != nil || !reflect.DeepEqual(caps, want) {
			t.Errorf("granted %s = %v, %v; want %v", path, caps, err, want)
		}
	}
	for _, path := range []string{
		"sys/policies/acl/controller", "sys/policies/acl/wyrwood-sample", "sys/policies/acl/namespace-admin", "sys/policy/controller",
		"auth/approle/role/controller", "auth/approle/role/controller/secret-id", "auth/approle/role/wyrwood-sample",
		"sys/auth/admin-oidc", "sys/auth/admin-oidc/tune", "auth/admin-oidc/config", "auth/admin-oidc/role/admin",
		"sys/mounts/kv", "sys/mounts/another", "identity/entity", "auth/token/create", "sys/namespaces/example",
		"other/data/example", "transit/keys/example", "ssh/roles/example", "kv/config/extra",
	} {
		t.Run("deny/"+path, func(t *testing.T) {
			caps, err := client.Sys().CapabilitiesSelf(path)
			if err != nil || !reflect.DeepEqual(caps, []string{"deny"}) {
				t.Fatalf("capabilities = %v, %v; want deny", caps, err)
			}
			_, err = client.Logical().WriteWithContext(ctx, path, map[string]any{"policy": everything})
			if CategoryOf(categorize(err)) != CategoryDenied {
				t.Fatalf("write did not get permission denied: %v", categorize(err))
			}
		})
	}
	for _, path := range []string{"sys/policies/acl/controller", "sys/policies/acl/wyrwood-sample", "auth/approle/role/controller"} {
		if _, err := client.Logical().Read(path); CategoryOf(categorize(err)) != CategoryDenied {
			t.Fatalf("read %s not denied", path)
		}
	}
	// Exercise each KV lifecycle operation, not just the policy's appearance.
	if _, err := client.KVv2("kv").Put(ctx, "example", map[string]any{"value": "first"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.KVv2("kv").Put(ctx, "example", map[string]any{"value": "second"}); err != nil {
		t.Fatal(err)
	}
	if got, err := client.KVv2("kv").Get(ctx, "example"); err != nil || got.Data["value"] != "second" {
		t.Fatal("read failed")
	}
	if _, err := client.Logical().List("kv/metadata"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Logical().Delete("kv/data/example"); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"undelete", "delete", "undelete", "destroy"} {
		if _, err := client.Logical().Write("kv/"+op+"/example", map[string]any{"versions": []int{2}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.Logical().Delete("kv/metadata/example"); err != nil {
		t.Fatal(err)
	}
	rootClient, _ := withToken(server.TopLevel, issued.Auth.ClientToken)
	if _, err := rootClient.Logical().Write("sys/policies/acl/escape", map[string]any{"policy": everything}); err == nil {
		t.Fatal("admin escaped namespace")
	}
}

func loginAdmin(t *testing.T, client *api.Client, settings AdminSettings) (*api.Secret, error) {
	t.Helper()
	ctx := context.Background()
	start, err := client.Logical().Write("auth/"+AdminAuthMount+"/oidc/auth_url", map[string]any{"role": AdminRole, "redirect_uri": settings.RedirectURL})
	if err != nil || start == nil {
		return nil, fmt.Errorf("auth-url failed")
	}
	authURL, _ := start.Data["auth_url"].(string)
	if authURL == "" {
		return nil, fmt.Errorf("auth-url empty")
	}
	browser := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := browser.Get(authURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	callback, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		return nil, err
	}
	values := callback.Query()
	state, _, _ := strings.Cut(values.Get("state"), ",ns=")
	return client.Logical().ReadWithDataWithContext(ctx, "auth/"+AdminAuthMount+"/oidc/callback", map[string][]string{"state": {state}, "code": {values.Get("code")}})
}

func TestAdminOIDCSetupAdmissionAndTeardown(t *testing.T) {
	server, manager := testManager(t)
	provider := oidctest.Start()
	defer provider.Close()
	cfg := adminSettings(provider)
	client := provisioner(t, server)
	ctx := context.Background()
	controllerPolicy, _ := server.Root.Sys().GetPolicy(baotest.ControllerName)
	controller, err := manager.authorized(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := ConfigureAdmin(ctx, controller, cfg, provider.ClientSecret); err == nil {
		t.Fatal("controller configured auth")
	}
	if err := ConfigureAdmin(ctx, client, cfg, provider.ClientSecret); err != nil {
		t.Fatal(err)
	}
	if err := ConfigureAdmin(ctx, client, cfg, provider.ClientSecret); err != nil {
		t.Fatalf("rerun: %v", err)
	}
	role, err := server.Root.Logical().Read("auth/" + AdminAuthMount + "/role/" + AdminRole)
	if err != nil || role == nil {
		t.Fatal("role missing")
	}
	for key, want := range map[string]string{"role_type": "oidc", "user_claim": "sub", "groups_claim": "groups", "bound_claims_type": "string", "token_no_default_policy": "true", "token_explicit_max_ttl": "28800", "token_ttl": "3600", "verbose_oidc_logging": "false"} {
		if fmt.Sprint(role.Data[key]) != want {
			t.Errorf("role %s = %v, want %s", key, role.Data[key], want)
		}
	}
	if fmt.Sprint(role.Data["bound_claims"]) != "map[groups:[wyrwood_admins]]" {
		t.Error("group constraint missing")
	}
	configResponse, _ := server.Root.Logical().Read("auth/" + AdminAuthMount + "/config")
	if configResponse == nil || configResponse.Data["namespace_in_state"] != true || configResponse.Data["default_role"] != AdminRole {
		t.Fatal("namespace OIDC config mismatch")
	}
	for _, scenario := range []struct {
		name    string
		account oidctest.Account
		tamper  oidctest.Tamper
		allowed bool
	}{
		{"allowed", oidctest.Account{Subject: "sample", Groups: []string{"unrelated", "wyrwood_admins"}}, "", true},
		{"missing", oidctest.Account{Subject: "sample", OmitGroups: true}, "", false},
		{"malformed", oidctest.Account{Subject: "sample", Groups: nil}, "", false},
		{"unrelated", oidctest.Account{Subject: "sample", Groups: []string{"unrelated"}}, "", false},
		{"wrong-case", oidctest.Account{Subject: "sample", Groups: []string{"WYRWOOD_ADMINS"}}, "", false},
		{"audience", oidctest.Account{Subject: "sample", Groups: []string{"wyrwood_admins"}}, oidctest.TamperAudience, false},
		{"issuer", oidctest.Account{Subject: "sample", Groups: []string{"wyrwood_admins"}}, oidctest.TamperIssuer, false},
		{"expiry", oidctest.Account{Subject: "sample", Groups: []string{"wyrwood_admins"}}, oidctest.TamperExpired, false},
		{"signature", oidctest.Account{Subject: "sample", Groups: []string{"wyrwood_admins"}}, oidctest.TamperSignature, false},
		{"nonce", oidctest.Account{Subject: "sample", Groups: []string{"wyrwood_admins"}}, oidctest.TamperNonce, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			provider.SignIn(scenario.account, scenario.tamper)
			logged, err := loginAdmin(t, client, cfg)
			if !scenario.allowed {
				if err == nil && logged != nil && logged.Auth != nil {
					t.Fatal("invalid identity admitted")
				}
				return
			}
			if err != nil || logged == nil || logged.Auth == nil {
				t.Fatalf("allowed login failed: %v", err)
			}
			if !reflect.DeepEqual(logged.Auth.Policies, []string{AdminPolicyName}) || len(logged.Auth.IdentityPolicies) != 0 {
				t.Fatalf("unexpected policies: %v", logged.Auth.Policies)
			}
		})
	}
	provider.SignIn(oidctest.Account{Subject: "sample", Groups: []string{"wyrwood_admins"}}, "")
	wrongCallback := cfg
	wrongCallback.RedirectURL = "https://other.example/ui/openbao/auth/admin-oidc/oidc/callback"
	if logged, err := loginAdmin(t, client, wrongCallback); err == nil && logged != nil && logged.Auth != nil {
		t.Fatal("unregistered callback admitted")
	}
	logged, err := loginAdmin(t, client, cfg)
	if err != nil || logged == nil || logged.Auth == nil {
		t.Fatalf("login failed: %v", err)
	}
	human, _ := withToken(server.Root, logged.Auth.ClientToken)
	for _, path := range []string{"sys/policies/acl/controller", "sys/policies/acl/wyrwood-sample", "auth/approle/role/controller", "sys/auth/admin-oidc", "sys/mounts/kv"} {
		caps, err := human.Sys().CapabilitiesSelf(path)
		if err != nil || !reflect.DeepEqual(caps, []string{"deny"}) {
			t.Fatalf("OIDC token reached %s: %v", path, caps)
		}
	}
	if _, err := human.Auth().Token().RenewSelf(0); err != nil {
		t.Fatal("human cannot renew")
	}
	server.WriteKV(t, "preserved", map[string]any{"value": "sample"})
	if err := RemoveAdmin(ctx, client); err != nil {
		t.Fatal(err)
	}
	if _, err := human.Auth().Token().LookupSelf(); err == nil {
		t.Fatal("teardown left OIDC token valid")
	}
	if inspected, err := server.Root.Auth().Token().Lookup(logged.Auth.ClientToken); err == nil && inspected != nil {
		t.Fatal("teardown removed permissions but left OIDC token stored")
	}
	if err := RemoveAdmin(ctx, client); err != nil {
		t.Fatal("remove not idempotent")
	}
	gotPolicy, _ := server.Root.Sys().GetPolicy(baotest.ControllerName)
	if gotPolicy != controllerPolicy {
		t.Fatal("controller policy changed")
	}
	if _, err := controller.Auth().Token().LookupSelf(); err != nil {
		t.Fatal("controller session revoked")
	}
	if _, err := server.Root.KVv2("kv").Get(ctx, "preserved"); err != nil {
		t.Fatal("secret deleted")
	}
}

func TestAdminPolicyRejectsUnsafeMounts(t *testing.T) {
	for _, mounts := range [][]string{nil, {""}, {"../kv"}, {"kv/../other"}, {"kv//other"}, {"kv/"}, {"/kv"}, {"kv*"}, {"kv/+"}, {"kv\" {}"}, {"sys"}, {"auth/approle"}, {"identity"}, {"cubbyhole"}, {"kv", "kv"}} {
		if _, err := AdminPolicy(mounts); err == nil {
			t.Fatalf("accepted mounts %q", mounts)
		}
	}
	one, _ := AdminPolicy([]string{"a/b", "kv"})
	two, _ := AdminPolicy([]string{"kv", "a/b"})
	if one != two || !strings.Contains(one, `path "a/b/data/*"`) {
		t.Fatal("policy not deterministic for nested mounts")
	}
}

func TestAdminProvisioningRequiresExplicitSafeIdentity(t *testing.T) {
	for _, endpoint := range []Endpoint{
		{Address: "https://vault.example", Namespace: ""}, {Address: "http://vault.example", Namespace: "example"},
		{Address: "https://user:pass@vault.example", Namespace: "example"}, {Address: "https://vault.example?token=sample", Namespace: "example"},
		{Address: "https://vault.example", Namespace: "root"}, {Address: "https://vault.example", Namespace: "example/../other"},
	} {
		if _, err := NewAdminClient(endpoint, "sample"); err == nil {
			t.Fatal("accepted unsafe provisioning endpoint")
		}
	}
	t.Setenv("BAO_ADDR", "https://other.example")
	t.Setenv("BAO_TOKEN", "ambient")
	t.Setenv("BAO_NAMESPACE", "other")
	client, err := NewAdminClient(Endpoint{Address: "https://vault.example", Namespace: "sample/nested"}, "explicit")
	if err != nil || client.Address() != "https://vault.example" || client.Token() != "explicit" || client.Namespace() != "sample/nested" {
		t.Fatal("ambient credentials changed provisioning client")
	}
}

func TestAdminSetupPreflightsAndPreservesUnownedResources(t *testing.T) {
	for _, scenario := range []string{"wrong-engine", "unowned-policy", "unowned-auth", "extra-role"} {
		t.Run(scenario, func(t *testing.T) {
			server := baotest.Start(t)
			provider := oidctest.Start()
			defer provider.Close()
			cfg := adminSettings(provider)
			client := provisioner(t, server)
			ctx := context.Background()
			switch scenario {
			case "wrong-engine":
				cfg.KVMounts = []string{"transit"}
			case "unowned-policy":
				if err := server.Root.Sys().PutPolicy(AdminPolicyName, `path "kv/data/sample" { capabilities=["read"] }`); err != nil {
					t.Fatal(err)
				}
			case "unowned-auth":
				if err := server.Root.Sys().EnableAuthWithOptions(AdminAuthMount, &api.EnableAuthOptions{Type: "oidc", Description: "Site managed"}); err != nil {
					t.Fatal(err)
				}
			case "extra-role":
				if err := ConfigureAdmin(ctx, client, cfg, provider.ClientSecret); err != nil {
					t.Fatal(err)
				}
				if _, err := server.Root.Logical().Write("auth/"+AdminAuthMount+"/role/extra", cfg.role()); err != nil {
					t.Fatal(err)
				}
			}
			beforePolicy, _ := server.Root.Sys().GetPolicy(AdminPolicyName)
			beforeAuth, _ := server.Root.Sys().ListAuth()
			if err := ConfigureAdmin(ctx, client, cfg, provider.ClientSecret); err == nil {
				t.Fatal("conflicting configure succeeded")
			}
			afterPolicy, _ := server.Root.Sys().GetPolicy(AdminPolicyName)
			afterAuth, _ := server.Root.Sys().ListAuth()
			if beforePolicy != afterPolicy || !reflect.DeepEqual(beforeAuth, afterAuth) {
				t.Fatal("preflight mutated resources")
			}
			if scenario != "wrong-engine" {
				if err := RemoveAdmin(ctx, client); err == nil {
					t.Fatal("removed unowned resources")
				}
				afterPolicy, _ = server.Root.Sys().GetPolicy(AdminPolicyName)
				afterAuth, _ = server.Root.Sys().ListAuth()
				if beforePolicy != afterPolicy || !reflect.DeepEqual(beforeAuth, afterAuth) {
					t.Fatal("remove changed conflicting resources")
				}
			}
		})
	}
}

func TestAdminRemovePreservesPolicyWhenDisableFails(t *testing.T) {
	var deletedPolicy bool
	policy, _ := AdminPolicy([]string{"kv"})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/sys/capabilities-self":
			_, _ = io.WriteString(w, `{"data":{"capabilities":["root"]}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/policies/acl/namespace-admin":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"policy": policy}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/auth/admin-oidc":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"type": "oidc", "description": adminDescription}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/auth/admin-oidc/role" && r.URL.Query().Get("list") == "true":
			_, _ = io.WriteString(w, `{"data":{"keys":["admin"]}}`)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/sys/auth/admin-oidc":
			w.WriteHeader(500)
			_, _ = io.WriteString(w, `{"errors":["sample upstream"]}`)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/sys/policies/acl/namespace-admin":
			deletedPolicy = true
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected remove request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer server.Close()
	client, _ := NewAdminClient(Endpoint{Address: server.URL, Namespace: "sample"}, "sample-token")
	err := RemoveAdmin(context.Background(), client)
	var failure *AdminError
	if !errors.As(err, &failure) || failure.Stage != "disable" || !failure.Partial || deletedPolicy {
		t.Fatal("failed disable removed policy or lost categorical stage")
	}
}

func TestAdminSetupRefusesRootClientBeforeMutation(t *testing.T) {
	server := baotest.Start(t)
	provider := oidctest.Start()
	defer provider.Close()
	if err := server.TopLevel.Sys().Mount("kv", &api.MountInput{Type: "kv", Options: map[string]string{"version": "2"}}); err != nil {
		t.Fatal(err)
	}
	err := ConfigureAdmin(context.Background(), server.TopLevel, adminSettings(provider), provider.ClientSecret)
	var failure *AdminError
	if !errors.As(err, &failure) || failure.Stage != "preflight" || failure.Partial {
		t.Fatal("root namespace was not rejected before writes")
	}
	policy, _ := server.TopLevel.Sys().GetPolicy(AdminPolicyName)
	if policy != "" {
		t.Fatal("root namespace policy was written")
	}
}
