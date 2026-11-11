// ---
// relationships:
//   verifies:
//     - controller
//     - agent
// ---

package openbao

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
)

func testManager(t *testing.T) (*baotest.Server, *Manager) {
	t.Helper()
	server := baotest.Start(t)
	roleID, secretFile := server.ControllerCredentials(t)
	client, err := NewClient(Endpoint{Address: server.Address, Namespace: server.Namespace, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(client, Mounts{AppRole: "approle", Transit: "transit", SSH: "ssh", KV: []string{"kv"}}, roleID,
		func() (string, error) { return config.ReadSecretFile(secretFile) })
	if err := manager.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	return server, manager
}

func TestManagerHealthInNamespace(t *testing.T) {
	server, manager := testManager(t)
	ctx := context.Background()
	if _, err := server.Root.Sys().HealthWithContext(ctx); err == nil {
		t.Fatal("namespaced health request unexpectedly succeeded")
	}
	if err := manager.Health(ctx); err != nil {
		t.Fatalf("Health() in namespace = %v", err)
	}
	if err := manager.WritePolicy(ctx, "wyrwood-teal", `path "kv/data/example" { capabilities = ["read"] }`); err != nil {
		t.Fatalf("namespaced policy write after Health() = %v", err)
	}
}

func TestBindingAppRoleLifecycle(t *testing.T) {
	ctx := context.Background()
	server, manager := testManager(t)
	server.WriteKV(t, "teams/teal/example", map[string]any{"value": "teal-secret"})

	if err := manager.WritePolicy(ctx, "wyrwood-teal", `path "kv/data/teams/teal/*" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }`); err != nil {
		t.Fatalf("WritePolicy() = %v", err)
	}
	if err := manager.WritePolicy(ctx, "wyrwood-broken", `path "kv/*" { capabilities = [`); CategoryOf(err) != CategoryInvalid {
		t.Fatalf("WritePolicy(invalid HCL) = %v, want invalid", err)
	}
	if err := manager.WritePolicy(ctx, "outside-prefix", `path "kv/*" {}`); CategoryOf(err) != CategoryInvalid {
		t.Fatalf("WritePolicy(outside prefix) = %v", err)
	}
	if err := manager.WriteRole(ctx, "wyrwood-host-b-1", []string{"wyrwood-teal"}, 20*time.Minute, 3*time.Hour); err != nil {
		t.Fatalf("WriteRole() = %v", err)
	}
	written, err := server.Root.Logical().Read("auth/approle/role/wyrwood-host-b-1")
	if err != nil || written == nil {
		t.Fatalf("read role = %v, %v", written, err)
	}
	if fmt.Sprint(written.Data["token_ttl"]) != "1200" || fmt.Sprint(written.Data["token_max_ttl"]) != "10800" {
		t.Fatalf("role token_ttl = %v, token_max_ttl = %v", written.Data["token_ttl"], written.Data["token_max_ttl"])
	}
	roleID, err := manager.RoleID(ctx, "wyrwood-host-b-1")
	if err != nil {
		t.Fatalf("RoleID() = %v", err)
	}
	wrapped, err := manager.WrappedSecretID(ctx, "wyrwood-host-b-1", time.Minute, nil)
	if err != nil {
		t.Fatalf("WrappedSecretID() = %v", err)
	}

	agentClient, err := NewClient(Endpoint{Address: server.Address, Namespace: server.Namespace, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	secretID, err := UnwrapSecretID(ctx, agentClient, wrapped)
	if err != nil {
		t.Fatalf("UnwrapSecretID() = %v", err)
	}
	if _, err := UnwrapSecretID(ctx, agentClient, wrapped); err == nil {
		t.Fatal("wrapped secret identifier unwrapped twice")
	}
	token, err := AppRoleLogin(ctx, agentClient, "approle", roleID, secretID)
	if err != nil {
		t.Fatalf("AppRoleLogin() = %v", err)
	}
	if strings.Join(token.Policies, ",") != "wyrwood-teal" || token.TTL != 20*time.Minute {
		t.Fatalf("token policies = %v ttl = %v", token.Policies, token.TTL)
	}
	if _, err := AppRoleLogin(ctx, agentClient, "approle", roleID, secretID); err == nil {
		t.Fatal("secret identifier was usable twice")
	}
	reader, _ := agentClient.CloneWithHeaders()
	reader.SetToken(token.Value())
	secret, err := reader.KVv2("kv").Get(ctx, "teams/teal/example")
	if err != nil || secret.Data["value"] != "teal-secret" {
		t.Fatalf("read with binding token = %v, %v", secret, err)
	}
	if _, err := reader.KVv2("kv").Get(ctx, "other"); err == nil {
		t.Fatal("binding token read outside its policy")
	}
	renewed, err := RenewSelf(ctx, agentClient, token)
	if err != nil || renewed.Value() != token.Value() {
		t.Fatalf("RenewSelf() = %v", err)
	}
	if err := RevokeSelf(ctx, agentClient, token); err != nil {
		t.Fatalf("RevokeSelf() = %v", err)
	}
	if _, err := reader.KVv2("kv").Get(ctx, "teams/teal/example"); err == nil {
		t.Fatal("revoked token still reads")
	}
	if err := manager.DeleteRole(ctx, "wyrwood-host-b-1"); err != nil {
		t.Fatalf("DeleteRole() = %v", err)
	}
	if _, err := manager.RoleID(ctx, "wyrwood-host-b-1"); err == nil {
		t.Fatal("deleted role still has a role identifier")
	}
}

func TestTransitAndSSHManagement(t *testing.T) {
	ctx := context.Background()
	_, manager := testManager(t)
	for name, keyType := range map[string]string{"teal-ed": "ed25519", "teal-rsa": "rsa-2048"} {
		if err := manager.CreateTransitKey(ctx, name, keyType); err != nil {
			t.Fatalf("CreateTransitKey(%s) = %v", name, err)
		}
	}
	if err := manager.CreateTransitKey(ctx, "teal-aes", "aes256-gcm96"); CategoryOf(err) != CategoryInvalid {
		t.Fatalf("CreateTransitKey(aes) = %v", err)
	}
	if err := manager.RotateTransitKey(ctx, "teal-ed"); err != nil {
		t.Fatal(err)
	}
	listing, err := manager.ListTransitKeys(ctx)
	if err != nil || len(listing.Keys) != 2 || len(listing.Unreadable) != 0 {
		t.Fatalf("ListTransitKeys() = %#v, %v", listing, err)
	}
	for _, key := range listing.Keys {
		if key.PublicKey == nil {
			t.Fatalf("key %s has no public key", key.Name)
		}
		if key.Name == "teal-ed" && (key.LatestVersion != 2 || key.PublicKey.Type() != ssh.KeyAlgoED25519) {
			t.Fatalf("teal-ed = %#v", key)
		}
		if key.Name == "teal-rsa" && key.PublicKey.Type() != ssh.KeyAlgoRSA {
			t.Fatalf("teal-rsa = %#v", key)
		}
	}
	if exists, err := manager.TransitKeyExists(ctx, "missing"); err != nil || exists {
		t.Fatalf("TransitKeyExists(missing) = %v, %v", exists, err)
	}
	if err := manager.CreateSSHRole(ctx, "teal-hosts", "git,deploy", "30m"); err != nil {
		t.Fatalf("CreateSSHRole() = %v", err)
	}
	roles, err := manager.ListSSHRoles(ctx)
	if err != nil || len(roles) != 1 || roles[0].AllowedUsers != "git,deploy" {
		t.Fatalf("ListSSHRoles() = %#v, %v", roles, err)
	}
	if exists, err := manager.SSHRoleExists(ctx, "teal-hosts"); err != nil || !exists {
		t.Fatalf("SSHRoleExists() = %v, %v", exists, err)
	}
}

func transitKeyNames(keys []TransitKey) []string {
	names := make([]string, 0, len(keys))
	for _, key := range keys {
		names = append(names, key.Name)
	}
	return names
}

func TestListTransitKeysWithImportedKey(t *testing.T) {
	ctx := context.Background()
	server, manager := testManager(t)
	server.CreateTransitKey(t, "sample-generated", "ed25519")
	server.ImportTransitKey(t, "sample-imported")
	listed, err := server.Root.Logical().List("transit/keys")
	if err != nil || !slices.Contains(listed.Data["keys"].([]any), any("import/")) {
		t.Fatalf("fixture LIST transit/keys = %#v, %v; want an import/ entry", listed, err)
	}
	listing, err := manager.ListTransitKeys(ctx)
	if err != nil {
		t.Fatalf("ListTransitKeys() = %#v, %v", listing, err)
	}
	if names := transitKeyNames(listing.Keys); !slices.Equal(names, []string{"sample-generated", "sample-imported"}) || len(listing.Unreadable) != 0 {
		t.Fatalf("ListTransitKeys() keys = %v, unreadable = %#v", names, listing.Unreadable)
	}
	for _, key := range listing.Keys {
		if key.PublicKey == nil || key.PublicKey.Type() != ssh.KeyAlgoED25519 {
			t.Fatalf("key %s public key = %v", key.Name, key.PublicKey)
		}
	}
}

func TestListTransitKeysReportsAnUnreadableKey(t *testing.T) {
	ctx := context.Background()
	server, manager := testManager(t)
	server.CreateTransitKey(t, "sample-open", "ed25519")
	server.CreateTransitKey(t, "sample-locked", "ed25519")
	// The exact path takes precedence over the controller policy's glob.
	if err := server.Root.Sys().PutPolicy(baotest.ControllerName, baotest.ControllerPolicy+`path "transit/keys/sample-locked" { capabilities = ["deny"] }`); err != nil {
		t.Fatal(err)
	}
	listing, err := manager.ListTransitKeys(ctx)
	if err != nil {
		t.Fatalf("ListTransitKeys() = %#v, %v", listing, err)
	}
	if names := transitKeyNames(listing.Keys); !slices.Equal(names, []string{"sample-open"}) {
		t.Fatalf("readable keys = %v", names)
	}
	if len(listing.Unreadable) != 1 || listing.Unreadable[0].Name != "sample-locked" || CategoryOf(listing.Unreadable[0].Err) != CategoryDenied {
		t.Fatalf("unreadable keys = %#v", listing.Unreadable)
	}
}

// TestListTransitKeysStopsWhenOpenBaoStopsAnswering serves the list and one
// key, and then drops the connection of the next read, as an OpenBao that went
// away during the reads.
func TestListTransitKeysStopsWhenOpenBaoStopsAnswering(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firstKey := fmt.Sprintf(`{"data":{"type":"ed25519","latest_version":1,"keys":{"1":{"public_key":%q}}}}`, base64.StdEncoding.EncodeToString(public))
	var thirdRead atomic.Bool
	fake := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/transit/keys", "/v1/transit/keys/":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"data":{"keys":["sample-first","sample-second","sample-third"]}}`))
			return
		case "/v1/transit/keys/sample-first":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(firstKey))
			return
		case "/v1/transit/keys/sample-third":
			thirdRead.Store(true)
		}
		connection, _, err := writer.(http.Hijacker).Hijack()
		if err == nil {
			_ = connection.Close()
		}
	}))
	defer fake.Close()
	client, err := NewClient(Endpoint{Address: fake.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(client, Mounts{Transit: "transit"}, "role", nil)
	manager.token = Token{value: "sample-token", TTL: time.Hour, Obtained: time.Now()}
	listing, err := manager.ListTransitKeys(context.Background())
	if !Unreachable(err) {
		t.Fatalf("ListTransitKeys() error = %v; want unreachable", err)
	}
	if names := transitKeyNames(listing.Keys); !slices.Equal(names, []string{"sample-first"}) || listing.Keys[0].PublicKey == nil {
		t.Fatalf("keys read before OpenBao stopped answering = %#v", listing.Keys)
	}
	if len(listing.Unreadable) != 1 || listing.Unreadable[0].Name != "sample-second" || !Unreachable(listing.Unreadable[0].Err) {
		t.Fatalf("unreadable keys = %#v; want sample-second unreachable", listing.Unreadable)
	}
	if thirdRead.Load() {
		t.Fatal("ListTransitKeys read another key after OpenBao stopped answering")
	}
}

func TestUnreachableOnlyWithoutAnAnswer(t *testing.T) {
	for _, test := range []struct {
		err  error
		want bool
	}{
		{&Error{Category: CategoryUnavailable}, true},
		{&Error{Category: CategoryTimeout}, true},
		{&Error{Category: CategoryUnavailable, Status: http.StatusServiceUnavailable}, false},
		{&Error{Category: CategoryDenied, Status: http.StatusForbidden}, false},
		{&Error{Category: CategoryNotFound, Status: http.StatusNotFound}, false},
		{errors.New("sample"), false},
		{nil, false},
	} {
		if got := Unreachable(test.err); got != test.want {
			t.Errorf("Unreachable(%#v) = %v, want %v", test.err, got, test.want)
		}
	}
}

func TestErrorsNeverCarryRawText(t *testing.T) {
	client, err := NewClient(Endpoint{Address: "http://127.0.0.1:1", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = AppRoleLogin(context.Background(), client, "approle", "role", "secret-value")
	if err == nil || CategoryOf(err) != CategoryUnavailable || err.Error() != "openbao unavailable" {
		t.Fatalf("AppRoleLogin() = %v", err)
	}
}

func TestBindingRolesCarryOnlyManagedPolicies(t *testing.T) {
	ctx := context.Background()
	_, manager := testManager(t)
	for _, policyName := range []string{baotest.ControllerName, "root", "default", "wyrwood-", ""} {
		var invalid *Error
		if err := manager.WriteRole(ctx, "wyrwood-host-a-1", []string{policyName}, time.Hour, time.Hour); !errors.As(err, &invalid) || invalid.Category != CategoryInvalid {
			t.Errorf("WriteRole(policy %q) = %v, want invalid", policyName, err)
		}
	}
	client, err := manager.authorized(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if role, err := client.Logical().ReadWithContext(ctx, "auth/approle/role/wyrwood-host-a-1"); err != nil || role != nil {
		t.Fatalf("a rejected role was written: %v, %v", role, err)
	}
}
