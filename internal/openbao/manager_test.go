// ---
// relationships:
//   verifies:
//     - controller
//     - agent
// ---

package openbao

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	manager := NewManager(client, Mounts{AppRole: "approle", Transit: "transit", SSH: "ssh"}, roleID,
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

	if err := manager.WritePolicy(ctx, "wyrwood-teal", `path "kv/data/teams/teal/*" { capabilities = ["read"] }`); err != nil {
		t.Fatalf("WritePolicy() = %v", err)
	}
	if err := manager.WritePolicy(ctx, "wyrwood-broken", `path "kv/*" { capabilities = [`); CategoryOf(err) != CategoryInvalid {
		t.Fatalf("WritePolicy(invalid HCL) = %v, want invalid", err)
	}
	if err := manager.WritePolicy(ctx, "outside-prefix", `path "kv/*" {}`); CategoryOf(err) != CategoryInvalid {
		t.Fatalf("WritePolicy(outside prefix) = %v", err)
	}
	if err := manager.WriteRole(ctx, "wyrwood-host-b-1", "wyrwood-teal", 20*time.Minute, 3*time.Hour); err != nil {
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
	wrapped, err := manager.WrappedSecretID(ctx, "wyrwood-host-b-1", time.Minute)
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
	if strings.Join(token.Policies, ",") != "default,wyrwood-teal" || token.TTL != 20*time.Minute {
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
	keys, err := manager.ListTransitKeys(ctx)
	if err != nil || len(keys) != 2 {
		t.Fatalf("ListTransitKeys() = %#v, %v", keys, err)
	}
	for _, key := range keys {
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
		if err := manager.WriteRole(ctx, "wyrwood-host-a-1", policyName, time.Hour, time.Hour); !errors.As(err, &invalid) || invalid.Category != CategoryInvalid {
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
