// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package openbao

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestBindingValuesThroughOpenBao runs the whole carrier with the controller's
// bounded policy: a placeholder compiles to a template, SecretID metadata
// reaches the alias at login, and each role reads only its own path.
func TestBindingValuesThroughOpenBao(t *testing.T) {
	server, manager := testManager(t)
	ctx := context.Background()
	client := manager.client
	server.WriteKV(t, "sample/alpha", map[string]any{"value": "one"})
	server.WriteKV(t, "sample/beta", map[string]any{"value": "two"})
	hcl := `path "kv/data/sample/{{binding.slug}}" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
`
	if err := manager.WritePolicy(ctx, "wyrwood-shared", hcl); err != nil {
		t.Fatalf("WritePolicy() = %v", err)
	}
	published, err := server.Root.Sys().GetPolicy("wyrwood-shared")
	if err != nil || strings.Contains(published, "{{binding.") || !strings.Contains(published, "{{identity.entity.aliases.auth_approle_") || !strings.Contains(published, ".metadata.binding_slug}}") {
		t.Fatalf("published = %q, %v", published, err)
	}

	login := func(role string, metadata map[string]string) Token {
		t.Helper()
		if err := manager.WriteRole(ctx, role, []string{"wyrwood-shared"}, time.Hour, time.Hour); err != nil {
			t.Fatal(err)
		}
		wrapped, err := manager.WrappedSecretID(ctx, role, time.Minute, metadata)
		if err != nil {
			t.Fatalf("WrappedSecretID() = %v", err)
		}
		id, err := manager.RoleID(ctx, role)
		if err != nil {
			t.Fatal(err)
		}
		secretID, err := UnwrapSecretID(ctx, client, wrapped)
		if err != nil {
			t.Fatal(err)
		}
		token, err := AppRoleLogin(ctx, client, "approle", id, secretID)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(token.Policies, ",") != "wyrwood-shared" {
			t.Fatalf("token policies = %v", token.Policies)
		}
		return token
	}
	reads := func(token Token, path string) bool {
		t.Helper()
		reader, err := withToken(client, token.Value())
		if err != nil {
			t.Fatal(err)
		}
		_, err = reader.KVv2("kv").Get(ctx, path)
		return err == nil
	}

	alpha := login("wyrwood-role-a", map[string]string{"binding_slug": "alpha"})
	beta := login("wyrwood-role-b", map[string]string{"binding_slug": "beta"})
	unset := login("wyrwood-role-c", nil)
	if !reads(alpha, "sample/alpha") || reads(alpha, "sample/beta") {
		t.Fatal("the alpha role does not read exactly its own path")
	}
	if !reads(beta, "sample/beta") || reads(beta, "sample/alpha") {
		t.Fatal("the beta role does not read exactly its own path")
	}
	if reads(unset, "sample/alpha") || reads(unset, "sample/beta") {
		t.Fatal("a role with no value read a templated path")
	}
	if _, err := RenewSelf(ctx, client, alpha); err != nil {
		t.Fatalf("RenewSelf() = %v", err)
	}
	if !reads(alpha, "sample/alpha") {
		t.Fatal("a renewed token lost its value")
	}

	// A deleted role voids its outstanding identifiers, and its next role has a
	// new alias with no value carried over.
	wrapped, err := manager.WrappedSecretID(ctx, "wyrwood-role-a", time.Minute, map[string]string{"binding_slug": "beta"})
	if err != nil {
		t.Fatal(err)
	}
	oldRoleID, err := manager.RoleID(ctx, "wyrwood-role-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.DeleteRole(ctx, "wyrwood-role-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := RenewSelf(ctx, client, alpha); err == nil {
		t.Fatal("a token of the deleted role renewed")
	}
	carried := login("wyrwood-role-a", nil)
	if reads(carried, "sample/alpha") {
		t.Fatal("a recreated role carried a value")
	}
	newRoleID, err := manager.RoleID(ctx, "wyrwood-role-a")
	if err != nil || newRoleID == oldRoleID {
		t.Fatalf("recreated role id = %s, %v", newRoleID, err)
	}
	stale, err := UnwrapSecretID(ctx, client, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{oldRoleID, newRoleID} {
		if _, err := AppRoleLogin(ctx, client, "approle", id, stale); err == nil {
			t.Fatal("an identifier of the deleted role logged in")
		}
	}
}

func TestDeleteRoleOfAnAbsentRoleSucceeds(t *testing.T) {
	_, manager := testManager(t)
	if err := manager.DeleteRole(context.Background(), "wyrwood-absent"); err != nil {
		t.Fatalf("DeleteRole() = %v", err)
	}
}

func TestWritePolicyReadsTheAccessorOnlyForPlaceholders(t *testing.T) {
	server, manager := testManager(t)
	ctx := context.Background()
	if err := manager.Login(ctx); err != nil {
		t.Fatal(err)
	}
	// With no such mount, any accessor read fails.
	manager.mounts.AppRole = "absent"
	if err := manager.WritePolicy(ctx, "wyrwood-plain", `path "kv/data/x" { capabilities = ["read"] }`); err != nil {
		t.Fatalf("WritePolicy(plain) = %v", err)
	}
	if err := manager.WritePolicy(ctx, "wyrwood-templated", `path "kv/{{binding.slug}}" { capabilities = ["read"] }`); err == nil {
		t.Fatal("WritePolicy(templated) published with no accessor")
	}
	if published, err := server.Root.Sys().GetPolicy("wyrwood-templated"); err != nil || published != "" {
		t.Fatalf("a policy was published with no accessor: %q, %v", published, err)
	}
}
