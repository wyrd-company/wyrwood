// ---
// relationships:
//   verifies:
//     - controller
//   mitigates: controller-token-blast-radius
// ---

package openbao

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
)

// everything is the policy a compromised controller would write for itself.
const everything = `path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }`

// TestADedicatedNamespaceContainsAnEscalatedBinding proves the supported
// deployment's mitigation: the controller can write any HCL into a managed
// policy and log in through it, but the resulting token reaches nothing
// outside the controller's namespace.
func TestADedicatedNamespaceContainsAnEscalatedBinding(t *testing.T) {
	ctx := context.Background()
	server, manager := testManager(t)
	if _, err := server.TopLevel.KVv2("secret").Put(ctx, "outside", map[string]any{"value": "outside-value"}); err != nil {
		t.Fatal(err)
	}

	if err := manager.WritePolicy(ctx, "wyrwood-escape", everything); err != nil {
		t.Fatalf("WritePolicy(everything) = %v", err)
	}
	if err := manager.WriteRole(ctx, "wyrwood-escape", []string{"wyrwood-escape"}, time.Hour, time.Hour); err != nil {
		t.Fatalf("WriteRole() = %v", err)
	}
	roleID, err := manager.RoleID(ctx, "wyrwood-escape")
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := manager.WrappedSecretID(ctx, "wyrwood-escape", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	inside, err := NewClient(Endpoint{Address: server.Address, Namespace: server.Namespace, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	secretID, err := UnwrapSecretID(ctx, inside, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	token, err := AppRoleLogin(ctx, inside, "approle", roleID, secretID)
	if err != nil {
		t.Fatal(err)
	}
	escalated, err := withToken(inside, token.Value())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := escalated.Logical().ReadWithContext(ctx, "sys/policies/acl/"+baotest.ControllerName); err != nil {
		t.Fatalf("the escalated token cannot use its namespace: %v", err)
	}

	outside, err := NewClient(Endpoint{Address: server.Address, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	outside, err = withToken(outside, token.Value())
	if err != nil {
		t.Fatal(err)
	}
	if secret, err := outside.KVv2("secret").Get(ctx, "outside"); err == nil {
		t.Fatalf("the escalated token read the root namespace: %v", secret.Data)
	}
	if _, err := outside.Logical().WriteWithContext(ctx, "sys/policies/acl/escape", map[string]any{"policy": everything}); err == nil {
		t.Fatal("the escalated token wrote a root-namespace policy")
	}
	if _, err := outside.Logical().WriteWithContext(ctx, "sys/namespaces/escape", nil); err == nil {
		t.Fatal("the escalated token created a namespace")
	}
}

func TestTheControllerCannotRewriteItsOwnPolicyOrRole(t *testing.T) {
	ctx := context.Background()
	_, manager := testManager(t)
	var invalid *Error
	if err := manager.WritePolicy(ctx, baotest.ControllerName, everything); !errors.As(err, &invalid) || invalid.Category != CategoryInvalid {
		t.Fatalf("WritePolicy(controller) = %v, want invalid", err)
	}
	client, err := manager.authorized(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Logical().WriteWithContext(ctx, "sys/policies/acl/"+baotest.ControllerName, map[string]any{"policy": everything}); err == nil {
		t.Fatal("the controller token rewrote its own policy")
	}
	if _, err := client.Logical().WriteWithContext(ctx, "auth/approle/role/"+baotest.ControllerName, map[string]any{"token_policies": "root"}); err == nil {
		t.Fatal("the controller token rewrote its own AppRole")
	}
}
