// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package controller_test

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/wyrd-company/wyrwood/internal/controller/controllertest"
	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/openbao"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// A controller that stops after the OpenBao delete and before the store delete
// starts again with the policy present in both, and the delete can be retried.
func TestRestartBetweenTheTwoDeletesKeepsThePolicy(t *testing.T) {
	ctx := context.Background()
	bao := baotest.Start(t)
	state, address := t.TempDir(), controllertest.FreeAddress(t)
	running := controllertest.StartIn(t, bao, state, address)
	saved, err := running.SavePolicy(ctx, policy.New("alpha", policy.StarterHCL), "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := bao.Root.Sys().DeletePolicy(saved.OpenBaoPolicyName()); err != nil {
		t.Fatal(err)
	}
	running.Stop()

	restarted := controllertest.StartIn(t, bao, state, address)
	acl, err := bao.Root.Sys().GetPolicy(saved.OpenBaoPolicyName())
	if err != nil || acl != saved.PublishedHCL() {
		t.Fatalf("OpenBao policy after restart = %q, %v", acl, err)
	}
	stored, err := restarted.Store().Policy(ctx, saved.Name)
	if err != nil || stored.Policy.Revision != saved.Revision {
		t.Fatalf("stored policy after restart = %#v, %v", stored, err)
	}
	if err := restarted.DeletePolicy(ctx, saved.Name, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Store().Policy(ctx, saved.Name); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stored policy lookup = %v", err)
	}
	if acl, err := bao.Root.Sys().GetPolicy(saved.OpenBaoPolicyName()); err != nil || acl != "" {
		t.Fatalf("OpenBao policy = %q, %v", acl, err)
	}
}

func grantedPolicy(path string) policy.Policy {
	return policy.New("alpha", policy.StarterHCL+`path "kv/data/`+path+`" { capabilities = ["read"] }`)
}

func approve(t *testing.T, running *controllertest.Controller) {
	t.Helper()
	ctx := context.Background()
	if _, err := running.Store().RecordKey(ctx, "SHA256:sample", "host-a", "ssh-ed25519 AAAA", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := running.DecideAgent(ctx, "SHA256:sample", true, "operator-1"); err != nil {
		t.Fatal(err)
	}
}

func bindWeb(t *testing.T, running *controllertest.Controller) store.Binding {
	t.Helper()
	binding, err := running.CreateBinding(context.Background(), "host-a", protocol.Key{Kind: protocol.KeyName, Value: "web"}, policy.Selection{Policies: []string{"alpha"}}, "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func loginBinding(t *testing.T, bao *baotest.Server, role string) openbao.Token {
	t.Helper()
	roleID, err := bao.Root.Logical().Read("auth/approle/role/" + role + "/role-id")
	if err != nil || roleID == nil {
		t.Fatalf("role-id: %v", err)
	}
	secret, err := bao.Root.Logical().Write("auth/approle/role/"+role+"/secret-id", nil)
	if err != nil || secret == nil {
		t.Fatalf("secret-id: %v", err)
	}
	client, err := openbao.NewClient(openbao.Endpoint{Address: bao.Address, Namespace: bao.Namespace, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	token, err := openbao.AppRoleLogin(context.Background(), client, "approle", roleID.Data["role_id"].(string), secret.Data["secret_id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func tokenReads(t *testing.T, bao *baotest.Server, token openbao.Token, path string) bool {
	t.Helper()
	client, err := bao.Root.CloneWithHeaders()
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(token.Value())
	secret, err := client.Logical().Read("kv/data/" + path)
	var response *api.ResponseError
	switch {
	case err == nil && secret != nil:
		return true
	case errors.As(err, &response) && response.StatusCode == http.StatusForbidden:
		return false
	}
	t.Fatalf("read %s: secret %v, error %v", path, secret, err)
	return false
}

func aclText(t *testing.T, bao *baotest.Server, name string) string {
	t.Helper()
	acl, err := bao.Root.Sys().GetPolicy(name)
	if err != nil {
		t.Fatal(err)
	}
	return acl
}

// The generation record survives a restart with no row, and the startup sync
// publishes only the current identity.
func TestRestartKeepsGenerationsAndNeverRepublishesARetiredIdentity(t *testing.T) {
	ctx := context.Background()
	bao := baotest.Start(t)
	bao.WriteKV(t, "first", map[string]any{"value": "one"})
	bao.WriteKV(t, "second", map[string]any{"value": "two"})
	state, address := t.TempDir(), controllertest.FreeAddress(t)
	running := controllertest.StartIn(t, bao, state, address)
	approve(t, running)
	first, err := running.SavePolicy(ctx, grantedPolicy("first"), "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	binding := bindWeb(t, running)
	survivor := loginBinding(t, bao, binding.Role)
	_ = running.DeleteBinding(ctx, binding.ID, "operator-1")
	if !tokenReads(t, bao, survivor, "first") {
		t.Fatal("the fixture needs a token that outlives its binding")
	}
	if err := running.DeletePolicy(ctx, "alpha", "operator-1"); err != nil {
		t.Fatal(err)
	}
	running.Stop()

	running = controllertest.StartIn(t, bao, state, address)
	second, err := running.SavePolicy(ctx, grantedPolicy("second"), "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	if second.OpenBaoPolicyName() != "wyrwood-alpha--2" {
		t.Fatalf("identity after restart = %s", second.OpenBaoPolicyName())
	}
	for _, path := range []string{"first", "second"} {
		if tokenReads(t, bao, survivor, path) {
			t.Fatalf("the surviving token reads %s after a restart", path)
		}
	}
	binding = bindWeb(t, running)
	fresh := loginBinding(t, bao, binding.Role)
	if !reflect.DeepEqual(fresh.Policies, []string{"wyrwood-alpha--2"}) {
		t.Fatalf("fresh policies = %v", fresh.Policies)
	}
	running.Stop()

	running = controllertest.StartIn(t, bao, state, address)
	if acl := aclText(t, bao, first.OpenBaoPolicyName()); acl != "" {
		t.Fatalf("the startup sync republished the first identity: %q", acl)
	}
	if acl := aclText(t, bao, second.OpenBaoPolicyName()); acl != second.PublishedHCL() {
		t.Fatalf("the current identity after restart = %q", acl)
	}
	if !tokenReads(t, bao, fresh, "second") {
		t.Fatal("the current token stopped working across a restart")
	}
	if tokenReads(t, bao, survivor, "second") {
		t.Fatal("the surviving token gained access across a restart")
	}
	_ = running.DeleteBinding(ctx, binding.ID, "operator-1")
	if err := running.DeletePolicy(ctx, "alpha", "operator-1"); err != nil {
		t.Fatal(err)
	}
	third, err := running.SavePolicy(ctx, grantedPolicy("second"), "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	if third.OpenBaoPolicyName() != "wyrwood-alpha--3" {
		t.Fatalf("identity = %s", third.OpenBaoPolicyName())
	}
}

// An upgrade from schema 2 keeps first-use identities, live tokens, and
// assignments: no binding transitions and no credential is reissued.
func TestUpgradeFromSchemaTwoKeepsIdentityTokensAndAssignments(t *testing.T) {
	ctx := context.Background()
	bao := baotest.Start(t)
	bao.WriteKV(t, "first", map[string]any{"value": "one"})
	bao.WriteKV(t, "second", map[string]any{"value": "two"})
	state, address := t.TempDir(), controllertest.FreeAddress(t)
	running := controllertest.StartIn(t, bao, state, address)
	approve(t, running)
	saved, err := running.SavePolicy(ctx, grantedPolicy("first"), "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	binding := bindWeb(t, running)
	before, err := running.Store().Binding(ctx, binding.ID)
	if err != nil || !before.Applied {
		t.Fatalf("binding = %#v, %v", before, err)
	}
	token := loginBinding(t, bao, binding.Role)
	running.Stop()

	db, err := sql.Open("sqlite", filepath.Join(state, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{`DROP INDEX bindings_directory`, `ALTER TABLE bindings DROP COLUMN directory`, `DROP TABLE operator_keys`, `DROP TABLE policy_retirements`, `DROP TABLE policy_generations`, `ALTER TABLE policies DROP COLUMN generation`, `PRAGMA user_version = 2`} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	running = controllertest.StartIn(t, bao, state, address)
	after, err := running.Store().Binding(ctx, binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Assignment() != before.Assignment() || !after.Applied || after.Revision != before.Revision {
		t.Fatalf("the upgrade changed the binding: %#v", after)
	}
	if acl := aclText(t, bao, saved.OpenBaoPolicyName()); acl != saved.PublishedHCL() {
		t.Fatalf("ACL after upgrade = %q", acl)
	}
	if !tokenReads(t, bao, token, "first") {
		t.Fatal("the upgrade revoked a live token")
	}
	if _, err := running.SavePolicy(ctx, grantedPolicy("second"), "operator-1"); err != nil {
		t.Fatal(err)
	}
	if edited, err := running.Store().Policy(ctx, "alpha"); err != nil || edited.Policy.OpenBaoPolicyName() != "wyrwood-alpha" || edited.Policy.Revision != 2 {
		t.Fatalf("edit after upgrade = %#v, %v", edited.Policy, err)
	}
	_ = running.DeleteBinding(ctx, binding.ID, "operator-1")
	if err := running.DeletePolicy(ctx, "alpha", "operator-1"); err != nil {
		t.Fatal(err)
	}
	reused, err := running.SavePolicy(ctx, grantedPolicy("second"), "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	if reused.OpenBaoPolicyName() != "wyrwood-alpha--2" {
		t.Fatalf("reused identity after upgrade = %s", reused.OpenBaoPolicyName())
	}
	if tokenReads(t, bao, token, "second") {
		t.Fatal("a token from before the upgrade reads the recreated policy")
	}
}
