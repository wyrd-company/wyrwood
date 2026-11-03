// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package controller

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/openbao"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
	gossh "golang.org/x/crypto/ssh"
)

const sharedValueHCL = `path "kv/data/sample/{{binding.slug}}" { capabilities = ["read"] }`

// valueFixture is an approved connected agent reporting one container, and one
// policy with a placeholder.
type valueFixture struct {
	h          *harness
	connection *agentConnection
	key        protocol.Key
	client     *agentLogin
}

// agentLogin logs in and reads as the agent does.
type agentLogin struct {
	t *testing.T
	h *harness
}

func newValueFixture(t *testing.T) valueFixture {
	t.Helper()
	return newValueFixtureWith(t, nil)
}

func newValueFixtureWith(t *testing.T, wrap func(OpenBao) OpenBao) valueFixture {
	t.Helper()
	ctx := context.Background()
	h := startHarnessWith(t, wrap)
	agentKey := newAgentKey(t)
	_, _ = h.dial("host-a", agentKey)
	if err := h.controller.DecideAgent(ctx, gossh.FingerprintSHA256(agentKey.PublicKey()), true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	connection, err := h.dial("host-a", agentKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.client.Close() })
	if err := connection.conn.Send(protocol.Hello{AgentVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	key := protocol.Key{Kind: protocol.KeyName, Value: "web"}
	if err := connection.conn.Send(protocol.Inventory{Containers: []protocol.Container{{ID: strings.Repeat("a", 64), Name: "web", Image: "busybox", State: protocol.StateRunning, Keys: []protocol.Key{key}}}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := connection.receive(t).(protocol.PolicySet); !ok {
		t.Fatal("no initial policy set")
	}
	h.bao.WriteKV(t, "sample/alpha", map[string]any{"value": "one"})
	h.bao.WriteKV(t, "sample/beta", map[string]any{"value": "two"})
	if _, err := h.controller.SavePolicy(ctx, policy.New("shared", sharedValueHCL), "operator-1"); err != nil {
		t.Fatalf("SavePolicy() = %v", err)
	}
	return valueFixture{h: h, connection: connection, key: key, client: &agentLogin{t: t, h: h}}
}

func valueSelection(values map[string]string) BindingRequest {
	settings := policy.DefaultSettings()
	settings.Values = values
	return BindingRequest{Policies: []string{"shared"}, Settings: settings}
}

// credential waits for the credential of an assignment.
func (fixture valueFixture) credential(t *testing.T, assignment string) protocol.Credential {
	t.Helper()
	for {
		if credential, ok := fixture.connection.receive(t).(protocol.Credential); ok && credential.Assignment == assignment {
			return credential
		}
	}
}

// login does what the agent does with a credential.
func (client *agentLogin) login(credential protocol.Credential) (openbao.Token, error) {
	ctx := context.Background()
	bao, err := openbao.NewClient(openbao.Endpoint{Address: client.h.bao.Address, Namespace: client.h.bao.Namespace, Timeout: 5 * time.Second})
	if err != nil {
		client.t.Fatal(err)
	}
	secretID, err := openbao.UnwrapSecretID(ctx, bao, credential.WrappedSecretID)
	if err != nil {
		return openbao.Token{}, err
	}
	return openbao.AppRoleLogin(ctx, bao, credential.AppRoleMount, credential.RoleID, secretID)
}

func (client *agentLogin) reads(token openbao.Token, path string) bool {
	client.t.Helper()
	reader, err := client.h.bao.Root.Clone()
	if err != nil {
		client.t.Fatal(err)
	}
	reader.SetNamespace(client.h.bao.Namespace)
	reader.SetToken(token.Value())
	_, err = reader.KVv2("kv").Get(context.Background(), path)
	return err == nil
}

func TestBindingValueReachesTheTokenAndAChangeReplacesIt(t *testing.T) {
	ctx := context.Background()
	fixture := newValueFixture(t)
	c := fixture.h.controller
	bound, err := c.CreateBinding(ctx, "host-a", fixture.key, valueSelection(map[string]string{"slug": "alpha"}), "operator-1")
	if err != nil {
		t.Fatalf("CreateBinding() = %v", err)
	}
	first, err := fixture.client.login(fixture.credential(t, bound.Assignment()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(first.Policies, ",") != "wyrwood-shared" {
		t.Fatalf("token policies = %v", first.Policies)
	}
	if !fixture.client.reads(first, "sample/alpha") || fixture.client.reads(first, "sample/beta") {
		t.Fatal("the token does not read exactly the path of its value")
	}
	reportAccessor(t, fixture.connection, bound, first)

	// A stale credential is in flight when the value changes.
	stale, err := c.openbao.WrappedSecretID(ctx, bound.Role, time.Minute, bound.Settings.IdentityMetadata())
	if err != nil {
		t.Fatal(err)
	}
	staleRole, err := c.openbao.RoleID(ctx, bound.Role)
	if err != nil {
		t.Fatal(err)
	}

	request := valueSelection(map[string]string{"slug": "beta"})
	request.Revision = bound.Revision
	if err := c.ChangeBinding(ctx, bound.ID, request, "operator-1"); err != nil {
		t.Fatalf("ChangeBinding() = %v", err)
	}
	current, err := c.store.Binding(ctx, bound.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != bound.Revision+1 || current.Assignment() == bound.Assignment() || !current.Applied {
		t.Fatalf("binding after a value change = %#v", current)
	}
	if !strings.Contains(current.Effective.OpenBao.Policy, `"kv/data/sample/beta"`) {
		t.Fatalf("effective policy = %s", current.Effective.OpenBao.Policy)
	}
	if fixture.client.reads(first, "sample/alpha") {
		t.Fatal("the old token still reads after the value changed")
	}
	second, err := fixture.client.login(fixture.credential(t, current.Assignment()))
	if err != nil {
		t.Fatal(err)
	}
	if !fixture.client.reads(second, "sample/beta") || fixture.client.reads(second, "sample/alpha") {
		t.Fatal("the new token does not read exactly the path of the new value")
	}
	if _, err := fixture.client.login(protocol.Credential{AppRoleMount: "approle", RoleID: staleRole, WrappedSecretID: stale}); err == nil {
		t.Fatal("a credential issued before the change logged in")
	}
	if !fixture.client.reads(second, "sample/beta") || fixture.client.reads(second, "sample/alpha") {
		t.Fatal("a stale credential changed the value under the new token")
	}
}

// roleFaultBao fails one role write after the role was deleted.
type roleFaultBao struct {
	OpenBao
	failWrite   atomic.Bool
	duringFault func()
}

func (wrapped *roleFaultBao) WriteRole(ctx context.Context, role string, policies []string, ttl, maxTTL time.Duration) error {
	if wrapped.failWrite.Swap(false) {
		wrapped.duringFault()
		return &openbao.Error{Category: openbao.CategoryUnavailable}
	}
	return wrapped.OpenBao.WriteRole(ctx, role, policies, ttl, maxTTL)
}

func TestValueChangeConvergesAfterAFailedRoleWrite(t *testing.T) {
	ctx := context.Background()
	fault := &roleFaultBao{}
	fixture := newValueFixtureWith(t, func(inner OpenBao) OpenBao {
		fault.OpenBao = inner
		return fault
	})
	c := fixture.h.controller
	bound, err := c.CreateBinding(ctx, "host-a", fixture.key, valueSelection(map[string]string{"slug": "alpha"}), "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	first, err := fixture.client.login(fixture.credential(t, bound.Assignment()))
	if err != nil {
		t.Fatal(err)
	}
	reportAccessor(t, fixture.connection, bound, first)

	roleDuringFault := make(chan any, 1)
	fault.duringFault = func() {
		role, err := fixture.h.bao.Root.Logical().Read("auth/approle/role/" + bound.Role)
		if err != nil {
			roleDuringFault <- err
			return
		}
		roleDuringFault <- role
	}
	fault.failWrite.Store(true)
	request := valueSelection(map[string]string{"slug": "beta"})
	request.Revision = bound.Revision
	if err := c.ChangeBinding(ctx, bound.ID, request, "operator-1"); err == nil {
		t.Fatal("ChangeBinding() with a failed role write = nil")
	}
	if role := <-roleDuringFault; role != (*api.Secret)(nil) {
		t.Fatalf("role during the failure = %v", role)
	}
	pending, err := c.store.Binding(ctx, bound.ID)
	if err != nil || pending.Settings.Values["slug"] != "beta" {
		t.Fatalf("binding after the failure = %#v, %v", pending, err)
	}

	// The session's next issue applies the pending transition.
	second, err := fixture.client.login(fixture.credential(t, pending.Assignment()))
	if err != nil {
		t.Fatal(err)
	}
	if !fixture.client.reads(second, "sample/beta") || fixture.client.reads(second, "sample/alpha") {
		t.Fatal("the token after recovery does not read exactly the new path")
	}
	if fixture.client.reads(first, "sample/alpha") {
		t.Fatal("the old token still reads after recovery")
	}
	applied, err := c.store.Binding(ctx, bound.ID)
	if err != nil || !applied.Applied {
		t.Fatalf("binding after recovery = %#v, %v", applied, err)
	}
}

func TestBindingValueRefusalsChangeNothing(t *testing.T) {
	ctx := context.Background()
	fixture := newValueFixture(t)
	c := fixture.h.controller
	for name, values := range map[string]map[string]string{
		"unset":   nil,
		"hostile": {"slug": "a/b"},
		"typo":    {"slgu": "alpha"},
	} {
		if _, err := c.PreviewBinding(ctx, valueSelection(values)); err == nil {
			t.Fatalf("%s: PreviewBinding() = nil", name)
		}
		_, err := c.CreateBinding(ctx, "host-a", fixture.key, valueSelection(values), "operator-1")
		var operation *OperationError
		if !errors.As(err, &operation) || operation.Part != policy.PartSelection {
			t.Fatalf("%s: CreateBinding() = %v", name, err)
		}
		bindings, err := c.store.Bindings(ctx, "")
		if err != nil || len(bindings) != 0 {
			t.Fatalf("%s: bindings = %#v, %v", name, bindings, err)
		}
	}
	preview, err := c.PreviewBinding(ctx, valueSelection(map[string]string{"slug": "alpha"}))
	if err != nil || !strings.Contains(preview.OpenBao.Policy, `"kv/data/sample/alpha"`) {
		t.Fatalf("PreviewBinding() = %s, %v", preview.OpenBao.Policy, err)
	}
}

func TestPolicyEditThatNeedsAnUnsetValueIsRefused(t *testing.T) {
	ctx := context.Background()
	fixture := newValueFixture(t)
	c := fixture.h.controller
	bound, err := c.CreateBinding(ctx, "host-a", fixture.key, valueSelection(map[string]string{"slug": "alpha"}), "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	published, err := fixture.h.bao.Root.Sys().GetPolicy("wyrwood-shared")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := c.store.Policy(ctx, "shared")
	if err != nil {
		t.Fatal(err)
	}
	edit := stored.Policy.Clone()
	edit.OpenBao.Policy = sharedValueHCL + "\n" + `path "kv/data/{{binding.area}}/x" { capabilities = ["read"] }`
	_, err = c.SavePolicy(ctx, edit, "operator-1")
	if err == nil || !strings.Contains(err.Error(), "{{binding.area}}") || !strings.Contains(err.Error(), "name web on agent host-a") {
		t.Fatalf("SavePolicy() = %v", err)
	}
	after, err := fixture.h.bao.Root.Sys().GetPolicy("wyrwood-shared")
	if err != nil || after != published {
		t.Fatalf("the published policy changed: %q, %v", after, err)
	}
	current, err := c.store.Binding(ctx, bound.ID)
	if err != nil || current.Revision != bound.Revision {
		t.Fatalf("binding = %#v, %v", current, err)
	}
	// An edit that stops using a value leaves the binding valid with the value.
	edit.OpenBao.Policy = `path "kv/data/sample/alpha" { capabilities = ["read"] }`
	if _, err := c.SavePolicy(ctx, edit, "operator-1"); err != nil {
		t.Fatalf("SavePolicy(no placeholder) = %v", err)
	}
	current, err = c.store.Binding(ctx, bound.ID)
	if err != nil || !reflect.DeepEqual(current.Settings.Values, map[string]string{"slug": "alpha"}) {
		t.Fatalf("binding after the edit = %#v, %v", current.Settings, err)
	}
}

func TestBindingValuesSurviveStorage(t *testing.T) {
	ctx := context.Background()
	fixture := newValueFixture(t)
	bound, err := fixture.h.controller.CreateBinding(ctx, "host-a", fixture.key, valueSelection(map[string]string{"slug": "alpha"}), "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	var stored store.Binding
	if stored, err = fixture.h.controller.store.Binding(ctx, bound.ID); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"slug": "alpha"}
	if !reflect.DeepEqual(stored.Settings.Values, want) || !reflect.DeepEqual(stored.Effective.Settings.Values, want) {
		t.Fatalf("stored settings = %#v", stored.Settings)
	}
}
