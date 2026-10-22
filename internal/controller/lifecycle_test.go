// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package controller

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
	gossh "golang.org/x/crypto/ssh"
)

func TestLifecycleSettingPublishesAndReplacesBindingAssignment(t *testing.T) {
	ctx := context.Background()
	h := startHarness(t)
	c := h.controller
	key := newAgentKey(t)
	_, _ = h.dial("host-a", key)
	if err := c.DecideAgent(ctx, gossh.FingerprintSHA256(key.PublicKey()), true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	disabled := false
	p := policy.New("sample", `path "auth/*" {capabilities=["update"]}
path "auth/token/renew-self" {capabilities=["update"]}`)
	p.OpenBao.AgentTokenRenewal = &disabled
	saved, err := c.SavePolicy(ctx, p, "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := c.store.Policy(ctx, p.Name)
	if err != nil || stored.Policy.OpenBao.AgentTokenRenewal == nil || stored.Policy.AgentRenewal() {
		t.Fatal("disabled setting did not survive storage")
	}
	published, err := h.bao.Root.Sys().GetPolicy(p.OpenBaoPolicyName())
	if err != nil || published != p.PublishedHCL() {
		t.Fatalf("published lifecycle = %q, %v", published, err)
	}
	selection := BindingRequest{Policies: []string{p.Name}, Settings: policy.DefaultSettings()}
	preview, err := c.PreviewBinding(ctx, selection)
	if err != nil || preview.AgentRenewal() || !strings.Contains(preview.OpenBao.Policy, policy.LifecycleHCL(false)) {
		t.Fatal("preview lost disabled lifecycle")
	}
	b, err := c.CreateBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "sample"}, selection, "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	token, err := appRoleLogin(t, h.bao, b.Role)
	if err != nil {
		t.Fatal(err)
	}
	for path, cap := range map[string]string{"auth/token/lookup-self": "read", "auth/token/revoke-self": "update", "auth/token/renew-self": ""} {
		caps, err := h.bao.Root.Sys().Capabilities(token.Value(), path)
		if err != nil || (cap != "" && !slices.Contains(caps, cap)) || (cap == "" && slices.Contains(caps, "update")) {
			t.Fatalf("%s capabilities = %v, %v", path, caps, err)
		}
	}
	if err := c.store.SaveAssignmentAccessor(ctx, b, token.Accessor, c.now()); err != nil {
		t.Fatal(err)
	}
	enabled := true
	saved.OpenBao.AgentTokenRenewal = &enabled
	if _, err := c.SavePolicy(ctx, saved, "operator-1"); err != nil {
		t.Fatal(err)
	}
	current, err := c.store.Binding(ctx, b.ID)
	if err != nil || !current.Effective.AgentRenewal() || current.Assignment() == b.Assignment() {
		t.Fatal("setting edit did not change effective assignment")
	}
	if tokenValid(t, h.bao, token) {
		t.Fatal("old-assignment token survived setting change")
	}
	replacement, err := appRoleLogin(t, h.bao, current.Role)
	if err != nil {
		t.Fatal(err)
	}
	caps, err := h.bao.Root.Sys().Capabilities(replacement.Value(), "auth/token/renew-self")
	if err != nil || !slices.Contains(caps, "update") {
		t.Fatalf("replacement renewal = %v, %v", caps, err)
	}
}

func TestLifecycleCompositionGrantsRenewalWhenAnyPolicyEnablesIt(t *testing.T) {
	ctx := context.Background()
	h := startHarness(t)
	c := h.controller
	off := false
	for _, name := range []string{"alpha", "beta"} {
		p := policy.New(name, "")
		if name == "alpha" {
			p.OpenBao.AgentTokenRenewal = &off
		}
		if _, err := c.SavePolicy(ctx, p, "operator-1"); err != nil {
			t.Fatal(err)
		}
	}
	effective, err := c.PreviewBinding(ctx, BindingRequest{Policies: []string{"alpha", "beta"}})
	if err != nil || !effective.AgentRenewal() {
		t.Fatal("mixed composition disabled renewal")
	}
	secret, err := h.bao.Root.Auth().Token().Create(&api.TokenCreateRequest{Policies: effective.OpenBaoPolicies(), NoDefaultPolicy: true, TTL: "2m"})
	if err != nil {
		t.Fatal(err)
	}
	caps, err := h.bao.Root.Sys().Capabilities(secret.Auth.ClientToken, "auth/token/renew-self")
	if err != nil || !slices.Contains(caps, "update") {
		t.Fatalf("mixed policy renewal = %v, %v", caps, err)
	}
}
