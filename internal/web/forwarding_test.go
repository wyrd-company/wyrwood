// ---
// relationships:
//   verifies:
//     - policy
//     - web-interface
//     - agent-controller-protocol
// ---

package web

import (
	"bytes"
	"context"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
	"github.com/wyrd-company/wyrwood/internal/web/oidctest"
)

func TestNotForwardablePolicyEditorPersistenceAndTransport(t *testing.T) {
	harness := startHarness(t, time.Hour)
	client := browser(t)
	harness.signIn(t, client, operator, oidctest.TamperNone)
	page := get(t, client, harness.site.URL+"/policies/edit")
	values := url.Values{
		"csrf": {csrf(t, page.body)}, "new": {"yes"}, "name": {"sample"}, "hcl": {`path "kv/data/sample/*" { capabilities = ["read"] }`},
		"mount-target": {"/run/wyrwood"}, "enforcement": {"report"},
		"not-forwardable-transit-keys": {"sample-key"}, "not-forwardable-ca-roles": {"sample-role"},
	}
	// Selectors do not themselves offer identities or require new OpenBao keys.
	saved := post(t, client, harness.site.URL+"/policies", values)
	if !strings.Contains(saved.body, "Policy saved") ||
		!strings.Contains(saved.body, `name="not-forwardable-transit-keys" value="sample-key"`) ||
		!strings.Contains(saved.body, `name="not-forwardable-ca-roles" value="sample-role"`) {
		t.Fatalf("saved editor lost selectors: %s", saved.body)
	}
	stored, err := harness.controller.Store().Policy(context.Background(), "sample")
	if err != nil {
		t.Fatal(err)
	}
	message := protocol.PolicySet{OpenBao: protocol.OpenBao{Address: "http://127.0.0.1:8200"}, Bindings: []protocol.Binding{{
		Binding: "b-1", Key: protocol.Key{Kind: protocol.KeyName, Value: "sample"}, Policy: (stored.Policy).Runtime(policy.DefaultSettings()), Assignment: ((stored.Policy).Runtime(
			policy.DefaultSettings())).Identity(),
	}}}
	wire, err := protocol.Encode(message)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := protocol.Decode(bytes.TrimSuffix(wire, []byte("\n")))
	if err != nil {
		t.Fatal(err)
	}
	restored := decoded.(protocol.PolicySet).Bindings[0].Policy.Clone()
	want := &policy.SSHIdentityNames{TransitKeys: []string{"sample-key"}, CARoles: []string{"sample-role"}}
	if restored.SSH == nil || !reflect.DeepEqual(restored.SSH.NotForwardable, want) {
		t.Fatalf("persisted/transmitted selectors = %#v, want %#v", restored.SSH, want)
	}
	// A later save can remove the restriction.
	values.Del("new")
	values.Set("not-forwardable-transit-keys", "")
	values.Set("not-forwardable-ca-roles", "")
	cleared := post(t, client, harness.site.URL+"/policies", values)
	if !strings.Contains(cleared.body, "Policy saved") {
		t.Fatalf("clear selectors: %s", cleared.body)
	}
	stored, err = harness.controller.Store().Policy(context.Background(), "sample")
	if err != nil || stored.Policy.SSH != nil {
		t.Fatalf("cleared selectors = %#v, %v", stored.Policy.SSH, err)
	}
}
