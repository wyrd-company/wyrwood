// ---
// relationships:
//   verifies:
//     - web-interface
//     - operator-interface
// ---

package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/web/oidctest"
	operatorclient "github.com/wyrd-company/wyrwood/operator"
)

// The renderer unescapes attribute values, so the JSON keeps its quotes.
var previousPattern = regexp.MustCompile(`name="previous" value="(\{.*?\})"`)

// grantEditFixture runs a controller with an approved agent, the policies
// teal and amber in OpenBao, a signed-in browser, and an operator client whose
// key holds grant and has a session open.
func grantEditFixture(t *testing.T, grant operatorclient.Grant) (*harness, *http.Client, *operatorclient.Client, string) {
	t.Helper()
	ctx := context.Background()
	harness := startHarness(t, time.Hour)
	browserClient := browser(t)
	harness.signIn(t, browserClient, operator, oidctest.TamperNone)
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := harness.controller.Store().RecordKey(ctx, "sample-host", "sample-host", "ssh-ed25519 AAAA-sample-host", now); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.controller.Store().DecideAgent(ctx, "sample-host", store.AgentApproved, "operator", now); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"teal", "amber"} {
		if _, err := harness.controller.SavePolicy(ctx, policy.New(name, samplePolicyHCL), "operator"); err != nil {
			t.Fatal(err)
		}
	}
	key := mustKey(t)
	settings := operatorclient.Config{URL: harness.controller.URL, Signer: key, HostKey: harness.controller.Fingerprint, Label: "menagerie", Timeout: 5 * time.Second}
	if _, err := operatorclient.Login(ctx, settings, nil); err != nil {
		t.Fatal(err)
	}
	fingerprint := gossh.FingerprintSHA256(key.PublicKey())
	if err := harness.controller.ApproveOperatorKey(ctx, fingerprint, "menagerie", grant, "approver"); err != nil {
		t.Fatal(err)
	}
	client, err := operatorclient.Dial(ctx, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return harness, browserClient, client, fingerprint
}

// Adding a policy to a key is one edit in the web interface. The client the
// key opened before the edit binds the policy on its next request, with no new
// key, configuration change, restart, or revocation.
func TestAKeyGainsAPolicyWithOneEditInTheWebInterface(t *testing.T) {
	ctx := context.Background()
	before := operatorclient.Grant{Agents: []string{"sample-host"}, Policies: []string{"teal"}, Actions: []operatorclient.Action{operatorclient.ActionRead, operatorclient.ActionBind}}
	harness, browserClient, client, fingerprint := grantEditFixture(t, before)
	approved, err := harness.controller.Store().OperatorKey(ctx, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	request := operatorclient.BindRequest{Agent: "sample-host", Key: operatorclient.Key{Kind: operatorclient.KeyName, Value: "workspace"}, Policies: []string{"amber", "teal"}}
	if _, err := client.Bind(ctx, request); !errors.Is(err, operatorclient.ErrOutsideGrant) {
		t.Fatalf("Bind() before the edit = %v; want outside the grant", err)
	}

	list := get(t, browserClient, harness.site.URL+"/operator-keys")
	editURL := "/operator-keys/grant?" + url.Values{"fingerprint": {fingerprint}}.Encode()
	if !strings.Contains(list.body, `href="`+editURL+`"`) {
		t.Fatalf("the approved key has no Edit grant link: %s", list.body)
	}
	editor := get(t, browserClient, harness.site.URL+editURL)
	for _, want := range []string{"Edit grant", "menagerie", fingerprint, "What this key can do", ">Validate<", ">Save<", `checked="" value="teal"`} {
		if !strings.Contains(editor.body, want) {
			t.Fatalf("the grant editor has no %s: %s", want, editor.body)
		}
	}
	for _, absent := range []string{"Review", "Cancel", "cannot be changed"} {
		if strings.Contains(editor.body, absent) {
			t.Fatalf("the grant editor holds %q: %s", absent, editor.body)
		}
	}
	previous := previousPattern.FindStringSubmatch(editor.body)
	if previous == nil {
		t.Fatalf("the grant editor holds no previous grant: %s", editor.body)
	}
	saved := post(t, browserClient, harness.site.URL+"/operator-keys/grant", url.Values{
		"csrf": {csrf(t, editor.body)}, "fingerprint": {fingerprint}, "previous": {previous[1]},
		"agents": {"sample-host", ""}, "policies": {"teal", "amber", ""}, "actions": {"read", "bind"},
	})
	if !strings.Contains(saved.body, "Grant saved.") || !strings.Contains(saved.body, `checked="" value="amber"`) {
		t.Fatalf("save = %s", saved.body)
	}

	bound, err := client.Bind(ctx, request)
	if err != nil {
		t.Fatalf("Bind() on the open session after the edit = %v", err)
	}
	if !slices.Equal(bound.Policies, []string{"amber", "teal"}) {
		t.Fatalf("bound policies = %v", bound.Policies)
	}
	identity, err := client.Whoami(ctx)
	if err != nil || identity.Label != "menagerie" || identity.Fingerprint != fingerprint {
		t.Fatalf("Whoami() = %+v, %v", identity, err)
	}
	edited, err := harness.controller.Store().OperatorKey(ctx, fingerprint)
	if err != nil || edited.Label != approved.Label || edited.PublicKey != approved.PublicKey || edited.State != store.OperatorKeyApproved ||
		!edited.DecidedAt.Equal(approved.DecidedAt) || edited.DecidedBy != approved.DecidedBy {
		t.Fatalf("the edit changed the key: %+v; was %+v", edited, approved)
	}
	if want := []string{"teal", "amber"}; !slices.Equal(edited.Grant.Policies, want) {
		t.Fatalf("policies = %v; want %v", edited.Grant.Policies, want)
	}
	subject := ""
	for _, event := range harness.controller.Events().Recent(1000) {
		if event.Operation == events.OperationOperatorKeyGrantChanged && event.Fingerprint == fingerprint {
			subject = event.Operator
		}
	}
	if subject == "" || strings.HasPrefix(subject, "key:") {
		t.Fatalf("the edit is recorded with operator %q; want the operator who signed in", subject)
	}
}

// A save that starts from a grant the key no longer holds changes nothing, and
// the editor keeps the edit and says why.
func TestAStaleGrantEditIsRefused(t *testing.T) {
	ctx := context.Background()
	before := operatorclient.Grant{Agents: []string{"sample-host"}, Policies: []string{"teal"}, Actions: []operatorclient.Action{operatorclient.ActionRead}}
	harness, browserClient, _, fingerprint := grantEditFixture(t, before)
	editor := get(t, browserClient, harness.site.URL+"/operator-keys/grant?"+url.Values{"fingerprint": {fingerprint}}.Encode())
	previous := previousPattern.FindStringSubmatch(editor.body)
	if previous == nil {
		t.Fatalf("the grant editor holds no previous grant: %s", editor.body)
	}
	other := before
	other.Actions = []operatorclient.Action{operatorclient.ActionRead, operatorclient.ActionBind}
	if err := harness.controller.ChangeOperatorKeyGrant(ctx, fingerprint, before, other, "other-operator"); err != nil {
		t.Fatal(err)
	}
	refused := post(t, browserClient, harness.site.URL+"/operator-keys/grant", url.Values{
		"csrf": {csrf(t, editor.body)}, "fingerprint": {fingerprint}, "previous": {previous[1]},
		"agents": {"sample-host", ""}, "policies": {"teal", "amber", ""}, "actions": {"read"},
	})
	if refused.status != http.StatusUnprocessableEntity || !strings.Contains(refused.body, "changed after you opened it") ||
		!strings.Contains(refused.body, `checked="" value="amber"`) {
		t.Fatalf("stale save = %d %s", refused.status, refused.body)
	}
	if stored, err := harness.controller.Store().OperatorKey(ctx, fingerprint); err != nil || !store.SameGrant(stored.Grant, other) {
		t.Fatalf("a stale save changed the grant: %+v, %v", stored, err)
	}
	forged := post(t, browserClient, harness.site.URL+"/operator-keys/grant", url.Values{
		"fingerprint": {fingerprint}, "previous": {previous[1]}, "agents": {"*"}, "policies": {"*"}, "actions": {"read", "bind", "policy-write"},
	})
	if forged.status != http.StatusForbidden {
		t.Fatalf("a save with no CSRF token = %d", forged.status)
	}
	if missing := get(t, browserClient, harness.site.URL+"/operator-keys/grant?fingerprint=SHA256%3Aunknown"); !strings.Contains(missing.body, "No approved key has this fingerprint") {
		t.Fatalf("editor of an unknown key = %s", missing.body)
	}
}
