// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/web/oidctest"
	operatorclient "github.com/wyrd-company/wyrwood/operator"
)

func newPendingOperatorKey(t *testing.T, harness *harness, label string) string {
	t.Helper()
	fingerprint := gossh.FingerprintSHA256(mustKey(t).PublicKey())
	if _, err := harness.controller.Store().RecordOperatorKey(context.Background(), fingerprint, label, "ssh-ed25519 AAAA", time.Now()); err != nil {
		t.Fatal(err)
	}
	return fingerprint
}

func TestOperatorKeyApprovalAndRevocationThroughPages(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t, time.Hour)
	client := browser(t)
	harness.signIn(t, client, operator, oidctest.TamperNone)
	fingerprint := newPendingOperatorKey(t, harness, "presented-label")

	page := get(t, client, harness.site.URL+"/operator-keys")
	if !strings.Contains(page.body, "Pending operator keys") || !strings.Contains(page.body, fingerprint) || !strings.Contains(page.body, "presented-label") {
		t.Fatalf("operator keys page = %s", page.body)
	}
	if agents := get(t, client, harness.site.URL+"/agents"); strings.Contains(agents.body, "presented-label") {
		t.Fatalf("a pending operator key is listed with the agents: %s", agents.body)
	}
	token := csrf(t, page.body)
	values := url.Values{
		"csrf": {token}, "fingerprint": {fingerprint}, "label": {"approved-label"},
		"agents": {"host-a, host-b"}, "policies": {"sample-policy"}, "actions": {"read", "bind"},
	}
	refused := url.Values{}
	for key, list := range values {
		refused[key] = list
	}
	refused.Del("actions")
	if result := post(t, client, harness.site.URL+"/operator-keys/approve", refused); !strings.Contains(result.body, "select at least one action") {
		t.Fatalf("approval with no action = %s", result.body)
	}
	if stored, err := harness.controller.Store().OperatorKey(ctx, fingerprint); err != nil || stored.State != store.OperatorKeyPending {
		t.Fatalf("OperatorKey() = %+v, %v", stored, err)
	}

	forged := url.Values{"fingerprint": {fingerprint}, "label": {"approved-label"}, "agents": {"*"}, "policies": {"*"}, "actions": {"read"}}
	if result := post(t, client, harness.site.URL+"/operator-keys/approve", forged); result.status != http.StatusForbidden {
		t.Fatalf("approval with no CSRF token = %d", result.status)
	}

	approved := post(t, client, harness.site.URL+"/operator-keys/approve", values)
	if !strings.Contains(approved.body, "Operator key approved") || !strings.Contains(approved.body, "approved-label") || !strings.Contains(approved.body, "host-a, host-b") {
		t.Fatalf("approve = %s", approved.body)
	}
	stored, err := harness.controller.Store().OperatorKey(ctx, fingerprint)
	if err != nil || stored.State != store.OperatorKeyApproved || stored.Label != "approved-label" || stored.DecidedBy == "" {
		t.Fatalf("OperatorKey() = %+v, %v", stored, err)
	}
	want := operatorclient.Grant{Agents: []string{"host-a", "host-b"}, Policies: []string{"sample-policy"}, Actions: []operatorclient.Action{operatorclient.ActionRead, operatorclient.ActionBind}}
	if !reflect.DeepEqual(stored.Grant, want) {
		t.Fatalf("grant = %+v; want %+v", stored.Grant, want)
	}

	revokeURL := harness.site.URL + "/operator-keys/revoke?" + url.Values{"fingerprint": {fingerprint}}.Encode()
	confirm := get(t, client, revokeURL)
	if !strings.Contains(confirm.body, "Revoke approved-label?") {
		t.Fatalf("confirm = %s", confirm.body)
	}
	if after, err := harness.controller.Store().OperatorKey(ctx, fingerprint); err != nil || after.State != store.OperatorKeyApproved {
		t.Fatalf("the confirmation page revoked the key: %+v, %v", after, err)
	}
	revoked := post(t, client, revokeURL, url.Values{"csrf": {token}})
	if !strings.Contains(revoked.body, "Operator key revoked") || !strings.Contains(revoked.body, "Revoked and rejected keys") {
		t.Fatalf("revoke = %s", revoked.body)
	}
	if after, err := harness.controller.Store().OperatorKey(ctx, fingerprint); err != nil || after.State != store.OperatorKeyRevoked || after.RevokedBy == "" {
		t.Fatalf("OperatorKey() = %+v, %v", after, err)
	}
	if again := get(t, client, revokeURL); !strings.Contains(again.body, "No approved key has this fingerprint") {
		t.Fatalf("confirm of a revoked key = %s", again.body)
	}
	seen := map[events.Operation]bool{}
	for _, record := range harness.controller.Events().Recent(100) {
		if record.Fingerprint == fingerprint && record.Operator == stored.DecidedBy {
			seen[record.Operation] = true
		}
	}
	if !seen[events.OperationOperatorKeyApproved] || !seen[events.OperationOperatorKeyRevoked] {
		t.Fatalf("events = %v", seen)
	}
}

func TestOperatorKeyRejectionThroughPages(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t, time.Hour)
	client := browser(t)
	harness.signIn(t, client, operator, oidctest.TamperNone)
	fingerprint := newPendingOperatorKey(t, harness, "presented-label")
	token := csrf(t, get(t, client, harness.site.URL+"/operator-keys").body)
	rejected := post(t, client, harness.site.URL+"/operator-keys/reject", url.Values{"csrf": {token}, "fingerprint": {fingerprint}})
	if !strings.Contains(rejected.body, "Operator key rejected") {
		t.Fatalf("reject = %s", rejected.body)
	}
	if stored, err := harness.controller.Store().OperatorKey(ctx, fingerprint); err != nil || stored.State != store.OperatorKeyRejected {
		t.Fatalf("OperatorKey() = %+v, %v", stored, err)
	}
	if again := post(t, client, harness.site.URL+"/operator-keys/reject", url.Values{"csrf": {token}, "fingerprint": {fingerprint}}); !strings.Contains(again.body, "no key in the right state") {
		t.Fatalf("second reject = %s", again.body)
	}
}

func TestOperatorKeyScreenNeedsASession(t *testing.T) {
	harness := startHarness(t, time.Hour)
	if landing := get(t, browser(t), harness.site.URL+"/operator-keys"); !strings.Contains(landing.url, "/sign-in") {
		t.Fatalf("landed on %s", landing.url)
	}
}

func TestGrantListSeparatesNames(t *testing.T) {
	if got := grantList(" host-a,host-b\n host-c ,, "); !reflect.DeepEqual(got, []string{"host-a", "host-b", "host-c"}) {
		t.Fatalf("grantList() = %q", got)
	}
	if got := grantList("  "); got == nil || len(got) != 0 {
		t.Fatalf("grantList() = %#v", got)
	}
}
