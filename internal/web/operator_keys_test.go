// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
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

// grantFixture holds approved and pending agents and two stored policies, so
// that the approval form offers names to choose.
func grantFixture(t *testing.T) (*harness, *http.Client, string) {
	t.Helper()
	ctx := context.Background()
	harness := startHarness(t, time.Hour)
	client := browser(t)
	harness.signIn(t, client, operator, oidctest.TamperNone)
	now := time.Now().UTC().Truncate(time.Second)
	for _, agent := range []struct {
		name  string
		state store.AgentState
	}{{"agent-b", store.AgentApproved}, {"agent-a", store.AgentApproved}, {"pending-agent", store.AgentPending}, {"rejected-agent", store.AgentRejected}} {
		if _, err := harness.controller.Store().RecordKey(ctx, agent.name, agent.name, "ssh-ed25519 AAAA-"+agent.name, now); err != nil {
			t.Fatal(err)
		}
		if agent.state != store.AgentPending {
			if _, err := harness.controller.Store().DecideAgent(ctx, agent.name, agent.state, "operator", now); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, name := range []string{"policy-y", "policy-x"} {
		if _, err := harness.controller.Store().SavePolicy(ctx, policy.New(name, samplePolicyHCL), "operator", now); err != nil {
			t.Fatal(err)
		}
	}
	return harness, client, csrf(t, get(t, client, harness.site.URL+"/operator-keys").body)
}

func TestOperatorKeyFormOffersOnlyGrantNames(t *testing.T) {
	harness, client, _ := grantFixture(t)
	newPendingOperatorKey(t, harness, "presented-label")
	response, err := client.Get(harness.site.URL + "/operator-keys")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	match := pageDataPattern.FindSubmatch(body)
	if match == nil {
		t.Fatalf("no page data in %s", body)
	}
	var payload struct {
		Data struct {
			GrantAgents   []string
			GrantPolicies []string
		}
	}
	if err := json.Unmarshal(match[1], &payload); err != nil {
		t.Fatal(err)
	}
	if want := []string{"agent-a", "agent-b"}; !reflect.DeepEqual(payload.Data.GrantAgents, want) {
		t.Fatalf("GrantAgents = %q; want %q", payload.Data.GrantAgents, want)
	}
	if want := []string{"policy-x", "policy-y"}; !reflect.DeepEqual(payload.Data.GrantPolicies, want) {
		t.Fatalf("GrantPolicies = %q; want %q", payload.Data.GrantPolicies, want)
	}
	// The page carries names only: no pending or rejected agent, no agent key,
	// and no policy source.
	for _, absent := range []string{"pending-agent", "rejected-agent", "AAAA-agent", "kv/data/sample"} {
		if bytes.Contains(body, []byte(absent)) {
			t.Fatalf("the operator keys page holds %q", absent)
		}
	}
	page := renderedPage(t, body)
	for _, want := range []string{`value="*"`, `value="agent-a"`, `value="policy-y"`, "All agents, including agents approved later", "What this key can do", "A grant cannot be changed after approval."} {
		if !strings.Contains(page, want) {
			t.Fatalf("the approval form has no %s: %s", want, page)
		}
	}
}

func TestOperatorKeyApprovalThroughGrantControls(t *testing.T) {
	ctx := context.Background()
	harness, client, token := grantFixture(t)
	all := []operatorclient.Action{operatorclient.ActionRead, operatorclient.ActionBind, operatorclient.ActionPolicyWrite}
	// Each case posts what the form posts: one value per selected name, and the
	// typed names as one more value, which is empty when nothing is typed.
	for index, test := range []struct {
		name     string
		agents   []string
		policies []string
		actions  []string
		want     operatorclient.Grant
		refusal  string
	}{
		{name: "all names", agents: []string{"*"}, policies: []string{"*"}, actions: []string{"read"},
			want: operatorclient.Grant{Agents: []string{"*"}, Policies: []string{"*"}, Actions: []operatorclient.Action{operatorclient.ActionRead}}},
		{name: "one name", agents: []string{"agent-a", ""}, policies: []string{"policy-x", ""}, actions: []string{"bind"},
			want: operatorclient.Grant{Agents: []string{"agent-a"}, Policies: []string{"policy-x"}, Actions: []operatorclient.Action{operatorclient.ActionBind}}},
		{name: "several names and typed names", agents: []string{"agent-a", "agent-b", "later-agent"}, policies: []string{"policy-x", "future-policy, other-policy"}, actions: []string{"read", "bind", "policy-write"},
			want: operatorclient.Grant{Agents: []string{"agent-a", "agent-b", "later-agent"}, Policies: []string{"policy-x", "future-policy", "other-policy"}, Actions: all}},
		{name: "the text field at the base", agents: []string{"agent-a, agent-b"}, policies: []string{"policy-x"}, actions: []string{"read", "bind"},
			want: operatorclient.Grant{Agents: []string{"agent-a", "agent-b"}, Policies: []string{"policy-x"}, Actions: []operatorclient.Action{operatorclient.ActionRead, operatorclient.ActionBind}}},
		{name: "the same choice through controls", agents: []string{"agent-a", "agent-b", ""}, policies: []string{"policy-x", ""}, actions: []string{"read", "bind"},
			want: operatorclient.Grant{Agents: []string{"agent-a", "agent-b"}, Policies: []string{"policy-x"}, Actions: []operatorclient.Action{operatorclient.ActionRead, operatorclient.ActionBind}}},
		{name: "no names", agents: []string{""}, policies: []string{""}, actions: []string{"read"},
			want: operatorclient.Grant{Agents: []string{}, Policies: []string{}, Actions: []operatorclient.Action{operatorclient.ActionRead}}},
		{name: "no action", agents: []string{"agent-a", ""}, policies: []string{"policy-x", ""}, refusal: "select at least one action"},
		{name: "* with a selected agent", agents: []string{"*", "agent-a", ""}, policies: []string{"policy-x", ""}, actions: []string{"read"}, refusal: `the agent list must hold only "*" or only names`},
		{name: "* typed beside a policy", agents: []string{"agent-a", ""}, policies: []string{"policy-x", "*"}, actions: []string{"read"}, refusal: `the policy list must hold only "*" or only names`},
		{name: "an invalid name", agents: []string{"agent-a", "bad/name"}, policies: []string{"policy-x", ""}, actions: []string{"read"}, refusal: `agent name "bad/name" is invalid`},
		{name: "an unknown action", agents: []string{"agent-a", ""}, policies: []string{"policy-x", ""}, actions: []string{"read", "admin"}, refusal: `action "admin" is not supported`},
	} {
		t.Run(test.name, func(t *testing.T) {
			fingerprint := newPendingOperatorKey(t, harness, "presented-label")
			label := fmt.Sprintf("grant-key-%d", index)
			values := url.Values{"csrf": {token}, "fingerprint": {fingerprint}, "label": {label}, "agents": test.agents, "policies": test.policies, "actions": test.actions}
			result := post(t, client, harness.site.URL+"/operator-keys/approve", values)
			stored, err := harness.controller.Store().OperatorKey(ctx, fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			if test.refusal != "" {
				if !strings.Contains(result.body, test.refusal) || stored.State != store.OperatorKeyPending {
					t.Fatalf("state %s after a refused approval: %s", stored.State, result.body)
				}
				return
			}
			if !strings.Contains(result.body, "Operator key approved") || stored.State != store.OperatorKeyApproved || stored.Label != label {
				t.Fatalf("OperatorKey() = %+v after %s", stored, result.body)
			}
			if !reflect.DeepEqual(stored.Grant, test.want) {
				t.Fatalf("grant = %#v; want %#v", stored.Grant, test.want)
			}
			recorded := false
			for _, record := range harness.controller.Events().Recent(200) {
				if record.Fingerprint == fingerprint && record.Operation == events.OperationOperatorKeyApproved && record.Operator == stored.DecidedBy {
					recorded = true
				}
			}
			if !recorded {
				t.Fatal("no operator key approval event")
			}
		})
	}

	fingerprint := newPendingOperatorKey(t, harness, "presented-label")
	forged := url.Values{"fingerprint": {fingerprint}, "label": {"forged-key"}, "agents": {"agent-a", ""}, "policies": {"policy-x", ""}, "actions": {"read"}}
	if result := post(t, client, harness.site.URL+"/operator-keys/approve", forged); result.status != http.StatusForbidden {
		t.Fatalf("approval with no CSRF token = %d", result.status)
	}
	if stored, err := harness.controller.Store().OperatorKey(ctx, fingerprint); err != nil || stored.State != store.OperatorKeyPending {
		t.Fatalf("OperatorKey() = %+v, %v", stored, err)
	}
	signedOut := browser(t)
	if landing := post(t, signedOut, harness.site.URL+"/operator-keys/approve", forged); strings.Contains(landing.body, "Operator key approved") {
		t.Fatalf("approval with no session = %s", landing.body)
	}
	if stored, err := harness.controller.Store().OperatorKey(ctx, fingerprint); err != nil || stored.State != store.OperatorKeyPending {
		t.Fatalf("OperatorKey() = %+v, %v", stored, err)
	}
}

func TestGrantNamesReadsEveryPostedValue(t *testing.T) {
	if got := grantNames([]string{"agent-a", "", "later-a, later-b"}); !reflect.DeepEqual(got, []string{"agent-a", "later-a", "later-b"}) {
		t.Fatalf("grantNames() = %q", got)
	}
	if got := grantNames(nil); got == nil || len(got) != 0 {
		t.Fatalf("grantNames(nil) = %#v", got)
	}
}
