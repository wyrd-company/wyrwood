// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/controller"
	"github.com/wyrd-company/wyrwood/internal/policy"
)

var selectedTabPattern = regexp.MustCompile(`role="tab" aria-selected="true"[^>]*>([^<]*)`)

// selectedTab reads the tab the real frontend selects for a real answer.
func selectedTab(t *testing.T, raw []byte) string {
	t.Helper()
	match := selectedTabPattern.FindStringSubmatch(renderedPage(t, raw))
	if match == nil {
		t.Fatalf("no selected tab in %s", renderedPage(t, raw))
	}
	return match[1]
}

// assertProblemAboveTabs proves the problem is shown outside every panel.
func assertProblemAboveTabs(t *testing.T, raw []byte) {
	t.Helper()
	body := renderedPage(t, raw)
	problem, tabs := strings.Index(body, `class="problem"`), strings.Index(body, `role="tablist"`)
	if problem < 0 || tabs < problem {
		t.Fatalf("problem at %d, tabs at %d: %s", problem, tabs, body)
	}
}

func policyForm(token string, change map[string]string) url.Values {
	form := url.Values{"csrf": {token}, "new": {"yes"}, "name": {"tabbed"}, "hcl": {samplePolicyHCL}, "mount-target": {"/run/wyrwood"}}
	for name, value := range change {
		form.Set(name, value)
	}
	return form
}

func TestRefusedPolicySaveSelectsTheTabThatOwnsTheProblem(t *testing.T) {
	fixture := newScreenFixture(t)
	for _, test := range []struct {
		name   string
		change map[string]string
		query  string
		owner  string
		tab    string
	}{
		{"name has no owner", map[string]string{"name": "Not Valid"}, "", "", "OpenBao policy"},
		{"name keeps the submitted tab", map[string]string{"name": "Not Valid"}, "?tab=ssh-identities", "", "SSH identities"},
		{"HCL OpenBao refuses", map[string]string{"hcl": `path "unfinished" {`}, "?tab=container-contract", "openbao-policy", "OpenBao policy"},
		{"HCL too long", map[string]string{"hcl": strings.Repeat("#", 65537)}, "?tab=ssh-identities", "openbao-policy", "OpenBao policy"},
		{"token lifecycle", map[string]string{"agent-token-renewal": "maybe"}, "?tab=ssh-identities", "openbao-policy", "OpenBao policy"},
		{"transit key not confirmed", map[string]string{"transit-keys": "absent-key"}, "", "ssh-identities", "SSH identities"},
		{"SSH role not confirmed", map[string]string{"ca-roles": "absent-role"}, "", "ssh-identities", "SSH identities"},
		{"identity name invalid", map[string]string{"transit-keys": "not/valid"}, "", "ssh-identities", "SSH identities"},
		{"mount target", map[string]string{"mount-target": "relative"}, "", "container-contract", "Container contract"},
		{"environment line", map[string]string{"env": "no-equals"}, "", "container-contract", "Container contract"},
		{"environment name", map[string]string{"env": "1BAD=value"}, "", "container-contract", "Container contract"},
	} {
		t.Run(test.name, func(t *testing.T) {
			failed := fixture.post(t, "/policies"+test.query, policyForm(fixture.token, test.change))
			if failed.status != 422 || failed.data.Problem == "" || failed.data.ProblemTab != test.owner {
				t.Fatalf("refused = %d %q owner %q, want %q", failed.status, failed.data.Problem, failed.data.ProblemTab, test.owner)
			}
			if got := selectedTab(t, failed.raw); got != test.tab {
				t.Fatalf("selected %q, want %q", got, test.tab)
			}
			assertProblemAboveTabs(t, failed.raw)
		})
	}
}

func TestSavedPolicyKeepsItsTabAndAConflictSelectsTheContract(t *testing.T) {
	fixture := newScreenFixture(t)
	saved := fixture.post(t, "/policies?tab=container-contract", policyForm(fixture.token, nil))
	target, err := url.Parse(saved.url)
	if err != nil || target.Query().Get("tab") != "container-contract" || target.Query().Get("notice") != "saved" {
		t.Fatalf("saved = %s, %v", saved.url, err)
	}
	if got := selectedTab(t, saved.raw); got != "Container contract" {
		t.Fatalf("selected %q", got)
	}
	// No tab in the action leaves the address as it was.
	if plain := fixture.post(t, "/policies", policyForm(fixture.token, map[string]string{"name": "plain"})); strings.Contains(plain.url, "tab=") {
		t.Fatalf("plain = %s", plain.url)
	}
	// Saving a policy that a bound sibling cannot compose with is a contract problem.
	fixture.post(t, "/bindings", url.Values{"agent": {"host-a"}, "container": {"shared-id"}, "key": {"compose:sample/worker"},
		"policies": {"first", "second"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}})
	conflict := fixture.post(t, "/policies", url.Values{"csrf": {fixture.token}, "name": {"first"}, "hcl": {samplePolicyHCL}, "mount-target": {"/run/other"}})
	if conflict.status != 422 || conflict.data.ProblemTab != "container-contract" {
		t.Fatalf("conflict = %d %q owner %q", conflict.status, conflict.data.Problem, conflict.data.ProblemTab)
	}
}

func TestRefusedBindSelectsTheTabThatOwnsTheProblem(t *testing.T) {
	fixture := newScreenFixture(t)
	valid := func(change map[string]string) url.Values {
		form := url.Values{"agent": {"host-a"}, "container": {"shared-id"}, "key": {"compose:sample/worker"}, "policies": {"first"},
			"token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}, "revision": {"0"}}
		for name, value := range change {
			if value == "" {
				form.Del(name)
			} else {
				form.Set(name, value)
			}
		}
		return form
	}
	const first, settings = "Key and policies", "Settings"
	for _, test := range []struct {
		name   string
		change map[string]string
		query  string
		owner  string
		tab    string
	}{
		{"key", map[string]string{"key": "name:"}, "?tab=settings", "key-and-policies", first},
		{"no policy", map[string]string{"policies": ""}, "?tab=settings", "key-and-policies", first},
		{"unknown policy", map[string]string{"policies": "absent"}, "?tab=effective-policy", "key-and-policies", first},
		{"TTL", map[string]string{"token-ttl": "soon"}, "", "settings", settings},
		{"maximum lifetime", map[string]string{"token-max-ttl": "soon"}, "", "settings", settings},
		{"maximum below TTL", map[string]string{"token-ttl": "9h"}, "", "settings", settings},
		{"access group", map[string]string{"access-group": "not-a-gid"}, "", "settings", settings},
		{"access group range", map[string]string{"access-group": "4294967295"}, "", "settings", settings},
		{"enforcement", map[string]string{"enforcement": "other"}, "", "settings", settings},
		{"recreate acknowledgement", map[string]string{"enforcement": "recreate"}, "", "settings", settings},
	} {
		t.Run(test.name, func(t *testing.T) {
			failed := fixture.post(t, "/bindings"+test.query, valid(test.change))
			if failed.status != 422 || failed.page != "binding" || failed.data.ProblemTab != test.owner {
				t.Fatalf("refused = %d %s %q owner %q, want %q", failed.status, failed.page, failed.data.Problem, failed.data.ProblemTab, test.owner)
			}
			if got := selectedTab(t, failed.raw); got != test.tab {
				t.Fatalf("selected %q, want %q", got, test.tab)
			}
			assertProblemAboveTabs(t, failed.raw)
		})
	}
	t.Run("composition conflict", func(t *testing.T) {
		if _, err := fixture.harness.controller.Store().SavePolicy(context.Background(), conflictingPolicy("elsewhere"), "operator", time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		form := valid(nil)
		form["policies"] = []string{"first", "elsewhere"}
		failed := fixture.post(t, "/bindings?tab=settings", form)
		if failed.status != 422 || failed.data.ProblemTab != "key-and-policies" || !strings.Contains(failed.data.Problem, "conflicts") {
			t.Fatalf("conflict = %d %q owner %q", failed.status, failed.data.Problem, failed.data.ProblemTab)
		}
		if got := selectedTab(t, failed.raw); got != first {
			t.Fatalf("selected %q", got)
		}
	})
}

func conflictingPolicy(name string) policy.Policy {
	document := policy.New(name, samplePolicyHCL)
	document.Contract.MountTarget = "/run/elsewhere"
	return document
}

func TestRefusedBindingChangeSelectsTheOwnerAndKeepsAnUnownedTab(t *testing.T) {
	fixture := newScreenFixture(t)
	binding := fixture.bind(t, "host-a")
	path := "/bindings/" + binding.ID
	form := func(change map[string]string) url.Values {
		values := url.Values{"policies": {"first"}, "revision": {"1"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}}
		for name, value := range change {
			if value == "" {
				values.Del(name)
			} else {
				values.Set(name, value)
			}
		}
		return values
	}
	for _, test := range []struct {
		name   string
		target string
		change map[string]string
		owner  string
		tab    string
	}{
		{"no policy", "/policy?tab=settings", map[string]string{"policies": ""}, "policies", "Policies"},
		{"unknown policy", "/policy?tab=status", map[string]string{"policies": "absent"}, "policies", "Policies"},
		{"TTL", "/policy?tab=policies", map[string]string{"token-ttl": "soon"}, "settings", "Settings"},
		{"revision conflict keeps the tab", "/policy?tab=settings", map[string]string{"revision": "7"}, "", "Settings"},
		{"revision conflict on the first tab", "/policy", map[string]string{"revision": "7"}, "", "Status"},
	} {
		t.Run(test.name, func(t *testing.T) {
			failed := fixture.post(t, path+test.target, form(test.change))
			if failed.status != 422 || failed.data.ProblemTab != test.owner {
				t.Fatalf("refused = %d %q owner %q, want %q", failed.status, failed.data.Problem, failed.data.ProblemTab, test.owner)
			}
			if got := selectedTab(t, failed.raw); got != test.tab {
				t.Fatalf("selected %q, want %q", got, test.tab)
			}
			assertProblemAboveTabs(t, failed.raw)
		})
	}
	// No agent is connected, so the controller refuses the recreate.
	recreate := fixture.post(t, path+"/recreate?container=shared-id&tab=settings", url.Values{})
	if recreate.status != 422 || recreate.data.ProblemTab != "" {
		t.Fatalf("recreate = %d owner %q", recreate.status, recreate.data.ProblemTab)
	}
	if got := selectedTab(t, recreate.raw); got != "Settings" {
		t.Fatalf("selected %q", got)
	}
	assertProblemAboveTabs(t, recreate.raw)

	confirm := fixture.get(t, path+"/recreate?container=shared-id&tab=settings")
	if !strings.Contains(string(confirm.raw), "tab=settings") {
		t.Fatalf("confirm screen drops the tab: %s", confirm.raw)
	}

	saved := fixture.post(t, path+"/policy?q=kept&tab=settings", form(map[string]string{"token-ttl": "2h"}))
	target, err := url.Parse(saved.url)
	if err != nil || target.Query().Get("tab") != "settings" || target.Query().Get("q") != "kept" || target.Query().Get("notice") != "changed" {
		t.Fatalf("saved = %s, %v", saved.url, err)
	}
	if got := selectedTab(t, saved.raw); got != "Settings" {
		t.Fatalf("selected %q", got)
	}
	if strings.Contains(saved.data.Back, "tab=") {
		t.Fatalf("the list link carries a tab: %s", saved.data.Back)
	}
}

func TestBindKeepsItsTabWhenTheBoundScreenHasIt(t *testing.T) {
	fixture := newScreenFixture(t)
	bound := fixture.post(t, "/bindings?tab=settings", url.Values{"agent": {"host-a"}, "container": {"shared-id"}, "key": {"compose:sample/worker"},
		"policies": {"first"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}})
	target, err := url.Parse(bound.url)
	if err != nil || target.Query().Get("tab") != "settings" || target.Query().Get("notice") != "bound" {
		t.Fatalf("bound = %s, %v", bound.url, err)
	}
	if got := selectedTab(t, bound.raw); got != "Settings" {
		t.Fatalf("selected %q", got)
	}
	unbound := fixture.post(t, "/bindings/"+bound.data.Row.BindingID+"/unbind?tab=settings", url.Values{})
	if strings.Contains(unbound.url, "tab=") {
		t.Fatalf("the list keeps a tab: %s", unbound.url)
	}
}

func TestNotReportedBindingHasNoSetupTabOrContractCheck(t *testing.T) {
	fixture := newScreenFixture(t)
	binding := fixture.bind(t, "host-a")
	if err := fixture.harness.controller.Store().SaveInventory(context.Background(), "host-a", "host-a", nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	screen := fixture.get(t, "/bindings/"+binding.ID+"?tab=container-setup")
	body := renderedPage(t, screen.raw)
	if screen.data.Reported || strings.Contains(body, "Container setup") || strings.Contains(body, "Contract check") {
		t.Fatalf("not-reported screen = %s", body)
	}
	if got := selectedTab(t, screen.raw); got != "Status" {
		t.Fatalf("selected %q", got)
	}
}

func TestPostFormFieldsIgnoreTheTabInTheAddress(t *testing.T) {
	fixture := newScreenFixture(t)
	saved := fixture.post(t, "/policies?tab=hcl&name=from-address&hcl=from-address", policyForm(fixture.token, nil))
	if saved.status != 200 {
		t.Fatalf("saved = %d %s", saved.status, saved.raw)
	}
	stored, err := fixture.harness.controller.Store().Policy(context.Background(), "tabbed")
	if err != nil || stored.Policy.OpenBao.Policy != samplePolicyHCL {
		t.Fatalf("stored = %#v, %v", stored, err)
	}
}

func TestProblemTabMapsEveryPart(t *testing.T) {
	for _, test := range []struct {
		part        policy.Part
		saved       string
		bind, bound string
	}{
		{policy.PartName, "", "", ""},
		{policy.PartOpenBao, "openbao-policy", "key-and-policies", "policies"},
		{policy.PartSSH, "ssh-identities", "key-and-policies", "policies"},
		{policy.PartContract, "container-contract", "key-and-policies", "policies"},
		{policy.PartKey, "", "key-and-policies", ""},
		{policy.PartSelection, "", "key-and-policies", "policies"},
		{policy.PartSettings, "", "settings", "settings"},
		{"", "", "", ""},
	} {
		err := &controller.OperationError{Message: "sample", Part: test.part}
		if got := policyProblemTab(err); got != test.saved {
			t.Errorf("%q policy tab = %q, want %q", test.part, got, test.saved)
		}
		if got := bindingProblemTab(err, false); got != test.bind {
			t.Errorf("%q bind tab = %q, want %q", test.part, got, test.bind)
		}
		if got := bindingProblemTab(err, true); got != test.bound {
			t.Errorf("%q bound tab = %q, want %q", test.part, got, test.bound)
		}
	}
}
