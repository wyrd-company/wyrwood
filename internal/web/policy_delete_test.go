// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
)

const (
	policyDeletePath     = "/policies/delete?name="
	policyDeletePageName = "policy-delete"
	freePolicy           = "free-policy"
	freePolicyACL        = "wyrwood-free-policy"
	boundPolicy          = "sample-policy"
	boundPolicyACL       = "wyrwood-sample-policy"
)

type deleteResponse struct {
	status   int
	location string
	page     string
	data     policyDeletePage
	raw      []byte
}

func noRedirects(client *http.Client) *http.Client {
	return &http.Client{Jar: client.Jar, Timeout: client.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func readDelete(t *testing.T, response *http.Response, err error) deleteResponse {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	result := deleteResponse{status: response.StatusCode, location: response.Header.Get("Location"), raw: body}
	if match := pageDataPattern.FindSubmatch(body); match != nil {
		var payload struct {
			Page string
			Data policyDeletePage
		}
		if err := json.Unmarshal(match[1], &payload); err != nil {
			t.Fatal(err)
		}
		result.page, result.data = payload.Page, payload.Data
	}
	return result
}

func (fixture listFixture) deleteToken(t *testing.T) string {
	t.Helper()
	return csrf(t, get(t, fixture.client, fixture.harness.site.URL+"/policies/edit").body)
}

func (fixture listFixture) confirmDelete(t *testing.T, name string) deleteResponse {
	t.Helper()
	response, err := noRedirects(fixture.client).Get(fixture.harness.site.URL + policyDeletePath + url.QueryEscape(name))
	return readDelete(t, response, err)
}

func (fixture listFixture) deletePolicy(t *testing.T, name string) deleteResponse {
	t.Helper()
	response, err := noRedirects(fixture.client).PostForm(fixture.harness.site.URL+policyDeletePath+url.QueryEscape(name), url.Values{"csrf": {fixture.deleteToken(t)}})
	return readDelete(t, response, err)
}

// published saves a policy through the controller, so that OpenBao holds it.
func (fixture listFixture) published(t *testing.T, name string) policy.Policy {
	t.Helper()
	saved, err := fixture.harness.controller.SavePolicy(fixture.ctx, policy.New(name, samplePolicyHCL), "operator")
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

func (fixture listFixture) acl(t *testing.T, name string) string {
	t.Helper()
	acl, err := fixture.harness.bao.Root.Sys().GetPolicy(name)
	if err != nil {
		t.Fatal(err)
	}
	return acl
}

func (fixture listFixture) stored(t *testing.T, name string) bool {
	t.Helper()
	_, err := fixture.harness.controller.Store().Policy(fixture.ctx, name)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	return err == nil
}

func (fixture listFixture) lastDeleteEvent(t *testing.T) events.Event {
	t.Helper()
	var last *events.Event
	recent := fixture.harness.controller.Events().Recent(1000)
	for index := range recent {
		if recent[index].Operation == events.OperationPolicyDeleted {
			last = &recent[index]
		}
	}
	if last == nil {
		t.Fatal("no policy-deleted event")
	}
	return *last
}

func blockerIDs(rows []bindingRow) []string {
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	return ids
}

func TestPolicyDeleteConfirmNamesThePolicyAndItsOpenBaoPolicy(t *testing.T) {
	fixture := newListFixture(t)
	fixture.published(t, freePolicy)
	screen := fixture.confirmDelete(t, freePolicy)
	if screen.status != http.StatusOK || screen.page != policyDeletePageName {
		t.Fatalf("confirm = %d %s", screen.status, screen.raw)
	}
	data := screen.data
	if !strings.Contains(data.Heading, freePolicy) || !strings.Contains(data.Body, freePolicyACL) {
		t.Fatalf("confirm does not name both: %q %q", data.Heading, data.Body)
	}
	if data.Action != policyDeletePath+freePolicy || data.Back != policyEditPath+freePolicy || !data.Danger || data.Button != "Delete policy" || len(data.Blockers) != 0 {
		t.Fatalf("confirm = %#v", data)
	}
	if !fixture.stored(t, freePolicy) || fixture.acl(t, freePolicyACL) == "" {
		t.Fatal("opening the confirm screen changed the policy")
	}
}

func TestPolicyDeletePostRemovesThePolicyAndItsOpenBaoPolicy(t *testing.T) {
	fixture := newListFixture(t)
	fixture.published(t, freePolicy)
	before := fixture.acl(t, baotest.ControllerName)
	done := fixture.deletePolicy(t, freePolicy)
	if done.status != http.StatusSeeOther || done.location != "/policies?notice=policy-deleted" {
		t.Fatalf("delete = %d %q %s", done.status, done.location, done.raw)
	}
	if fixture.stored(t, freePolicy) || fixture.acl(t, freePolicyACL) != "" {
		t.Fatal("the policy remains")
	}
	if !fixture.stored(t, boundPolicy) || fixture.acl(t, baotest.ControllerName) != before {
		t.Fatal("another policy changed")
	}
	list := loadPage[policiesPage](t, fixture, "/policies?notice=policy-deleted", "policies")
	if !strings.Contains(list.Notice, "Policy deleted") {
		t.Fatalf("notice = %q", list.Notice)
	}
	for _, summary := range list.Policies {
		if summary.Name == freePolicy {
			t.Fatal("the list still shows the policy")
		}
	}
	event := fixture.lastDeleteEvent(t)
	if event.Policy != freePolicy || event.Outcome != events.OutcomeOK || event.Operator == "" {
		t.Fatalf("event = %#v", event)
	}
}

// Every stored binding blocks: reported, not reported, and on an agent that is
// pending or rejected. The rows match the policy page, and link to their screens.
func TestPolicyDeleteRefusalShowsEveryBlockingBinding(t *testing.T) {
	fixture := newListFixture(t)
	want := []string{"b-a-gone", "b-a-replica", "b-a-sample", "b-b-sample", "b-pending", "b-rejected"}
	screen := fixture.confirmDelete(t, boundPolicy)
	if screen.status != http.StatusOK || screen.page != policyDeletePageName {
		t.Fatalf("confirm = %d %s", screen.status, screen.raw)
	}
	assertBlockers := func(t *testing.T, rows []bindingRow) {
		t.Helper()
		got := blockerIDs(rows)
		sortedGot, sortedWant := append([]string(nil), got...), append([]string(nil), want...)
		slices.Sort(sortedGot)
		slices.Sort(sortedWant)
		if !reflect.DeepEqual(sortedGot, sortedWant) {
			t.Fatalf("blockers = %v, want %v", got, want)
		}
		for _, row := range rows {
			if !strings.HasPrefix(row.Screen, "/bindings/"+row.ID) {
				t.Fatalf("row %s links to %q", row.ID, row.Screen)
			}
		}
	}
	assertBlockers(t, screen.data.Blockers)
	if screen.data.Action != "" || screen.data.Button != "" || !strings.Contains(screen.data.Heading, "cannot be deleted") || !strings.Contains(screen.data.Body, "6 bindings") {
		t.Fatalf("refusal offers a delete: %#v", screen.data.confirmPage)
	}
	if notReported := policyRow(t, policyPage{BindingRows: screen.data.Blockers}, "b-a-gone"); notReported.Badge != "Not reported" {
		t.Fatalf("b-a-gone badge = %q", notReported.Badge)
	}
	if pending := policyRow(t, policyPage{BindingRows: screen.data.Blockers}, "b-pending"); !pending.AgentNotApproved {
		t.Fatal("b-pending is not marked")
	}
	if rejected := policyRow(t, policyPage{BindingRows: screen.data.Blockers}, "b-rejected"); !rejected.AgentNotApproved {
		t.Fatal("b-rejected is not marked")
	}
}

// A direct POST, past the screen that hides the action.
func TestPolicyDeleteDirectPostIsRefusedWhileBound(t *testing.T) {
	fixture := newListFixture(t)
	data := fixture.harness.controller.Store()
	saved, err := data.Policy(fixture.ctx, boundPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.harness.controller.OpenBao().WritePolicy(fixture.ctx, saved.Policy.OpenBaoPolicyName(), saved.Policy.PublishedHCL()); err != nil {
		t.Fatal(err)
	}
	acl := fixture.acl(t, boundPolicyACL)
	before, err := data.Bindings(fixture.ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	refused := fixture.deletePolicy(t, boundPolicy)
	if refused.status != http.StatusUnprocessableEntity || refused.page != policyDeletePageName || !strings.Contains(refused.data.Problem, "bindings still select") {
		t.Fatalf("refused = %d %s", refused.status, refused.raw)
	}
	if len(refused.data.Blockers) != len(before) || refused.data.Action != "" {
		t.Fatalf("refusal = %v, action %q", blockerIDs(refused.data.Blockers), refused.data.Action)
	}
	stored, err := data.Policy(fixture.ctx, boundPolicy)
	if err != nil || stored.Policy.Revision != saved.Policy.Revision {
		t.Fatalf("policy changed: %#v %v", stored, err)
	}
	if fixture.acl(t, boundPolicyACL) != acl || acl == "" {
		t.Fatal("OpenBao policy changed")
	}
	after, err := data.Bindings(fixture.ctx, "")
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("bindings changed: %v", err)
	}
	event := fixture.lastDeleteEvent(t)
	if event.Policy != boundPolicy || event.Outcome != events.OutcomeDenied || event.ErrorCode != events.ErrorPolicyDenied || event.Operator == "" {
		t.Fatalf("event = %#v", event)
	}
}

// The name comes from the query, as the form action states it. A name in the
// form cannot select another policy.
func TestPolicyDeleteTakesItsNameOnlyFromTheQuery(t *testing.T) {
	fixture := newListFixture(t)
	fixture.published(t, freePolicy)
	response, err := noRedirects(fixture.client).PostForm(fixture.harness.site.URL+"/policies/delete", url.Values{"csrf": {fixture.deleteToken(t)}, "name": {freePolicy}})
	missing := readDelete(t, response, err)
	if missing.status != http.StatusNotFound || !fixture.stored(t, freePolicy) {
		t.Fatalf("form name = %d, stored = %v", missing.status, fixture.stored(t, freePolicy))
	}
}

func TestPolicyDeleteOfAGonePolicyIsAClearMessage(t *testing.T) {
	fixture := newListFixture(t)
	fixture.published(t, freePolicy)
	if done := fixture.deletePolicy(t, freePolicy); done.status != http.StatusSeeOther {
		t.Fatalf("delete = %d %s", done.status, done.raw)
	}
	for name, response := range map[string]deleteResponse{"post": fixture.deletePolicy(t, freePolicy), "confirm": fixture.confirmDelete(t, freePolicy)} {
		if response.status != http.StatusNotFound || response.page != "confirm" || !strings.Contains(response.data.Body, "may have deleted") || response.data.Action != "" || response.data.Back != "/policies" {
			t.Fatalf("%s = %d %s", name, response.status, response.raw)
		}
	}
	event := fixture.lastDeleteEvent(t)
	if event.Policy != freePolicy || event.Outcome != events.OutcomeDenied {
		t.Fatalf("event = %#v", event)
	}
	again, err := fixture.harness.controller.SavePolicy(fixture.ctx, policy.New(freePolicy, samplePolicyHCL), "operator")
	if err != nil || again.Revision != 1 {
		t.Fatalf("reused name = %#v %v", again, err)
	}
}

func TestPolicyDeleteCraftedNamesReachNothing(t *testing.T) {
	fixture := newListFixture(t)
	before := fixture.acl(t, baotest.ControllerName)
	for _, name := range []string{"", "../controller", "wyrwood-sample-policy/../controller", "controller", "SAMPLE-POLICY"} {
		for label, response := range map[string]deleteResponse{"post": fixture.deletePolicy(t, name), "confirm": fixture.confirmDelete(t, name)} {
			if response.status != http.StatusNotFound || response.data.Action != "" {
				t.Fatalf("%s %q = %d %s", label, name, response.status, response.raw)
			}
		}
	}
	if fixture.acl(t, baotest.ControllerName) != before || !fixture.stored(t, boundPolicy) {
		t.Fatal("a crafted name changed a policy")
	}
}
