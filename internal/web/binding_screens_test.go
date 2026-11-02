// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/protocol"
	"github.com/wyrd-company/wyrwood/internal/web/oidctest"
)

const samplePolicyHCL = `path "kv/data/sample/*" { capabilities = ["read"] }`

// screenFixture is two approved agents reporting the same container ID, a
// pending agent reporting one container, and two policies.
type screenFixture struct {
	harness *harness
	client  *http.Client
	token   string
}

func newScreenFixture(t *testing.T) screenFixture {
	t.Helper()
	h := startHarness(t, time.Hour)
	client := browser(t)
	signedIn := h.signIn(t, client, operator, oidctest.TamperNone)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	for _, agent := range []struct {
		name  string
		state store.AgentState
	}{{"host-a", store.AgentApproved}, {"host-b", store.AgentApproved}, {"pending-host", store.AgentPending}} {
		if _, err := h.controller.Store().RecordKey(ctx, agent.name, agent.name, "ssh-ed25519 AAAA", now); err != nil {
			t.Fatal(err)
		}
		if agent.state != store.AgentPending {
			if _, err := h.controller.Store().DecideAgent(ctx, agent.name, agent.state, "operator", now); err != nil {
				t.Fatal(err)
			}
		}
		containers := []protocol.Container{{ID: "shared-id", Name: "sample-" + agent.name, Image: "busybox:latest", State: protocol.StateRunning,
			ConsumerDirectory: "/srv/sample/" + agent.name, Keys: []protocol.Key{{Kind: protocol.KeyCompose, Value: "sample/worker"}, {Kind: protocol.KeyName, Value: "sample-" + agent.name}}}}
		if err := h.controller.Store().SaveInventory(ctx, agent.name, agent.name, containers, now); err != nil {
			t.Fatal(err)
		}
	}
	fixture := screenFixture{harness: h, client: client, token: csrf(t, signedIn.body)}
	for _, name := range []string{"first", "second"} {
		saved := post(t, client, h.site.URL+"/policies", url.Values{"csrf": {fixture.token}, "new": {"yes"}, "name": {name},
			"hcl": {samplePolicyHCL}, "mount-target": {"/run/wyrwood"}})
		if !strings.Contains(saved.body, "Policy saved") {
			t.Fatalf("save policy %s = %s", name, saved.body)
		}
	}
	return fixture
}

type screenResponse struct {
	status int
	url    string
	page   string
	data   bindingScreen
	raw    []byte
}

func readScreen(t *testing.T, response *http.Response, err error) screenResponse {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	result := screenResponse{status: response.StatusCode, url: response.Request.URL.String(), raw: body}
	match := pageDataPattern.FindSubmatch(body)
	if match == nil {
		return result
	}
	var payload struct {
		Page string
		Data bindingScreen
	}
	if err := json.Unmarshal(match[1], &payload); err != nil {
		t.Fatal(err)
	}
	result.page, result.data = payload.Page, payload.Data
	return result
}

func (fixture screenFixture) get(t *testing.T, path string) screenResponse {
	t.Helper()
	response, err := fixture.client.Get(fixture.harness.site.URL + path)
	return readScreen(t, response, err)
}

func (fixture screenFixture) post(t *testing.T, path string, form url.Values) screenResponse {
	t.Helper()
	form.Set("csrf", fixture.token)
	response, err := fixture.client.PostForm(fixture.harness.site.URL+path, form)
	return readScreen(t, response, err)
}

func (fixture screenFixture) bind(t *testing.T, agent string) store.Binding {
	t.Helper()
	bound := fixture.post(t, "/bindings", url.Values{"agent": {agent}, "container": {"shared-id"}, "key": {"compose:sample/worker"},
		"policies": {"first"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}})
	if bound.status != http.StatusOK || bound.page != "binding" {
		t.Fatalf("bind = %d %s", bound.status, bound.raw)
	}
	bindings, err := fixture.harness.controller.Store().Bindings(context.Background(), agent)
	if err != nil || len(bindings) != 1 {
		t.Fatalf("bindings = %#v, %v", bindings, err)
	}
	return bindings[0]
}

func selectedPolicies(choices []policyChoice) []string {
	selected := []string{}
	for _, choice := range choices {
		if choice.Selected {
			selected = append(selected, choice.Name)
		}
	}
	return selected
}

func TestBindScreenRendersFormFromTheAgentsReport(t *testing.T) {
	fixture := newScreenFixture(t)
	screen := fixture.get(t, "/bindings/new?agent=host-b&container=shared-id&q=sample&sort=agent&order=desc&next=https://example.com/")
	if screen.status != http.StatusOK || screen.page != "binding" {
		t.Fatalf("screen = %d %s", screen.status, screen.raw)
	}
	if screen.data.Row.Agent != "host-b" || screen.data.Row.Name != "sample-host-b" || !screen.data.Reported {
		t.Fatalf("row = %#v", screen.data.Row)
	}
	if screen.data.Form.Key != "compose:sample/worker" {
		t.Fatalf("preselected key = %q", screen.data.Form.Key)
	}
	if len(screen.data.Row.Candidates) != 2 || screen.data.Row.Candidates[0].Note != "most stable" {
		t.Fatalf("candidates = %#v", screen.data.Row.Candidates)
	}
	if want := []string{"first", "second"}; len(screen.data.Policies) != 2 || screen.data.Policies[0].Name != want[0] || len(selectedPolicies(screen.data.Policies)) != 0 {
		t.Fatalf("policies = %#v", screen.data.Policies)
	}
	back, err := url.Parse(screen.data.Back)
	if err != nil || back.Path != "/bindings/add" || !reflect.DeepEqual(back.Query(), url.Values{"q": {"sample"}, "sort": {"agent"}, "order": {"desc"}}) {
		t.Fatalf("back = %q", screen.data.Back)
	}
	body := renderedPage(t, screen.raw)
	for _, want := range []string{"Bind by key", "Binding settings", "I understand the writable layer", "Preview effective policy", `name="agent" value="host-b"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("bind screen lacks %q: %s", want, body)
		}
	}
	if strings.Contains(body, "https://example.com") {
		t.Fatalf("bind screen follows a request-supplied URL: %s", body)
	}
}

func TestBindScreenForBoundContainerGoesToItsBinding(t *testing.T) {
	fixture := newScreenFixture(t)
	binding := fixture.bind(t, "host-a")
	screen := fixture.get(t, "/bindings/new?agent=host-a&container=shared-id&q=sample")
	target, err := url.Parse(screen.url)
	if err != nil || target.Path != "/bindings/"+binding.ID || target.Query().Get("q") != "sample" || screen.data.Row.BindingID != binding.ID {
		t.Fatalf("redirect = %s %#v", screen.url, screen.data.Row)
	}
}

func TestBoundScreenTakesTheAgentFromTheRecord(t *testing.T) {
	fixture := newScreenFixture(t)
	binding := fixture.bind(t, "host-b")
	screen := fixture.get(t, "/bindings/"+binding.ID+"?agent=host-a&container=shared-id")
	if screen.status != http.StatusOK || screen.page != "binding" || screen.data.Row.Agent != "host-b" || screen.data.Row.Name != "sample-host-b" {
		t.Fatalf("screen = %d %#v", screen.status, screen.data.Row)
	}
	body := renderedPage(t, screen.raw)
	for _, want := range []string{"Bound by compose key", "Contract check", "Container setup", "/srv/sample/host-b", "Save binding", "Request recreate", "Unbind and revoke AppRole", `name="agent" value="host-b"`, "AppRole assignment applied"} {
		if !strings.Contains(body, want) {
			t.Fatalf("bound screen lacks %q: %s", want, body)
		}
	}
	// A failed save with a forged agent still shows the binding's own agent.
	forged := fixture.post(t, "/bindings/"+binding.ID+"/policy", url.Values{"agent": {"host-a"}, "policies": {"absent"}, "revision": {"1"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}})
	if forged.status != http.StatusUnprocessableEntity || forged.data.Row.Agent != "host-b" {
		t.Fatalf("forged = %d %#v", forged.status, forged.data.Row)
	}
}

func TestBoundScreenOnlySelectsContainersItsKeyMatches(t *testing.T) {
	fixture := newScreenFixture(t)
	binding := fixture.bind(t, "host-a")
	ctx := context.Background()
	store := fixture.harness.controller.Store()
	worker := func(id, name string) protocol.Container {
		return protocol.Container{ID: id, Name: name, Image: "busybox:latest", State: protocol.StateRunning, Keys: []protocol.Key{{Kind: protocol.KeyCompose, Value: "sample/worker"}, {Kind: protocol.KeyName, Value: name}}}
	}
	other := protocol.Container{ID: "other-id", Name: "unrelated", Image: "alpine:latest", State: protocol.StateRunning, Keys: []protocol.Key{{Kind: protocol.KeyName, Value: "unrelated"}}}
	if err := store.SaveInventory(ctx, "host-a", "host-a", []protocol.Container{worker("one-id", "worker-1"), worker("two-id", "worker-2"), other}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := fixture.get(t, "/bindings/"+binding.ID+"?container=two-id").data.Row; got.ID != "two-id" {
		t.Fatalf("preferred container = %#v", got)
	}
	if got := fixture.get(t, "/bindings/"+binding.ID+"?container=other-id").data.Row; got.ID != "one-id" {
		t.Fatalf("unmatched preference selected %#v", got)
	}
	if got := fixture.get(t, "/bindings/"+binding.ID).data.Row; got.ID != "one-id" {
		t.Fatalf("default container = %#v", got)
	}
}

func TestBoundScreenWithoutAReportedContainerStillOffersTheBinding(t *testing.T) {
	fixture := newScreenFixture(t)
	binding := fixture.bind(t, "host-a")
	if err := fixture.harness.controller.Store().SaveInventory(context.Background(), "host-a", "host-a", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	screen := fixture.get(t, "/bindings/"+binding.ID)
	if screen.status != http.StatusOK || screen.data.Reported || screen.data.Row.Agent != "host-a" || !screen.data.Row.Bound || screen.data.Row.Checks != nil || screen.data.Row.Setup != nil {
		t.Fatalf("screen = %d %#v", screen.status, screen.data)
	}
	body := renderedPage(t, screen.raw)
	if !strings.Contains(body, "does not report a container") || !strings.Contains(body, "Unbind and revoke AppRole") {
		t.Fatalf("unreported binding = %s", body)
	}
}

func TestFailedCreateStaysOnBindScreenWithEnteredValues(t *testing.T) {
	fixture := newScreenFixture(t)
	form := url.Values{"agent": {"host-a"}, "container": {"shared-id"}, "key": {"name:sample-host-a"}, "policies": {"first", "absent"},
		"token-ttl": {"45m"}, "token-max-ttl": {"2h"}, "access-group": {""}, "enforcement": {"recreate"}, "understood": {"yes"}, "revision": {"0"}}
	failed := fixture.post(t, "/bindings?q=sample&order=desc", form)
	if failed.status != http.StatusUnprocessableEntity || failed.page != "binding" || failed.data.Problem == "" {
		t.Fatalf("failed = %d %s %s", failed.status, failed.page, failed.raw)
	}
	data := failed.data
	if data.Row.Agent != "host-a" || data.Row.ID != "shared-id" || data.Row.Bound {
		t.Fatalf("row = %#v", data.Row)
	}
	want := bindingForm{Key: "name:sample-host-a", Policies: []string{"first", "absent"}, Understood: true,
		Settings: enteredSettings{TokenTTL: "45m", TokenMaxTTL: "2h", Enforcement: "recreate"}}
	if !reflect.DeepEqual(data.Form, want) {
		t.Fatalf("form = %#v, want %#v", data.Form, want)
	}
	if got := selectedPolicies(data.Policies); !reflect.DeepEqual(got, []string{"first"}) {
		t.Fatalf("selected = %v", got)
	}
	if data.Back != "/bindings/add?order=desc&q=sample" || !strings.HasPrefix(data.Action, "/bindings?") {
		t.Fatalf("back = %q action = %q", data.Back, data.Action)
	}
	if bindings, _ := fixture.harness.controller.Store().Bindings(context.Background(), "host-a"); len(bindings) != 0 {
		t.Fatalf("failed create saved %#v", bindings)
	}
	body := renderedPage(t, failed.raw)
	if !strings.Contains(body, data.Problem) || !strings.Contains(body, "Bind by key") {
		t.Fatalf("failed screen = %s", body)
	}

	// A key the container does not offer falls back to its most stable key.
	unknownKey := fixture.post(t, "/bindings", url.Values{"agent": {"host-a"}, "container": {"shared-id"}, "key": {"name:other"},
		"policies": {"absent"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}})
	if unknownKey.data.Form.Key != "compose:sample/worker" {
		t.Fatalf("fallback key = %q", unknownKey.data.Form.Key)
	}

	// Text that does not parse is returned for the operator to correct.
	unparsed := fixture.post(t, "/bindings", url.Values{"agent": {"host-a"}, "container": {"shared-id"}, "key": {"compose:sample/worker"},
		"policies": {"first"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "access-group": {"not-a-gid"}, "enforcement": {"report"}})
	if unparsed.status != http.StatusUnprocessableEntity || !strings.Contains(unparsed.data.Problem, "numeric GID") || unparsed.data.Form.Settings.AccessGroup != "not-a-gid" {
		t.Fatalf("unparsed = %d %#v", unparsed.status, unparsed.data)
	}

	// Recreate acknowledgement still gates the first bind.
	unconfirmed := fixture.post(t, "/bindings", url.Values{"agent": {"host-a"}, "container": {"shared-id"}, "key": {"compose:sample/worker"},
		"policies": {"first"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"recreate"}})
	if unconfirmed.status != http.StatusUnprocessableEntity || !strings.Contains(unconfirmed.data.Problem, "confirm before binding") || unconfirmed.data.Form.Settings.Enforcement != "recreate" || unconfirmed.data.Form.Understood {
		t.Fatalf("unconfirmed = %d %#v", unconfirmed.status, unconfirmed.data)
	}
}

func TestCreateConflictShowsTheSavedBinding(t *testing.T) {
	fixture := newScreenFixture(t)
	binding := fixture.bind(t, "host-a")
	again := fixture.post(t, "/bindings", url.Values{"agent": {"host-a"}, "container": {"shared-id"}, "key": {"compose:sample/worker"},
		"policies": {"second"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}})
	if again.status != http.StatusUnprocessableEntity || !strings.Contains(again.data.Problem, "already bound") || again.data.Row.BindingID != binding.ID || !reflect.DeepEqual(selectedPolicies(again.data.Policies), []string{"first"}) {
		t.Fatalf("again = %d %#v", again.status, again.data)
	}
}

func TestCreateSavedBeforeOpenBaoRefusedShowsTheBinding(t *testing.T) {
	fixture := newScreenFixture(t)
	// Without AppRole write access the binding saves and its assignment stays pending.
	restricted := strings.ReplaceAll(baotest.ControllerPolicy, `path "auth/approle/role/wyrwood-*" { capabilities = ["create", "read", "update", "delete", "list"] }`, "")
	if err := fixture.harness.bao.Root.Sys().PutPolicy(baotest.ControllerName, restricted); err != nil {
		t.Fatal(err)
	}
	// The container is not reported, so only the saved record can show this binding.
	failed := fixture.post(t, "/bindings", url.Values{"agent": {"host-a"}, "container": {"gone-id"}, "key": {"name:gone"},
		"policies": {"first"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}})
	if failed.status != http.StatusUnprocessableEntity || failed.page != "binding" || !strings.Contains(failed.data.Problem, "binding saved") || !failed.data.Row.Bound || failed.data.Reported || failed.data.Row.Applied {
		t.Fatalf("failed = %d %s %#v", failed.status, failed.page, failed.data)
	}
	if !strings.Contains(renderedPage(t, failed.raw), "Token transition pending") {
		t.Fatal("pending transition state is not shown")
	}
}

func TestSuccessfulCreateGoesToTheBindingScreen(t *testing.T) {
	fixture := newScreenFixture(t)
	bound := fixture.post(t, "/bindings?q=sample", url.Values{"agent": {"host-a"}, "container": {"shared-id"}, "key": {"compose:sample/worker"},
		"policies": {"first"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}})
	target, err := url.Parse(bound.url)
	if err != nil || !strings.HasPrefix(target.Path, "/bindings/b-") || target.Query().Get("q") != "sample" || target.Query().Get("container") != "shared-id" {
		t.Fatalf("redirect = %s", bound.url)
	}
	if !strings.Contains(bound.data.Notice, "Policy bound") || bound.data.Row.ID != "shared-id" || bound.data.Back != "/bindings?q=sample" {
		t.Fatalf("bound = %#v", bound.data)
	}
}

func TestFailedChangeStaysOnBoundScreenWithEnteredValues(t *testing.T) {
	fixture := newScreenFixture(t)
	binding := fixture.bind(t, "host-a")
	path := "/bindings/" + binding.ID
	failed := fixture.post(t, path+"/policy?container=shared-id&q=sample", url.Values{"policies": {"second", "absent"}, "revision": {"1"},
		"token-ttl": {"20m"}, "token-max-ttl": {"3h"}, "enforcement": {"report"}})
	if failed.status != http.StatusUnprocessableEntity || failed.page != "binding" || failed.data.Problem == "" {
		t.Fatalf("failed = %d %s", failed.status, failed.raw)
	}
	data := failed.data
	if !reflect.DeepEqual(selectedPolicies(data.Policies), []string{"second"}) || data.Form.Settings.TokenTTL != "20m" || data.Form.Settings.TokenMaxTTL != "3h" {
		t.Fatalf("entered values = %#v %#v", data.Policies, data.Form)
	}
	if !reflect.DeepEqual(data.Row.Policies, []string{"first"}) {
		t.Fatalf("saved assignment display = %#v", data.Row.Policies)
	}
	if data.Screen != path+"?container=shared-id&q=sample" || data.Action != path+"/policy?container=shared-id&q=sample" {
		t.Fatalf("links = %q %q", data.Screen, data.Action)
	}
	stored, err := fixture.harness.controller.Store().Binding(context.Background(), binding.ID)
	if err != nil || stored.Revision != binding.Revision || !slices.Equal(stored.Policies, []string{"first"}) {
		t.Fatalf("stored = %#v, %v", stored, err)
	}

	stale := fixture.post(t, path+"/policy", url.Values{"policies": {"second"}, "revision": {"7"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}})
	if stale.status != http.StatusUnprocessableEntity || !strings.Contains(stale.data.Problem, "reload") || stale.data.Form.Revision != 7 {
		t.Fatalf("stale = %d %#v", stale.status, stale.data)
	}
	if !strings.Contains(renderedPage(t, stale.raw), "Reload saved values") {
		t.Fatal("stale screen has no way to reload saved values")
	}

	changed := fixture.post(t, path+"/policy?q=sample&container=shared-id", url.Values{"policies": {"second"}, "revision": {"1"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}})
	target, err := url.Parse(changed.url)
	if err != nil || target.Path != path || target.Query().Get("notice") != "changed" || target.Query().Get("q") != "sample" {
		t.Fatalf("changed = %s", changed.url)
	}
	if !reflect.DeepEqual(changed.data.Row.Policies, []string{"second"}) || changed.data.Form.Revision != 2 {
		t.Fatalf("changed data = %#v", changed.data)
	}
}

func TestPreviewRefusesAnInvalidSelectionWithAnActionableMessage(t *testing.T) {
	fixture := newScreenFixture(t)
	form := url.Values{"csrf": {fixture.token}, "policies": {"absent"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}}
	response, err := fixture.client.PostForm(fixture.harness.site.URL+"/bindings/preview", form)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnprocessableEntity || result.Error == "" || result.Error == "The operation failed." {
		t.Fatalf("preview = %d %q", response.StatusCode, result.Error)
	}
}

func TestConfirmationsReturnToTheBindingScreen(t *testing.T) {
	fixture := newScreenFixture(t)
	binding := fixture.bind(t, "host-a")
	path := "/bindings/" + binding.ID
	context := "?container=shared-id&order=desc&q=sample"
	for _, action := range []string{"recreate", "unbind"} {
		screen := fixture.get(t, path+"/"+action+context)
		var payload struct {
			Page string
			Data confirmPage
		}
		if err := json.Unmarshal(pageDataPattern.FindSubmatch(screen.raw)[1], &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Page != "confirm" || payload.Data.Back != path+context || payload.Data.Action != path+"/"+action+context {
			t.Fatalf("%s confirm = %#v", action, payload)
		}
		if !strings.Contains(renderedPage(t, screen.raw), "Cancel") {
			t.Fatalf("%s confirm has no cancel", action)
		}
	}
	// The screen's own links carry the context to the confirmations.
	screen := fixture.get(t, path+context)
	if screen.data.Recreate != path+"/recreate"+context || screen.data.Unbind != path+"/unbind"+context {
		t.Fatalf("links = %q %q", screen.data.Recreate, screen.data.Unbind)
	}
}

func TestFailedRecreateStaysOnTheBindingScreen(t *testing.T) {
	fixture := newScreenFixture(t)
	binding := fixture.bind(t, "host-a")
	// No agent is connected, so the controller refuses the recreate.
	failed := fixture.post(t, "/bindings/"+binding.ID+"/recreate?container=shared-id", url.Values{})
	if failed.status != http.StatusUnprocessableEntity || failed.page != "binding" || failed.data.Problem == "" || failed.data.Row.BindingID != binding.ID {
		t.Fatalf("failed recreate = %d %s %s", failed.status, failed.page, failed.raw)
	}
}

func TestUnbindReturnsToTheList(t *testing.T) {
	fixture := newScreenFixture(t)
	binding := fixture.bind(t, "host-a")
	unbound := fixture.post(t, "/bindings/"+binding.ID+"/unbind?q=sample", url.Values{})
	target, err := url.Parse(unbound.url)
	if err != nil || target.Path != "/bindings" || target.Query().Get("q") != "sample" || target.Query().Get("filter-agent") != "host-a" || !strings.HasPrefix(target.Query().Get("notice"), "unbound") {
		t.Fatalf("unbound = %s", unbound.url)
	}
}

func TestUnknownBindingIsNotFound(t *testing.T) {
	fixture := newScreenFixture(t)
	for _, test := range []struct {
		name string
		get  func() screenResponse
	}{
		{"screen", func() screenResponse { return fixture.get(t, "/bindings/b-absent") }},
		{"recreate confirmation", func() screenResponse { return fixture.get(t, "/bindings/b-absent/recreate") }},
		{"unbind confirmation", func() screenResponse { return fixture.get(t, "/bindings/b-absent/unbind") }},
		{"change", func() screenResponse {
			return fixture.post(t, "/bindings/b-absent/policy", url.Values{"policies": {"first"}})
		}},
		{"recreate", func() screenResponse { return fixture.post(t, "/bindings/b-absent/recreate", url.Values{}) }},
		{"unbind", func() screenResponse { return fixture.post(t, "/bindings/b-absent/unbind", url.Values{}) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := test.get()
			if response.status != http.StatusNotFound || response.page != "confirm" {
				t.Fatalf("response = %d %s", response.status, response.page)
			}
			body := renderedPage(t, response.raw)
			if !strings.Contains(body, "Binding not found") || response.data.Back != "/bindings" {
				t.Fatalf("not found page = %s", body)
			}
		})
	}
}

func TestBindScreenForUnreportedContainerSaysSoAndLinksBack(t *testing.T) {
	fixture := newScreenFixture(t)
	for _, query := range []string{
		"?agent=host-a&container=gone-id",
		"?agent=absent-host&container=shared-id",
		"?agent=pending-host&container=shared-id",
		"?container=shared-id",
		"?agent=host-a",
		"",
	} {
		screen := fixture.get(t, "/bindings/new"+query)
		if screen.status != http.StatusNotFound || screen.page != "confirm" {
			t.Fatalf("%q = %d %s", query, screen.status, screen.page)
		}
		body := renderedPage(t, screen.raw)
		if !strings.Contains(body, "Container not reported") || screen.data.Back != "/bindings/add" || strings.Contains(body, "Bind policies") {
			t.Fatalf("%q page = %s", query, body)
		}
	}
	// A submission for a container that is gone keeps the reason.
	failed := fixture.post(t, "/bindings", url.Values{"agent": {"host-a"}, "container": {"gone-id"}, "key": {"compose:sample/worker"}, "policies": {"absent"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}})
	if failed.status != http.StatusNotFound || !strings.Contains(renderedPage(t, failed.raw), "The binding was not saved") {
		t.Fatalf("failed = %d %s", failed.status, failed.raw)
	}
}

func TestBindingScreensRequireASessionAndAntiForgeryToken(t *testing.T) {
	fixture := newScreenFixture(t)
	binding := fixture.bind(t, "host-a")
	site := fixture.harness.site.URL
	signedOut := browser(t)
	// The first answer is the session gate's, so that a route outside the gate
	// cannot pass by redirecting to one inside it.
	signedOut.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, path := range []string{"/containers", "/containers?agent=host-b", "/bindings", "/bindings/add", "/bindings/new?agent=host-b&container=shared-id", "/bindings/" + binding.ID, "/bindings/" + binding.ID + "/recreate", "/bindings/" + binding.ID + "/unbind"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			request, err := http.NewRequest(method, site+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := signedOut.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if location := response.Header.Get("Location"); response.StatusCode != http.StatusSeeOther || location != "/sign-in" {
				t.Fatalf("%s %s without a session = %d %q", method, path, response.StatusCode, location)
			}
		}
	}
	mutations := []struct {
		path string
		form url.Values
	}{
		{"/bindings", url.Values{"agent": {"host-b"}, "container": {"shared-id"}, "key": {"compose:sample/worker"}, "policies": {"first"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}}},
		{"/bindings/" + binding.ID + "/policy", url.Values{"policies": {"second"}, "revision": {"1"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}}},
		{"/bindings/" + binding.ID + "/recreate", url.Values{}},
		{"/bindings/" + binding.ID + "/unbind", url.Values{}},
	}
	ctx := context.Background()
	for _, mutation := range mutations {
		for _, token := range []string{"", "wrong-token"} {
			form := url.Values{"csrf": {token}}
			for name, values := range mutation.form {
				form[name] = values
			}
			response, err := fixture.client.PostForm(site+mutation.path, form)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != http.StatusForbidden {
				t.Fatalf("%s with token %q = %d", mutation.path, token, response.StatusCode)
			}
		}
		// The token in the query string is not a form field, so it is refused too.
		response, err := fixture.client.PostForm(site+mutation.path+"?csrf="+url.QueryEscape(fixture.token), mutation.form)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("%s with query token = %d", mutation.path, response.StatusCode)
		}
	}
	stored, err := fixture.harness.controller.Store().Binding(ctx, binding.ID)
	if err != nil || stored.Revision != binding.Revision || !slices.Equal(stored.Policies, binding.Policies) {
		t.Fatalf("forged request changed the binding: %#v %v", stored, err)
	}
	if others, _ := fixture.harness.controller.Store().Bindings(ctx, "host-b"); len(others) != 0 {
		t.Fatalf("forged request created %#v", others)
	}
	// The same request with the session's token completes.
	if changed := fixture.post(t, mutations[1].path, mutations[1].form); changed.status != http.StatusOK || !reflect.DeepEqual(changed.data.Row.Policies, []string{"second"}) {
		t.Fatalf("admitted change = %d %#v", changed.status, changed.data.Row)
	}
	if created := fixture.post(t, mutations[0].path, mutations[0].form); created.status != http.StatusOK || created.data.Row.Agent != "host-b" {
		t.Fatalf("admitted create = %d %#v", created.status, created.data.Row)
	}
}
