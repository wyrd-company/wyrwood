// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
	"github.com/wyrd-company/wyrwood/internal/web/oidctest"
)

// listFixture holds approved agents host-a, host-b and empty, a pending agent
// and a rejected agent, with bindings stored directly so that each list case
// sets its own contract result.
//
//	host-a: sample-id (compose unique-project/worker, name sample) bound as b-a-sample
//	        other-id  (name zebra), unbound
//	        replica-one and replica-two (compose unique-project/replica) bound as b-a-replica
//	host-a: b-a-gone is bound by name absent-container, which no container offers
//	host-b: sample-id (name sample) bound as b-b-sample, and a container that
//	        offers host-a's compose key, unbound on host-b
//	pending and rejected: each reports a bound and an unbound container
type listFixture struct {
	harness *harness
	client  *http.Client
	ctx     context.Context
	now     time.Time
}

func nameKey(value string) protocol.Key { return protocol.Key{Kind: protocol.KeyName, Value: value} }

func composeKey(value string) protocol.Key {
	return protocol.Key{Kind: protocol.KeyCompose, Value: value}
}

// newListFixture starts the harness, after configure adjusts the controller's
// configuration when one is given.
func newListFixture(t *testing.T, configure ...func(*config.Controller)) listFixture {
	t.Helper()
	var adjust func(*config.Controller)
	if len(configure) > 0 {
		adjust = configure[0]
	}
	h := startConfiguredHarness(t, time.Hour, adjust)
	client := browser(t)
	h.signIn(t, client, operator, oidctest.TamperNone)
	fixture := listFixture{harness: h, client: client, ctx: context.Background(), now: time.Now().UTC().Truncate(time.Second)}
	data := h.controller.Store()
	if _, err := data.SavePolicy(fixture.ctx, policy.New("sample-policy", samplePolicyHCL), "operator", fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := data.SavePolicy(fixture.ctx, policy.New("other-policy", samplePolicyHCL), "operator", fixture.now); err != nil {
		t.Fatal(err)
	}
	for _, agent := range []struct {
		name       string
		state      store.AgentState
		containers []protocol.Container
	}{
		{"host-a", store.AgentApproved, []protocol.Container{
			{ID: "sample-id", Name: "sample", Image: "busybox:latest", State: protocol.StateRunning, Keys: []protocol.Key{composeKey("unique-project/worker"), nameKey("sample")}},
			{ID: "other-id", Name: "zebra", Image: "alpine:latest", State: protocol.StateExited, Keys: []protocol.Key{nameKey("zebra")}},
			{ID: "replica-two", Name: "replica-2", Image: "registry:2", State: protocol.StateRunning, Keys: []protocol.Key{composeKey("unique-project/replica"), nameKey("replica-2")}},
			{ID: "replica-one", Name: "replica-1", Image: "registry:2", State: protocol.StateRunning, Keys: []protocol.Key{composeKey("unique-project/replica"), nameKey("replica-1")}},
		}},
		{"host-b", store.AgentApproved, []protocol.Container{
			{ID: "sample-id", Name: "sample", Image: "busybox:latest", State: protocol.StateRunning, Keys: []protocol.Key{nameKey("sample")}},
			{ID: "lookalike-id", Name: "lookalike", Image: "alpine:latest", State: protocol.StateRunning, Keys: []protocol.Key{composeKey("unique-project/worker")}},
		}},
		{"empty", store.AgentApproved, nil},
		{"pending", store.AgentPending, []protocol.Container{{ID: "pending-id", Name: "pending-container", Keys: []protocol.Key{nameKey("pending-container")}}, {ID: "pending-unbound", Name: "pending-unbound", Keys: []protocol.Key{nameKey("pending-unbound")}}}},
		{"rejected", store.AgentRejected, []protocol.Container{{ID: "rejected-id", Name: "rejected-container", Keys: []protocol.Key{nameKey("rejected-container")}}, {ID: "rejected-unbound", Name: "rejected-unbound", Keys: []protocol.Key{nameKey("rejected-unbound")}}}},
	} {
		if _, err := data.RecordKey(fixture.ctx, agent.name, agent.name, "ssh-ed25519 AAAA", fixture.now); err != nil {
			t.Fatal(err)
		}
		if agent.state != store.AgentPending {
			if _, err := data.DecideAgent(fixture.ctx, agent.name, agent.state, "operator", fixture.now); err != nil {
				t.Fatal(err)
			}
		}
		if err := data.SaveInventory(fixture.ctx, agent.name, agent.name, agent.containers, fixture.now); err != nil {
			t.Fatal(err)
		}
	}
	for _, binding := range []struct {
		id, agent string
		key       protocol.Key
		policies  []string
	}{
		{"b-a-sample", "host-a", composeKey("unique-project/worker"), []string{"sample-policy"}},
		{"b-a-replica", "host-a", composeKey("unique-project/replica"), []string{"other-policy", "sample-policy"}},
		{"b-a-gone", "host-a", nameKey("absent-container"), []string{"sample-policy"}},
		{"b-b-sample", "host-b", nameKey("sample"), []string{"sample-policy"}},
		{"b-pending", "pending", nameKey("pending-container"), []string{"sample-policy"}},
		{"b-rejected", "rejected", nameKey("rejected-container"), []string{"sample-policy"}},
	} {
		if err := data.CreateBinding(fixture.ctx, store.Binding{ID: binding.id, Agent: binding.agent, Key: binding.key, Policies: binding.policies, Revision: 1, Applied: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := data.SaveContractResult(fixture.ctx, protocol.ContractResult{Binding: "b-a-sample", Outcome: protocol.OutcomeConforming}, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := data.SaveContractResult(fixture.ctx, protocol.ContractResult{Binding: "b-a-gone", Outcome: protocol.OutcomeConforming}, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := data.SaveContractResult(fixture.ctx, protocol.ContractResult{Binding: "b-b-sample", Outcome: protocol.OutcomeNonConforming}, fixture.now); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func loadPage[Data any](t *testing.T, fixture listFixture, target, wantPage string) Data {
	t.Helper()
	response, err := fixture.client.Get(fixture.harness.site.URL + target)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("%s status = %d", target, response.StatusCode)
	}
	match := pageDataPattern.FindSubmatch(body)
	if match == nil {
		t.Fatalf("%s has no page data: %s", target, body)
	}
	var payload struct {
		Page string
		Data Data
	}
	if err := json.Unmarshal(match[1], &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Page != wantPage {
		t.Fatalf("%s page = %s, want %s", target, payload.Page, wantPage)
	}
	return payload.Data
}

func (fixture listFixture) bindings(t *testing.T, query string) bindingsPage {
	t.Helper()
	return loadPage[bindingsPage](t, fixture, "/bindings"+query, "bindings")
}

func (fixture listFixture) add(t *testing.T, query string) addBindingPage {
	t.Helper()
	return loadPage[addBindingPage](t, fixture, "/bindings/add"+query, "add-binding")
}

func bindingIDs(page bindingsPage) []string {
	ids := []string{}
	for _, row := range page.Rows {
		ids = append(ids, row.ID)
	}
	return ids
}

func addIdentities(page addBindingPage) []string {
	ids := []string{}
	for _, row := range page.Rows {
		ids = append(ids, row.Agent+"/"+row.ID)
	}
	return ids
}

func rowByID(t *testing.T, page bindingsPage, id string) bindingRow {
	t.Helper()
	for _, row := range page.Rows {
		if row.ID == id {
			return row
		}
	}
	t.Fatalf("no row %s in %v", id, bindingIDs(page))
	return bindingRow{}
}

func TestBindingsListsOneRowPerStoredBindingOfAnApprovedAgent(t *testing.T) {
	fixture := newListFixture(t)
	page := fixture.bindings(t, "")
	if page.Title != "Bindings" || page.Current != "bindings" {
		t.Fatalf("layout = %q %q", page.Title, page.Current)
	}
	if got, want := bindingIDs(page), []string{"b-a-gone", "b-a-replica", "b-a-sample", "b-b-sample"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rows = %v, want %v", got, want)
	}
	if page.FilterAgent != "" || page.Sort != "name" || page.Order != "asc" || page.Add != "/bindings/add" {
		t.Fatalf("defaults = %#v", page)
	}
	want := []agentChoice{{Name: "empty"}, {Name: "host-a", Count: 3}, {Name: "host-b", Count: 1}}
	if !reflect.DeepEqual(page.Agents, want) {
		t.Fatalf("agents = %#v", page.Agents)
	}
	row := rowByID(t, page, "b-a-sample")
	if row.Agent != "host-a" || row.Connected || !row.LastReport.Equal(fixture.now) || row.KeyKind != "compose" || row.KeyValue != "unique-project/worker" ||
		!reflect.DeepEqual(row.Policies, []string{"sample-policy"}) || row.Badge != "Conforms" || row.BadgeClass != "good" {
		t.Fatalf("row = %#v", row)
	}
	if len(row.Containers) != 1 || row.Containers[0].Name != "sample" || row.Containers[0].Image != "busybox:latest" || row.Containers[0].ID != "sample-id" {
		t.Fatalf("containers = %#v", row.Containers)
	}
	if other := rowByID(t, page, "b-b-sample"); other.Badge != "Non-conforming" || other.BadgeClass != "bad" {
		t.Fatalf("state = %#v", other)
	}
}

func TestBindingRowStaysWhenItsContainerLeavesTheInventory(t *testing.T) {
	fixture := newListFixture(t)
	data := fixture.harness.controller.Store()
	before := rowByID(t, fixture.bindings(t, ""), "b-b-sample")
	if len(before.Containers) != 1 || before.Badge == "Not reported" {
		t.Fatalf("before = %#v", before)
	}
	later := fixture.now.Add(time.Minute)
	if err := data.SaveInventory(fixture.ctx, "host-b", "host-b", []protocol.Container{{ID: "lookalike-id", Name: "lookalike", Keys: []protocol.Key{composeKey("unique-project/worker")}}}, later); err != nil {
		t.Fatal(err)
	}
	page := fixture.bindings(t, "")
	after := rowByID(t, page, "b-b-sample")
	if len(after.Containers) != 0 || after.Badge != "Not reported" || after.BadgeClass != "neutral" || after.Agent != "host-b" || after.KeyKind != "name" || after.KeyValue != "sample" {
		t.Fatalf("after = %#v", after)
	}
	if after.Screen != "/bindings/b-b-sample" {
		t.Fatalf("screen = %q", after.Screen)
	}
	if after.Connected {
		t.Fatalf("connected = %#v", after)
	}
	// The binding itself is untouched, and its screen stays reachable.
	if stored, err := data.Binding(fixture.ctx, "b-b-sample"); err != nil || stored.Key != nameKey("sample") {
		t.Fatalf("stored = %#v, %v", stored, err)
	}
	screen := loadPage[bindingScreen](t, fixture, after.Screen, "binding")
	if screen.Reported || screen.Row.BindingID != "b-b-sample" || screen.Row.Badge != after.Badge {
		t.Fatalf("screen = %#v", screen)
	}
	body := renderModel(t, "bindings", page)
	for _, text := range []string{"Not reported", "No container reported", "Disconnected · last report shown", `href="/bindings/b-b-sample"`} {
		if !strings.Contains(body, text) {
			t.Fatalf("list lacks %q: %s", text, body)
		}
	}
	if strings.Contains(body, `role="alert"`) {
		t.Fatalf("a binding with no reported container reads as an error: %s", body)
	}
	// A container that offers the key again returns to the same binding.
	if err := data.SaveInventory(fixture.ctx, "host-b", "host-b", []protocol.Container{{ID: "rebuilt-id", Name: "sample", Image: "busybox:latest", Keys: []protocol.Key{nameKey("sample")}}}, later); err != nil {
		t.Fatal(err)
	}
	returned := rowByID(t, fixture.bindings(t, ""), "b-b-sample")
	if len(returned.Containers) != 1 || returned.Containers[0].ID != "rebuilt-id" || returned.Badge != "Non-conforming" {
		t.Fatalf("returned = %#v", returned)
	}
}

func TestEveryReportedContainerIsOnTheListOrTheAddScreen(t *testing.T) {
	fixture := newListFixture(t)
	page := fixture.bindings(t, "")
	seen := map[string]string{}
	for _, row := range page.Rows {
		for _, container := range row.Containers {
			seen[row.Agent+"/"+container.ID] = "binding " + row.ID
		}
	}
	for _, identity := range addIdentities(fixture.add(t, "")) {
		if where, found := seen[identity]; found {
			t.Fatalf("%s is on both pages, also as %s", identity, where)
		}
		seen[identity] = "add screen"
	}
	want := map[string]string{
		"host-a/sample-id":    "binding b-a-sample",
		"host-a/replica-one":  "binding b-a-replica",
		"host-a/replica-two":  "binding b-a-replica",
		"host-a/other-id":     "add screen",
		"host-b/sample-id":    "binding b-b-sample",
		"host-b/lookalike-id": "add screen",
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("containers = %#v, want %#v", seen, want)
	}
	replica := rowByID(t, page, "b-a-replica")
	if len(replica.Containers) != 2 || replica.Containers[0].Name != "replica-1" || replica.Containers[1].Name != "replica-2" {
		t.Fatalf("one binding must show every container it governs: %#v", replica.Containers)
	}
	body := renderModel(t, "bindings", page)
	for _, name := range []string{"replica-1", "replica-2"} {
		if !strings.Contains(body, name) {
			t.Fatalf("list lacks %s: %s", name, body)
		}
	}
}

func TestAgentIsolationOnTheLists(t *testing.T) {
	fixture := newListFixture(t)
	t.Run("a key on another agent does not match a binding", func(t *testing.T) {
		page := fixture.bindings(t, "")
		for _, container := range rowByID(t, page, "b-a-sample").Containers {
			if container.ID == "lookalike-id" {
				t.Fatalf("host-a's binding matched host-b's container: %#v", container)
			}
		}
		if got := addIdentities(fixture.add(t, "?q=lookalike")); !reflect.DeepEqual(got, []string{"host-b/lookalike-id"}) {
			t.Fatalf("host-a's key bound a host-b container: %v", got)
		}
	})
	t.Run("a shared container ID stays separate per agent", func(t *testing.T) {
		link, err := url.Parse(rowByID(t, fixture.bindings(t, ""), "b-b-sample").Containers[0].Screen)
		if err != nil || link.Path != "/bindings/b-b-sample" {
			t.Fatalf("link = %v %v", link, err)
		}
	})
	t.Run("agents that are not approved are absent from both pages", func(t *testing.T) {
		bindings := fixture.bindings(t, "")
		add := fixture.add(t, "")
		for _, name := range []string{"pending", "rejected"} {
			for _, choice := range slices.Concat(bindings.Agents, add.Agents) {
				if choice.Name == name {
					t.Fatalf("%s offered: %#v", name, choice)
				}
			}
			if got := fixture.bindings(t, "?filter-agent="+name); len(got.Rows) != 0 {
				t.Fatalf("%s bindings = %v", name, bindingIDs(got))
			}
			if got := fixture.add(t, "?filter-agent="+name); len(got.Rows) != 0 {
				t.Fatalf("%s containers = %v", name, addIdentities(got))
			}
		}
	})
}

func TestBindingsFiltersAndSorts(t *testing.T) {
	fixture := newListFixture(t)
	for _, test := range []struct {
		query string
		want  []string
	}{
		{"?filter-agent=host-b", []string{"b-b-sample"}},
		{"?filter-agent=empty", []string{}},
		{"?filter-agent=missing", []string{}},
		{"?q=%20OTHER-POLICY%20", []string{"b-a-replica"}},
		{"?q=UNIQUE-PROJECT%2Fworker", []string{"b-a-sample"}},
		{"?q=compose", []string{"b-a-replica", "b-a-sample"}},
		{"?q=not%20reported", []string{"b-a-gone"}},
		{"?q=registry", []string{"b-a-replica"}},
		{"?q=replica-two", []string{"b-a-replica"}},
		{"?q=running&filter-agent=host-b", []string{"b-b-sample"}},
		{"?q=Conforms&filter-agent=host-b", []string{}},
		{"?q=zebra", []string{}},
		{"?sort=name&order=desc", []string{"b-b-sample", "b-a-sample", "b-a-replica", "b-a-gone"}},
		{"?sort=agent&order=desc", []string{"b-b-sample", "b-a-sample", "b-a-replica", "b-a-gone"}},
		{"?sort=image", []string{"b-a-gone", "b-a-sample", "b-b-sample", "b-a-replica"}},
		{"?sort=key", []string{"b-a-replica", "b-a-sample", "b-a-gone", "b-b-sample"}},
		{"?sort=policies", []string{"b-a-replica", "b-a-gone", "b-a-sample", "b-b-sample"}},
		{"?sort=state", []string{"b-a-sample", "b-a-replica", "b-b-sample", "b-a-gone"}},
		{"?sort=unknown&order=unknown", []string{"b-a-gone", "b-a-replica", "b-a-sample", "b-b-sample"}},
	} {
		t.Run(test.query, func(t *testing.T) {
			if got := bindingIDs(fixture.bindings(t, test.query)); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("rows = %v, want %v", got, test.want)
			}
		})
	}
	t.Run("row links retain the list", func(t *testing.T) {
		page := fixture.bindings(t, "?filter-agent=host-a&q=busybox&sort=key&order=desc&next=https://example.com/")
		want := url.Values{"filter-agent": {"host-a"}, "q": {"busybox"}, "sort": {"key"}, "order": {"desc"}}
		add, err := url.Parse(page.Add)
		if err != nil || add.Path != "/bindings/add" || !reflect.DeepEqual(add.Query(), want) {
			t.Fatalf("add = %q", page.Add)
		}
		row := rowByID(t, page, "b-a-sample")
		link, err := url.Parse(row.Screen)
		if err != nil || link.Path != "/bindings/b-a-sample" || !reflect.DeepEqual(link.Query(), want) {
			t.Fatalf("screen = %q", row.Screen)
		}
		contained, err := url.Parse(row.Containers[0].Screen)
		want.Set("container", "sample-id")
		if err != nil || contained.Path != "/bindings/b-a-sample" || !reflect.DeepEqual(contained.Query(), want) {
			t.Fatalf("container screen = %q", row.Containers[0].Screen)
		}
		screen := loadPage[bindingScreen](t, fixture, row.Containers[0].Screen, "binding")
		if screen.Row.ID != "sample-id" || !strings.HasPrefix(screen.Back, "/bindings?") {
			t.Fatalf("screen = %#v %q", screen.Row, screen.Back)
		}
	})
	t.Run("the list carries no binding detail or actions", func(t *testing.T) {
		page := fixture.bindings(t, "?filter-agent=host-b")
		body := renderModel(t, "bindings", page)
		for _, absent := range []string{"<aside", "Save binding", "Bind policies", "Request recreate", "Unbind and revoke"} {
			if strings.Contains(body, absent) {
				t.Fatalf("list contains %q: %s", absent, body)
			}
		}
	})
	t.Run("a filter that matches nothing explains and clears", func(t *testing.T) {
		body := renderModel(t, "bindings", fixture.bindings(t, "?q=no-such-value"))
		if !strings.Contains(body, "No bindings match these filters.") || !strings.Contains(body, `<a href="/bindings">Clear filters</a>`) {
			t.Fatalf("message = %s", body)
		}
	})
}

func TestAddBindingListsContainersWithNoBinding(t *testing.T) {
	fixture := newListFixture(t)
	page := fixture.add(t, "")
	if page.Title != "Add binding" || page.Current != "bindings" || page.Back != "/bindings" {
		t.Fatalf("layout = %#v", page.layout)
	}
	want := []agentChoice{{Name: "empty"}, {Name: "host-a", Count: 1}, {Name: "host-b", Count: 1}}
	if !reflect.DeepEqual(page.Agents, want) {
		t.Fatalf("agents = %#v", page.Agents)
	}
	for _, test := range []struct {
		query string
		want  []string
	}{
		{"", []string{"host-b/lookalike-id", "host-a/other-id"}},
		{"?filter-agent=host-a", []string{"host-a/other-id"}},
		{"?filter-agent=empty", []string{}},
		{"?q=ZEBRA", []string{"host-a/other-id"}},
		{"?q=unique-project%2Fworker", []string{"host-b/lookalike-id"}},
		{"?q=compose", []string{"host-b/lookalike-id"}},
		{"?q=lookalike-id", []string{"host-b/lookalike-id"}},
		{"?q=exited", []string{"host-a/other-id"}},
		{"?q=sample-policy", []string{}},
		{"?sort=name&order=desc", []string{"host-a/other-id", "host-b/lookalike-id"}},
		{"?sort=agent&order=desc", []string{"host-b/lookalike-id", "host-a/other-id"}},
		{"?sort=state", []string{"host-a/other-id", "host-b/lookalike-id"}},
		{"?sort=image", []string{"host-a/other-id", "host-b/lookalike-id"}},
		{"?sort=key", []string{"host-b/lookalike-id", "host-a/other-id"}},
	} {
		t.Run("query"+test.query, func(t *testing.T) {
			if got := addIdentities(fixture.add(t, test.query)); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("rows = %v, want %v", got, test.want)
			}
		})
	}
	t.Run("selecting a container opens its bind form and comes back", func(t *testing.T) {
		query := "?filter-agent=host-a&q=zebra"
		filtered := fixture.add(t, query)
		if filtered.Back != "/bindings?filter-agent=host-a&q=zebra" {
			t.Fatalf("back to bindings = %q", filtered.Back)
		}
		row := filtered.Rows[0]
		link, err := url.Parse(row.Screen)
		if err != nil || link.Path != "/bindings/new" || link.Query().Get("agent") != "host-a" || link.Query().Get("container") != "other-id" || link.Query().Get("q") != "zebra" {
			t.Fatalf("link = %q", row.Screen)
		}
		screen := loadPage[bindingScreen](t, fixture, row.Screen, "binding")
		back, err := url.Parse(screen.Back)
		if err != nil || back.Path != "/bindings/add" || !reflect.DeepEqual(back.Query(), url.Values{"filter-agent": {"host-a"}, "q": {"zebra"}}) {
			t.Fatalf("back = %q", screen.Back)
		}
		if screen.Row.Agent != "host-a" || screen.Row.Bound {
			t.Fatalf("screen row = %#v", screen.Row)
		}
	})
	t.Run("a filter that matches nothing explains and clears", func(t *testing.T) {
		body := renderModel(t, "add-binding", fixture.add(t, "?q=no-such-value"))
		if !strings.Contains(body, "No containers match these filters.") || !strings.Contains(body, `<a href="/bindings/add">Clear filters</a>`) {
			t.Fatalf("message = %s", body)
		}
	})
	t.Run("the screen has no binding actions", func(t *testing.T) {
		body := renderModel(t, "add-binding", page)
		for _, absent := range []string{"<aside", "Save binding", "Bind policies", "Request recreate", "Unbind and revoke"} {
			if strings.Contains(body, absent) {
				t.Fatalf("add screen contains %q", absent)
			}
		}
	})
}

func TestContainersAddressRedirectsToBindings(t *testing.T) {
	fixture := newListFixture(t)
	noFollow := *fixture.client
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, test := range []struct {
		name, query string
		want        url.Values
	}{
		{"plain", "", url.Values{}},
		{"every filter", "?filter-agent=host-a&q=sample&sort=image&order=desc", url.Values{"filter-agent": {"host-a"}, "q": {"sample"}, "sort": {"image"}, "order": {"desc"}}},
		{"agent-only link from the Agents page", "?agent=host-b", url.Values{"filter-agent": {"host-b"}}},
		{"a filter wins over the agent", "?filter-agent=host-a&agent=host-b", url.Values{"filter-agent": {"host-a"}}},
		{"an empty filter means every agent", "?filter-agent=&agent=host-b", url.Values{}},
		{"former container link keeps its agent", "?agent=host-a&container=other-id", url.Values{"filter-agent": {"host-a"}}},
		{"unknown values are dropped", "?next=https://example.com/&notice=bound&q=sample", url.Values{"q": {"sample"}}},
		{"values stay encoded", "?q=" + url.QueryEscape("a&b=c/d"), url.Values{"q": {"a&b=c/d"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, err := noFollow.Get(fixture.harness.site.URL + "/containers" + test.query)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != http.StatusMovedPermanently {
				t.Fatalf("status = %d", response.StatusCode)
			}
			target, err := url.Parse(response.Header.Get("Location"))
			if err != nil || target.Host != "" || target.Path != "/bindings" || !reflect.DeepEqual(target.Query(), test.want) {
				t.Fatalf("location = %q", response.Header.Get("Location"))
			}
		})
	}
	t.Run("a saved link lands on the same list", func(t *testing.T) {
		held := fixture.bindings(t, "?filter-agent=host-a&q=sample&sort=image&order=desc")
		followed := loadPage[bindingsPage](t, fixture, "/containers?filter-agent=host-a&q=sample&sort=image&order=desc", "bindings")
		if !reflect.DeepEqual(bindingIDs(followed), bindingIDs(held)) || len(followed.Rows) == 0 || followed.Sort != "image" || followed.Order != "desc" || followed.Query != "sample" || followed.FilterAgent != "host-a" {
			t.Fatalf("followed = %#v", followed.listFilter)
		}
		agentOnly := loadPage[bindingsPage](t, fixture, "/containers?agent=host-b", "bindings")
		if agentOnly.FilterAgent != "host-b" || !reflect.DeepEqual(bindingIDs(agentOnly), []string{"b-b-sample"}) {
			t.Fatalf("agent-only = %#v", agentOnly.listFilter)
		}
	})
}

func TestBindingsAnswerAnErrorWhenAReadFails(t *testing.T) {
	fixture := newListFixture(t)
	database, err := sql.Open("sqlite", filepath.Join(fixture.harness.controller.Configuration().StateDirectory, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	before := fixture.bindings(t, "")
	if len(before.Rows) == 0 {
		t.Fatal("no rows before the fault")
	}
	if _, err := database.Exec(`UPDATE inventories SET containers = 'not json' WHERE agent = 'host-a'`); err != nil {
		t.Fatal(err)
	}
	response, err := fixture.client.Get(fixture.harness.site.URL + "/bindings")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusInternalServerError || strings.Contains(string(body), "Not reported") {
		t.Fatalf("a failed inventory read = %d %s", response.StatusCode, body)
	}
}
