// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

const (
	bindingsUnreadable  = "Bindings could not be read."
	policyPageName      = "policy"
	bindingsSectionMark = `id="h-bindings"`
)

func (fixture listFixture) policy(t *testing.T, name string) policyPage {
	t.Helper()
	return loadPage[policyPage](t, fixture, policyEditPath+name, policyPageName)
}

func policyRowIDs(page policyPage) []string {
	ids := make([]string, 0, len(page.BindingRows))
	for _, row := range page.BindingRows {
		ids = append(ids, row.ID)
	}
	return ids
}

func policyRow(t *testing.T, page policyPage, id string) bindingRow {
	t.Helper()
	for _, row := range page.BindingRows {
		if row.ID == id {
			return row
		}
	}
	t.Fatalf("no row %s in %v", id, policyRowIDs(page))
	return bindingRow{}
}

func (fixture listFixture) savePolicy(t *testing.T, name string, form url.Values) screenResponse {
	t.Helper()
	token := csrf(t, get(t, fixture.client, fixture.harness.site.URL+"/policies/edit").body)
	form.Set("csrf", token)
	form.Set("name", name)
	response, err := fixture.client.PostForm(fixture.harness.site.URL+"/policies", form)
	return readScreen(t, response, err)
}

func (fixture listFixture) get(t *testing.T, target string) screenResponse {
	t.Helper()
	response, err := fixture.client.Get(fixture.harness.site.URL + target)
	return readScreen(t, response, err)
}

func TestPolicyPageListsEveryBindingThatSelectsThePolicy(t *testing.T) {
	fixture := newListFixture(t)
	page := fixture.policy(t, "sample-policy")
	want := []string{"b-a-gone", "b-pending", "b-rejected", "b-a-replica", "b-a-sample", "b-b-sample"}
	if got := policyRowIDs(page); !reflect.DeepEqual(got, want) {
		t.Fatalf("rows = %v, want %v", got, want)
	}
	sample := policyRow(t, page, "b-a-sample")
	if len(sample.Containers) != 1 || sample.Containers[0].Name != "sample" || sample.Containers[0].Image != "busybox:latest" ||
		sample.Agent != "host-a" || sample.KeyKind != "compose" || sample.KeyValue != "unique-project/worker" ||
		sample.Badge != "Conforms" || sample.Screen != "/bindings/b-a-sample" {
		t.Fatalf("sample = %#v", sample)
	}
	replica := policyRow(t, page, "b-a-replica")
	if len(replica.Containers) != 2 || replica.Containers[0].Name != "replica-1" || replica.Containers[1].Name != "replica-2" {
		t.Fatalf("replica = %#v", replica)
	}
	body := renderModel(t, policyPageName, page)
	for _, text := range []string{"busybox:latest", "unique-project/worker", `href="/bindings/b-a-gone"`, `href="/bindings/b-a-sample?container=sample-id"`, "Conforms"} {
		if !strings.Contains(body, text) {
			t.Fatalf("policy page lacks %q: %s", text, body)
		}
	}
	// A binding that selects only another policy is not on this page.
	other := fixture.policy(t, "other-policy")
	if got := policyRowIDs(other); !reflect.DeepEqual(got, []string{"b-a-replica"}) {
		t.Fatalf("other-policy rows = %v", got)
	}
}

// The projection is the one the Bindings page reads: the row of a binding on an
// approved agent is the same on both pages.
func TestPolicyPageRowsMatchTheBindingsPage(t *testing.T) {
	fixture := newListFixture(t)
	page := fixture.policy(t, "sample-policy")
	for _, id := range []string{"b-a-sample", "b-a-replica", "b-a-gone", "b-b-sample"} {
		if got, want := policyRow(t, page, id), rowByID(t, fixture.bindings(t, ""), id); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s:\n policy page   %#v\n bindings page %#v", id, got, want)
		}
	}
}

func TestPolicyPageRowStaysWhenItsContainerLeavesTheInventory(t *testing.T) {
	fixture := newListFixture(t)
	data := fixture.harness.controller.Store()
	before := policyRow(t, fixture.policy(t, "sample-policy"), "b-b-sample")
	if len(before.Containers) != 1 || before.Badge != "Non-conforming" {
		t.Fatalf("before = %#v", before)
	}
	later := fixture.now.Add(time.Minute)
	if err := data.SaveInventory(fixture.ctx, "host-b", "host-b", []protocol.Container{{ID: "lookalike-id", Name: "lookalike", Keys: []protocol.Key{composeKey("unique-project/worker")}}}, later); err != nil {
		t.Fatal(err)
	}
	page := fixture.policy(t, "sample-policy")
	after := policyRow(t, page, "b-b-sample")
	if len(after.Containers) != 0 || after.Badge != "Not reported" || after.BadgeClass != "neutral" || after.Agent != "host-b" ||
		after.KeyKind != "name" || after.KeyValue != "sample" || after.Screen != "/bindings/b-b-sample" || after.Connected {
		t.Fatalf("after = %#v", after)
	}
	if page.Bindings != 6 {
		t.Fatalf("header = %d", page.Bindings)
	}
	body := renderModel(t, policyPageName, page)
	for _, text := range []string{"Not reported", "No container reported", "Disconnected · last report shown", "Last report", `href="/bindings/b-b-sample"`} {
		if !strings.Contains(body, text) {
			t.Fatalf("policy page lacks %q: %s", text, body)
		}
	}
}

// Delete is refused while any binding references the policy, and the Policies
// list counts every one, so that a binding on an agent that is not approved is
// listed too. That agent's reports are not read.
func TestPolicyPageListsABindingOnAnAgentThatIsNotApproved(t *testing.T) {
	fixture := newListFixture(t)
	page := fixture.policy(t, "sample-policy")
	for _, id := range []string{"b-pending", "b-rejected"} {
		row := policyRow(t, page, id)
		if !row.AgentNotApproved || len(row.Containers) != 0 || row.Badge != "Not reported" || row.Connected || row.Screen != "/bindings/"+id {
			t.Fatalf("%s = %#v", id, row)
		}
	}
	if row := policyRow(t, page, "b-a-sample"); row.AgentNotApproved {
		t.Fatalf("approved agent's row = %#v", row)
	}
	body := renderModel(t, policyPageName, page)
	if !strings.Contains(body, "Agent not approved") || strings.Contains(body, "pending-id") {
		t.Fatalf("policy page = %s", body)
	}
	// It stays off the Bindings list, whose contract is approved agents.
	if got := fixture.bindings(t, "?filter-agent=pending"); len(got.Rows) != 0 {
		t.Fatalf("bindings list = %v", bindingIDs(got))
	}
}

func TestPolicyPageHeaderCountsAgreeWithItsRows(t *testing.T) {
	fixture := newListFixture(t)
	page := fixture.policy(t, "sample-policy")
	if page.Bindings != len(page.BindingRows) || page.Bindings != 6 {
		t.Fatalf("header %d, rows %d", page.Bindings, len(page.BindingRows))
	}
	if page.Agents != 4 {
		t.Fatalf("agents = %d", page.Agents)
	}
	if agents := []string{policyRow(t, page, "b-a-sample").Agent, policyRow(t, page, "b-b-sample").Agent}; agents[0] == agents[1] {
		t.Fatalf("rows are not across agents: %v", agents)
	}
	if body := renderModel(t, policyPageName, page); !strings.Contains(body, "<!-- -->6<!-- --> binding") && !strings.Contains(body, "6 binding") {
		t.Fatalf("header not rendered: %s", body)
	}
	// One binding with two containers is one binding and one row.
	other := fixture.policy(t, "other-policy")
	if other.Bindings != 1 || other.Agents != 1 || len(other.BindingRows) != 1 || len(other.BindingRows[0].Containers) != 2 {
		t.Fatalf("other-policy = %d on %d, %#v", other.Bindings, other.Agents, other.BindingRows)
	}
	// The Policies list states the same counts.
	list := loadPage[policiesPage](t, fixture, "/policies", "policies")
	for _, summary := range list.Policies {
		saved := fixture.policy(t, summary.Name)
		if summary.Bindings != saved.Bindings || summary.Agents != saved.Agents {
			t.Fatalf("%s list %d on %d, page %d on %d", summary.Name, summary.Bindings, summary.Agents, saved.Bindings, saved.Agents)
		}
	}
}

func TestPolicyPageWithoutBindingsSaysSoAndNewPolicyHasNoSection(t *testing.T) {
	fixture := newListFixture(t)
	data := fixture.harness.controller.Store()
	if _, err := data.SavePolicy(fixture.ctx, policy.New("unused-policy", samplePolicyHCL), "operator", fixture.now); err != nil {
		t.Fatal(err)
	}
	unused := fixture.policy(t, "unused-policy")
	if unused.Bindings != 0 || unused.Agents != 0 || unused.BindingRows == nil || len(unused.BindingRows) != 0 {
		t.Fatalf("unused = %#v", unused.BindingRows)
	}
	if body := renderModel(t, policyPageName, unused); !strings.Contains(body, bindingsSectionMark) || !strings.Contains(body, "No binding selects this policy.") {
		t.Fatalf("unused page = %s", body)
	}
	fresh := loadPage[policyPage](t, fixture, "/policies/edit", policyPageName)
	if !fresh.New || fresh.BindingRows != nil {
		t.Fatalf("new page = %#v", fresh.BindingRows)
	}
	if body := renderModel(t, policyPageName, fresh); strings.Contains(body, bindingsSectionMark) {
		t.Fatalf("new page has the section: %s", body)
	}
}

// A refused save renders the same page, so that its count and list stay.
func TestFailedSaveKeepsThePolicyBindings(t *testing.T) {
	fixture := newListFixture(t)
	refused := url.Values{"hcl": {samplePolicyHCL}, "env": {"not an assignment"}}
	answer := fixture.savePolicy(t, "sample-policy", refused)
	if answer.status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d: %s", answer.status, answer.raw)
	}
	match := pageDataPattern.FindSubmatch(answer.raw)
	if match == nil {
		t.Fatalf("no page data: %s", answer.raw)
	}
	var payload struct{ Data policyPage }
	if err := json.Unmarshal(match[1], &payload); err != nil {
		t.Fatal(err)
	}
	page := payload.Data
	if page.Problem == "" || page.Bindings != 6 || page.Agents != 4 || len(page.BindingRows) != 6 {
		t.Fatalf("refused page: problem %q, %d on %d, %v", page.Problem, page.Bindings, page.Agents, policyRowIDs(page))
	}
	// A refused new policy has no section, even with the name of a saved one.
	refused.Set("new", "yes")
	answer = fixture.savePolicy(t, "sample-policy", refused)
	match = pageDataPattern.FindSubmatch(answer.raw)
	if answer.status != http.StatusUnprocessableEntity || match == nil {
		t.Fatalf("new status = %d: %s", answer.status, answer.raw)
	}
	var fresh struct{ Data policyPage }
	if err := json.Unmarshal(match[1], &fresh); err != nil {
		t.Fatal(err)
	}
	if !fresh.Data.New || fresh.Data.BindingRows != nil {
		t.Fatalf("refused new page = %#v", fresh.Data.BindingRows)
	}
}

func TestPolicyPageListRequiresASessionAndExposesNoToken(t *testing.T) {
	fixture := newListFixture(t)
	const accessor = "sentinel-accessor-value"
	data := fixture.harness.controller.Store()
	if err := data.SaveTokenAccessor(fixture.ctx, "b-a-sample", accessor, fixture.now); err != nil {
		t.Fatal(err)
	}
	if stored, err := data.TokenAccessor(fixture.ctx, "b-a-sample"); err != nil || stored != accessor {
		t.Fatalf("stored accessor = %q, %v", stored, err)
	}
	anonymous := get(t, browser(t), fixture.harness.site.URL+policyEditPath+"sample-policy")
	if !strings.Contains(anonymous.url, "/sign-in") || strings.Contains(anonymous.body, "b-a-sample") {
		t.Fatalf("list exposed without a session: %s", anonymous.url)
	}
	answer := fixture.get(t, policyEditPath+"sample-policy")
	if answer.status != http.StatusOK || !strings.Contains(string(answer.raw), "b-a-sample") {
		t.Fatalf("signed in = %d", answer.status)
	}
	if strings.Contains(string(answer.raw), accessor) {
		t.Fatalf("page data holds the token accessor: %s", answer.raw)
	}
	rows, err := json.Marshal(fixture.policy(t, "sample-policy").BindingRows)
	if err != nil {
		t.Fatal(err)
	}
	for _, word := range []string{"token", "accessor", "secret", "credential"} {
		if strings.Contains(strings.ToLower(string(rows)), word) {
			t.Fatalf("rows hold %q: %s", word, rows)
		}
	}
}

func TestPolicyPageAnswersAnErrorWhenItsBindingsCannotBeRead(t *testing.T) {
	fixture := newListFixture(t)
	database := openStore(t, fixture.harness)
	results := storeFault{name: "contract results", apply: `ALTER TABLE contract_results RENAME TO contract_results_unavailable`,
		restore: `ALTER TABLE contract_results_unavailable RENAME TO contract_results`}
	for _, fault := range []storeFault{agentsFault(), results, inventoryFault("host-a"), inventoryFault("host-b"), bindingFault("b-a-sample")} {
		t.Run(fault.name, func(t *testing.T) {
			fault.during(t, database, func() {
				answer := fixture.get(t, policyEditPath+"sample-policy")
				if answer.status != http.StatusInternalServerError || answer.page != "" || !strings.Contains(string(answer.raw), bindingsUnreadable) {
					t.Fatalf("answer = %d %q: %s", answer.status, answer.page, answer.raw)
				}
				saved := fixture.savePolicy(t, "sample-policy", url.Values{"hcl": {samplePolicyHCL}, "env": {"not an assignment"}})
				if saved.status != http.StatusInternalServerError || saved.page != "" || !strings.Contains(string(saved.raw), bindingsUnreadable) || !strings.Contains(string(saved.raw), "NAME=value") {
					t.Fatalf("refused save = %d %q: %s", saved.status, saved.page, saved.raw)
				}
			})
			if got := fixture.policy(t, "sample-policy"); len(got.BindingRows) != 6 {
				t.Fatalf("after the fault = %v", policyRowIDs(got))
			}
		})
	}
	// A refused save cannot read as a policy with no bindings when the policy
	// itself cannot be read.
	t.Run("policy on a refused save", func(t *testing.T) {
		fault := storeFault{apply: `CREATE TABLE fault_saved AS SELECT document AS value FROM policies WHERE name = 'sample-policy'; UPDATE policies SET document = 'not json' WHERE name = 'sample-policy'`,
			restore: `UPDATE policies SET document = (SELECT value FROM fault_saved) WHERE name = 'sample-policy'; DROP TABLE fault_saved`}
		fault.during(t, database, func() {
			saved := fixture.savePolicy(t, "sample-policy", url.Values{"hcl": {samplePolicyHCL}, "env": {"not an assignment"}})
			if saved.status != http.StatusInternalServerError || saved.page != "" || !strings.Contains(string(saved.raw), bindingsUnreadable) || !strings.Contains(string(saved.raw), "NAME=value") {
				t.Fatalf("refused save = %d %q: %s", saved.status, saved.page, saved.raw)
			}
		})
	})
	// A refused save of a policy that is not stored has nothing to list.
	t.Run("refused save of a policy that is not stored", func(t *testing.T) {
		saved := fixture.savePolicy(t, "absent-policy", url.Values{"hcl": {samplePolicyHCL}, "env": {"not an assignment"}})
		if saved.status != http.StatusUnprocessableEntity {
			t.Fatalf("refused save = %d: %s", saved.status, saved.raw)
		}
	})
	// An agent that holds no binding of this policy cannot fail its page.
	t.Run("unrelated agent", func(t *testing.T) {
		inventoryFault("host-b").during(t, database, func() {
			if got := policyRowIDs(fixture.policy(t, "other-policy")); !reflect.DeepEqual(got, []string{"b-a-replica"}) {
				t.Fatalf("rows = %v", got)
			}
		})
	})
}

// A long list follows the form, so that its length cannot move the Save action.
func TestPolicyPageWithFiftyBindingsKeepsSaveInTheHeader(t *testing.T) {
	fixture := newListFixture(t)
	data := fixture.harness.controller.Store()
	if _, err := data.SavePolicy(fixture.ctx, policy.New("wide-policy", samplePolicyHCL), "operator", fixture.now); err != nil {
		t.Fatal(err)
	}
	for index := range 50 {
		agent := "host-a"
		if index%2 == 1 {
			agent = "host-b"
		}
		id := fmt.Sprintf("b-wide-%02d", index)
		key := nameKey(fmt.Sprintf("wide-%02d", index))
		if err := data.CreateBinding(fixture.ctx, store.Binding{ID: id, Agent: agent, Key: key, Policies: []string{"wide-policy"}, Revision: 1, Applied: true}); err != nil {
			t.Fatal(err)
		}
	}
	page := fixture.policy(t, "wide-policy")
	if len(page.BindingRows) != 50 || page.Bindings != 50 || page.Agents != 2 {
		t.Fatalf("rows %d, header %d on %d", len(page.BindingRows), page.Bindings, page.Agents)
	}
	body := renderModel(t, policyPageName, page)
	save, section := strings.Index(body, "Save and validate"), strings.Index(body, bindingsSectionMark)
	tabs, editor := strings.Index(body, `role="tablist"`), strings.Index(body, `id="h-hcl"`)
	if save < 0 || tabs < save || editor < tabs || section < editor {
		t.Fatalf("order: save %d, tabs %d, editor %d, section %d", save, tabs, editor, section)
	}
	// Each row keeps its container link and has one Edit action.
	if strings.Count(body, `href="/bindings/b-wide-`) != 100 || strings.Count(body, `class="row-action"`) != 50 {
		t.Fatalf("links = %d, actions = %d", strings.Count(body, `href="/bindings/b-wide-`), strings.Count(body, `class="row-action"`))
	}
}
