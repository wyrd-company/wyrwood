// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const containersUnreadable = "Containers could not be read."

// storeFault makes one store read fail by changing the controller's database,
// which the real store then reads. Restoring it is the proof that the fault was
// the only cause of the failure.
type storeFault struct {
	name    string
	apply   string
	restore string
}

func inventoryFault(agent string) storeFault {
	return storeFault{
		name:    "inventory of " + agent,
		apply:   `CREATE TABLE fault_saved AS SELECT containers AS value FROM inventories WHERE agent = '` + agent + `'; UPDATE inventories SET containers = 'not json' WHERE agent = '` + agent + `'`,
		restore: `UPDATE inventories SET containers = (SELECT value FROM fault_saved) WHERE agent = '` + agent + `'; DROP TABLE fault_saved`,
	}
}

func bindingFault(id string) storeFault {
	return storeFault{
		name:    "binding " + id,
		apply:   `CREATE TABLE fault_saved AS SELECT effective AS value FROM bindings WHERE id = '` + id + `'; UPDATE bindings SET effective = 'not json' WHERE id = '` + id + `'`,
		restore: `UPDATE bindings SET effective = (SELECT value FROM fault_saved) WHERE id = '` + id + `'; DROP TABLE fault_saved`,
	}
}

func agentsFault() storeFault {
	return storeFault{
		name:    "agents",
		apply:   `ALTER TABLE agents RENAME TO agents_unavailable`,
		restore: `ALTER TABLE agents_unavailable RENAME TO agents`,
	}
}

func openStore(t *testing.T, h *harness) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", filepath.Join(h.controller.Configuration().StateDirectory, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

// during runs check with the fault applied, and restores the database even when
// the check fails.
func (fault storeFault) during(t *testing.T, database *sql.DB, check func()) {
	t.Helper()
	if _, err := database.Exec(fault.apply); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := database.Exec(fault.restore); err != nil {
			t.Fatal(err)
		}
	}()
	check()
}

// assertReadFailure holds that an answer is the explicit failure and that it
// carries no page, and therefore no container or state.
func assertReadFailure(t *testing.T, answer screenResponse, want ...string) {
	t.Helper()
	if answer.status != http.StatusInternalServerError || answer.page != "" {
		t.Fatalf("answer = %d page %q: %s", answer.status, answer.page, answer.raw)
	}
	for _, text := range append([]string{containersUnreadable}, want...) {
		if !strings.Contains(string(answer.raw), text) {
			t.Fatalf("answer lacks %q: %s", text, answer.raw)
		}
	}
}

func TestAddBindingAnswersAnErrorWhenAReadFails(t *testing.T) {
	fixture := newListFixture(t)
	database := openStore(t, fixture.harness)
	want := []string{"host-b/lookalike-id", "host-a/other-id"}
	for _, fault := range []storeFault{
		inventoryFault("host-a"),
		inventoryFault("host-b"),
		bindingFault("b-a-sample"),
		bindingFault("b-b-sample"),
	} {
		t.Run(fault.name, func(t *testing.T) {
			if got := addIdentities(fixture.add(t, "")); !reflect.DeepEqual(got, want) {
				t.Fatalf("before the fault = %v", got)
			}
			fault.during(t, database, func() {
				response, err := fixture.client.Get(fixture.harness.site.URL + addBindingPath)
				assertReadFailure(t, readScreen(t, response, err))
			})
			if got := addIdentities(fixture.add(t, "")); !reflect.DeepEqual(got, want) {
				t.Fatalf("after the fault = %v", got)
			}
		})
	}
}

// An agent that has not reported has no containers. That is a successful read,
// and the other agents' containers stay on the screen.
func TestAddBindingTreatsAnAgentWithNoReportAsEmpty(t *testing.T) {
	fixture := newListFixture(t)
	database := openStore(t, fixture.harness)
	if _, err := database.Exec(`DELETE FROM inventories WHERE agent = 'host-b'`); err != nil {
		t.Fatal(err)
	}
	if got, want := addIdentities(fixture.add(t, "")), []string{"host-a/other-id"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rows = %v, want %v", got, want)
	}
}

func TestBindAndBindingScreensAnswerAnErrorWhenAReadFails(t *testing.T) {
	fixture := newListFixture(t)
	database := openStore(t, fixture.harness)
	get := func(t *testing.T, path string) screenResponse {
		t.Helper()
		response, err := fixture.client.Get(fixture.harness.site.URL + path)
		return readScreen(t, response, err)
	}
	const (
		unbound = "/bindings/new?agent=host-a&container=other-id"
		bound   = "/bindings/new?agent=host-a&container=sample-id"
		screen  = "/bindings/b-a-sample?container=sample-id"
		gone    = "/bindings/b-a-gone"
	)
	// Each screen's answer with no fault, so that the fault is what changes it.
	healthy := map[string]func(*testing.T, screenResponse){
		unbound: func(t *testing.T, answer screenResponse) {
			t.Helper()
			if answer.page != "binding" || answer.data.Row.Bound || answer.data.Row.ID != "other-id" || len(answer.data.Row.Candidates) == 0 {
				t.Fatalf("bind screen = %d %s %+v", answer.status, answer.page, answer.data.Row)
			}
		},
		bound: func(t *testing.T, answer screenResponse) {
			t.Helper()
			if answer.page != "binding" || !answer.data.Row.Bound || answer.data.Row.BindingID != "b-a-sample" || len(answer.data.Row.Candidates) != 0 {
				t.Fatalf("bound container = %d %s %+v", answer.status, answer.page, answer.data.Row)
			}
		},
		screen: func(t *testing.T, answer screenResponse) {
			t.Helper()
			if answer.page != "binding" || !answer.data.Reported || answer.data.Row.ID != "sample-id" {
				t.Fatalf("binding screen = %d %s %+v", answer.status, answer.page, answer.data.Row)
			}
		},
		gone: func(t *testing.T, answer screenResponse) {
			t.Helper()
			if answer.page != "binding" || answer.data.Reported || answer.data.Row.Badge != "Not reported" {
				t.Fatalf("not reported screen = %d %s %+v", answer.status, answer.page, answer.data.Row)
			}
		},
	}
	for _, test := range []struct {
		path  string
		fault storeFault
	}{
		// A failed inventory read must not read as a container that is gone.
		{unbound, inventoryFault("host-a")},
		{bound, inventoryFault("host-a")},
		{screen, inventoryFault("host-a")},
		{gone, inventoryFault("host-a")},
		// A failed read of another binding of the agent must not offer a bound
		// container as unbound, or read as this binding's container being gone.
		{unbound, bindingFault("b-a-replica")},
		{bound, bindingFault("b-a-replica")},
		{screen, bindingFault("b-a-replica")},
		{gone, bindingFault("b-a-replica")},
		// A failed agent read must not read as the agent not being approved.
		{unbound, agentsFault()},
		{screen, agentsFault()},
		{gone, agentsFault()},
	} {
		t.Run(test.fault.name+" "+test.path, func(t *testing.T) {
			healthy[test.path](t, get(t, test.path))
			test.fault.during(t, database, func() {
				assertReadFailure(t, get(t, test.path))
			})
			healthy[test.path](t, get(t, test.path))
		})
	}
}

// The screen of a binding on an agent that is not approved stays reachable, and
// a container of such an agent stays not found: neither is a read failure.
func TestAgentThatIsNotApprovedIsNotAReadFailure(t *testing.T) {
	fixture := newListFixture(t)
	response, err := fixture.client.Get(fixture.harness.site.URL + "/bindings/b-pending")
	answer := readScreen(t, response, err)
	if answer.status != http.StatusOK || answer.page != "binding" || answer.data.Reported || answer.data.Row.Badge != "Not reported" {
		t.Fatalf("binding screen = %d %s %+v", answer.status, answer.page, answer.data.Row)
	}
	response, err = fixture.client.Get(fixture.harness.site.URL + "/bindings/new?agent=pending&container=pending-unbound")
	if answer := readScreen(t, response, err); answer.status != http.StatusNotFound || !strings.Contains(renderedPage(t, answer.raw), "Container not reported") {
		t.Fatalf("bind screen = %d %s", answer.status, answer.raw)
	}
}

func TestFailedSubmissionKeepsItsReasonWhenContainersCannotBeRead(t *testing.T) {
	fixture := newScreenFixture(t)
	database := openStore(t, fixture.harness)
	data := fixture.harness.controller.Store()
	ctx := context.Background()
	refused := func() url.Values {
		return url.Values{"agent": {"host-b"}, "container": {"shared-id"}, "key": {"compose:sample/worker"}, "policies": {"absent"},
			"token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}}
	}
	// With no fault, the refusal and its reason are on the bind screen.
	healthy := fixture.post(t, "/bindings", refused())
	if healthy.status != http.StatusUnprocessableEntity || healthy.page != "binding" || healthy.data.Problem == "" {
		t.Fatalf("refused bind = %d %s %q", healthy.status, healthy.page, healthy.data.Problem)
	}
	reason := healthy.data.Problem
	t.Run("create", func(t *testing.T) {
		inventoryFault("host-b").during(t, database, func() {
			assertReadFailure(t, fixture.post(t, "/bindings", refused()), "The request failed: "+reason)
		})
		bindings, err := data.Bindings(ctx, "host-b")
		if err != nil || len(bindings) != 0 {
			t.Fatalf("bindings = %v, %v", bindings, err)
		}
	})
	binding := fixture.bind(t, "host-a")
	t.Run("create when another binding cannot be read", func(t *testing.T) {
		form := refused()
		form.Set("agent", "host-a")
		bindingFault(binding.ID).during(t, database, func() {
			assertReadFailure(t, fixture.post(t, "/bindings", form), "The request failed:")
		})
	})
	t.Run("change", func(t *testing.T) {
		form := url.Values{"policies": {"absent"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}}
		path := bindingPath(binding.ID) + "/policy"
		healthy := fixture.post(t, path, form)
		if healthy.status != http.StatusUnprocessableEntity || healthy.page != "binding" || healthy.data.Problem == "" {
			t.Fatalf("refused change = %d %s %q", healthy.status, healthy.page, healthy.data.Problem)
		}
		inventoryFault("host-a").during(t, database, func() {
			assertReadFailure(t, fixture.post(t, path, form), "The request failed: "+healthy.data.Problem)
		})
		stored, err := data.Binding(ctx, binding.ID)
		if err != nil || !reflect.DeepEqual(stored.Policies, binding.Policies) || stored.Revision != binding.Revision {
			t.Fatalf("binding changed = %+v, %v", stored, err)
		}
	})
}
