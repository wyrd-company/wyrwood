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

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

func typedForm(agent, key, directory string) url.Values {
	return url.Values{"typed": {"yes"}, "agent": {agent}, "key": {key}, "directory": {directory},
		"policies": {"first"}, "token-ttl": {"1h"}, "token-max-ttl": {"8h"}, "enforcement": {"report"}}
}

func agentNames(screen screenResponse) []string {
	names := []string{}
	for _, agent := range screen.data.AgentChoices {
		names = append(names, agent.Name)
	}
	return names
}

// Add binding links to the typed-key screen, which offers approved agents only
// and does not take an agent that is not one from the request.
func TestTypedBindScreenOffersOnlyApprovedAgents(t *testing.T) {
	fixture := newScreenFixture(t)
	add := fixture.get(t, "/bindings/add?q=sample")
	if !strings.Contains(renderedPage(t, add.raw), `href="/bindings/new/key?q=sample"`) {
		t.Fatal("Add binding has no link to the typed-key screen")
	}
	for query, want := range map[string]string{"?filter-agent=host-b": "host-b", "?filter-agent=pending-host": "", "?filter-agent=absent-host": "", "": ""} {
		screen := fixture.get(t, "/bindings/new/key"+query)
		if screen.status != http.StatusOK || screen.page != "binding" || !screen.data.Typed {
			t.Fatalf("%q = %d %s", query, screen.status, screen.raw)
		}
		if names := agentNames(screen); strings.Join(names, ",") != "host-a,host-b" {
			t.Fatalf("%q agents = %v", query, names)
		}
		if screen.data.Form.Agent != want || screen.data.Row.Agent != want {
			t.Fatalf("%q selected agent = %q, row %q", query, screen.data.Form.Agent, screen.data.Row.Agent)
		}
		body := renderedPage(t, screen.raw)
		for _, text := range []string{"Container key", "Directory name", `value="host-a"`, `name="typed"`, "Bind policies"} {
			if !strings.Contains(body, text) {
				t.Fatalf("%q typed screen lacks %q: %s", query, text, body)
			}
		}
		if strings.Contains(body, `value="pending-host"`) {
			t.Fatalf("%q typed screen offers the pending agent", query)
		}
	}
}

// A typed key that is not name binds a container no agent reports, stores the
// directory name, and shows it on the binding screen. The create records its
// operator event.
func TestTypedKeyCreateStoresTheDirectoryName(t *testing.T) {
	fixture := newScreenFixture(t)
	created := fixture.post(t, "/bindings?q=sample", typedForm("host-a", "compose:shop/web", "shop-web"))
	target, err := url.Parse(created.url)
	if err != nil || !strings.HasPrefix(target.Path, "/bindings/b-") || target.Query().Has("container") || target.Query().Get("q") != "sample" {
		t.Fatalf("redirect = %s", created.url)
	}
	if created.status != http.StatusOK || !created.data.Row.Bound || created.data.Reported || created.data.Row.Directory != "shop-web" ||
		created.data.Row.KeyKind != "compose" || created.data.Row.KeyValue != "shop/web" {
		t.Fatalf("binding screen = %d %#v", created.status, created.data.Row)
	}
	body := renderedPage(t, created.raw)
	if !strings.Contains(body, "Directory name") || !strings.Contains(body, "shop-web") {
		t.Fatalf("binding screen does not show the directory name: %s", body)
	}
	bindings, err := fixture.harness.controller.Store().Bindings(context.Background(), "host-a")
	if err != nil || len(bindings) != 1 || bindings[0].Directory != "shop-web" || bindings[0].Key != (protocol.Key{Kind: protocol.KeyCompose, Value: "shop/web"}) {
		t.Fatalf("bindings = %#v, %v", bindings, err)
	}
	recorded := false
	for _, event := range fixture.harness.controller.Events().Recent(100) {
		if event.Operation == events.OperationBindingCreated && event.Outcome == events.OutcomeOK && event.Binding == bindings[0].ID && event.Operator != "" {
			recorded = true
		}
	}
	if !recorded {
		t.Fatal("the create recorded no operator event")
	}
	// A name key needs no directory name.
	named := fixture.post(t, "/bindings", typedForm("host-b", "name:later", ""))
	if named.status != http.StatusOK || !named.data.Row.Bound || named.data.Row.Directory != "" {
		t.Fatalf("name key = %d %#v", named.status, named.data.Row)
	}
}

// A refused directory name, or none for a key no agent reports, stays on the
// typed-key screen with the entered values and saves nothing.
func TestTypedKeyCreateRefusesADirectoryName(t *testing.T) {
	fixture := newScreenFixture(t)
	for name, test := range map[string]struct {
		form    url.Values
		problem string
	}{
		"separator":   {typedForm("host-a", "compose:shop/web", "a/b"), "path separator"},
		"parent":      {typedForm("host-a", "compose:shop/web", ".."), "must not be . or .."},
		"length":      {typedForm("host-a", "compose:shop/web", strings.Repeat("a", 256)), "exceeds 255 bytes"},
		"missing":     {typedForm("host-a", "devcontainer:/src/app", ""), "give the directory name"},
		"name-key":    {typedForm("host-a", "name:later", "later"), "names its own directory"},
		"pending":     {typedForm("pending-host", "compose:shop/web", "shop-web"), "not approved"},
		"unknown-key": {typedForm("host-a", "label:shop", "shop-web"), "container key is invalid"},
	} {
		t.Run(name, func(t *testing.T) {
			refused := fixture.post(t, "/bindings?q=sample", test.form)
			if refused.status != http.StatusUnprocessableEntity || refused.page != "binding" || !refused.data.Typed || !strings.Contains(refused.data.Problem, test.problem) {
				t.Fatalf("refused = %d %s %#v", refused.status, refused.page, refused.data.layout)
			}
			if test.form.Get("agent") == "host-a" && (refused.data.Form.Agent != "host-a" || refused.data.Form.Directory != test.form.Get("directory") || refused.data.Form.Key != test.form.Get("key")) {
				t.Fatalf("entered values = %#v", refused.data.Form)
			}
			if test.form.Get("agent") == "pending-host" && refused.data.Form.Agent != "" {
				t.Fatalf("the refused screen selects the pending agent: %#v", refused.data.Form)
			}
			if refused.data.Back != "/bindings/add?q=sample" {
				t.Fatalf("back = %q", refused.data.Back)
			}
			if !strings.Contains(renderedPage(t, refused.raw), refused.data.Problem) {
				t.Fatal("the problem is not shown")
			}
			for _, agent := range []string{"host-a", "pending-host"} {
				if bindings, _ := fixture.harness.controller.Store().Bindings(context.Background(), agent); len(bindings) != 0 {
					t.Fatalf("refused create saved %#v", bindings)
				}
			}
		})
	}
	// The directory problem opens the tab that holds the field.
	if refused := fixture.post(t, "/bindings", typedForm("host-a", "compose:shop/web", "a/b")); refused.data.ProblemTab != "key-and-policies" {
		t.Fatalf("problem tab = %q", refused.data.ProblemTab)
	}
}

// The typed-key create keeps the session and anti-forgery checks.
func TestTypedKeyCreateRequiresASessionAndAntiForgeryToken(t *testing.T) {
	fixture := newScreenFixture(t)
	site := fixture.harness.site.URL
	signedOut := browser(t)
	signedOut.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := signedOut.Get(site + "/bindings/new/key")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/sign-in" {
		t.Fatalf("typed screen without a session = %d %q", response.StatusCode, response.Header.Get("Location"))
	}
	form := typedForm("host-a", "compose:shop/web", "shop-web")
	for _, token := range []string{"", "wrong-token"} {
		forged := url.Values{"csrf": {token}}
		for name, values := range form {
			forged[name] = values
		}
		response, err := fixture.client.PostForm(site+"/bindings", forged)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("typed create with token %q = %d", token, response.StatusCode)
		}
	}
	response, err = signedOut.PostForm(site+"/bindings", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/sign-in" {
		t.Fatalf("typed create without a session = %d", response.StatusCode)
	}
	if bindings, _ := fixture.harness.controller.Store().Bindings(context.Background(), "host-a"); len(bindings) != 0 {
		t.Fatalf("forged request created %#v", bindings)
	}
	if created := fixture.post(t, "/bindings", form); created.status != http.StatusOK || created.data.Row.Directory != "shop-web" {
		t.Fatalf("admitted create = %d %#v", created.status, created.data.Row)
	}
}

// Each approved agent carries what its live session reports, so that the form's
// access group choice follows the selected agent. Other agents are not offered.
func TestTypedAgentsCarryEachAgentsGroups(t *testing.T) {
	groups := &protocol.AssignableGroups{Groups: []protocol.Group{{GID: 4242, Name: "apps"}}}
	agents := []store.Agent{{Name: "pending-host", State: store.AgentPending}, {Name: "host-a", State: store.AgentApproved},
		{Name: "host-b", State: store.AgentApproved}, {Name: "gone-host", State: store.AgentRejected}}
	connected := func(name string) bool { return name == "host-a" }
	reported := func(name string) *protocol.AssignableGroups {
		if name == "host-a" {
			return groups
		}
		return nil
	}
	got := typedAgents(agents, "host-a", connected, reported)
	want := []typedAgent{{Name: "host-a", Selected: true, Connected: true, AssignableGroups: groups}, {Name: "host-b"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("typedAgents() = %#v, want %#v", got, want)
	}
	if got := typedAgents(agents, "pending-host", connected, reported); got[0].Selected || got[1].Selected {
		t.Fatalf("a pending agent was selected: %#v", got)
	}
}
