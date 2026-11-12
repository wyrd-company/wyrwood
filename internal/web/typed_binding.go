// ---
// relationships:
//   implements: web-interface
//   uses: controller
// ---

package web

import (
	"net/http"
	"net/url"
	"slices"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

const typedBindingPath = "/bindings/new/key"

// typedBindingURL is the typed-key bind screen, opened from the given list.
func typedBindingURL(list url.Values) string {
	return withQuery(typedBindingPath, list)
}

// typedAgent is one approved agent the typed-key screen offers, with what its
// live session reports, so that the access group choice follows the agent the
// operator selects. An agent with no session has no groups.
type typedAgent struct {
	Name             string
	Selected         bool
	Connected        bool
	AssignableGroups *protocol.AssignableGroups
}

// typedAgents lists the approved agents in the Agents order and marks the one
// named selected.
func typedAgents(agents []store.Agent, selected string, connected func(string) bool, groups func(string) *protocol.AssignableGroups) []typedAgent {
	choices := []typedAgent{}
	for _, choice := range agentChoices(agents, nil, selected) {
		choices = append(choices, typedAgent{Name: choice.Name, Selected: choice.Selected, Connected: connected(choice.Name), AssignableGroups: groups(choice.Name)})
	}
	return choices
}

// handleTypedBindScreen shows the bind form for a key the operator types, so
// that a container can be bound before any agent reports it. The agent filter
// of Add binding selects the agent when it names an approved one.
func (server *Server) handleTypedBindScreen(writer http.ResponseWriter, request *http.Request) {
	server.renderTypedBindScreen(writer, request, http.StatusOK, bindingForm{Agent: request.URL.Query().Get("filter-agent")}, "", "")
}

// renderTypedBindScreen offers only approved agents, and drops an agent that is
// not one, so that a request cannot preselect it.
func (server *Server) renderTypedBindScreen(writer http.ResponseWriter, request *http.Request, status int, form bindingForm, problem, problemTab string) {
	ctx := request.Context()
	agents, err := server.controller.Store().Agents(ctx)
	if err != nil {
		server.renderContainersUnreadable(writer, problem)
		return
	}
	choices := typedAgents(agents, form.Agent, server.controller.Connected, server.controller.AssignableGroups)
	row := containerRow{}
	if index := slices.IndexFunc(choices, func(choice typedAgent) bool { return choice.Selected }); index >= 0 {
		row.Agent, row.Connected, row.AssignableGroups = choices[index].Name, choices[index].Connected, choices[index].AssignableGroups
	}
	form.Agent = row.Agent
	row.Badge, row.BadgeClass = notReportedBadge()
	base := server.layout(request, "Bind by typed key", "bindings")
	base.Problem, base.ProblemTab = problem, problemTab
	list := listContext(request.URL.Query())
	server.renderStatus(writer, request, status, "binding", bindingScreen{
		layout: base, Row: row, Typed: true, AgentChoices: choices, Policies: server.policyChoices(ctx, form.Policies), Form: form,
		Screen: typedBindingURL(list), Action: withQuery(bindingsPath, list), Back: addBindingURL(list),
	})
}
