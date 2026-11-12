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
)

const typedBindingPath = "/bindings/new/key"

// typedBindingURL is the typed-key bind screen, opened from the given list.
func typedBindingURL(list url.Values) string {
	return withQuery(typedBindingPath, list)
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
	choices := agentChoices(agents, nil, form.Agent)
	if !slices.ContainsFunc(choices, func(choice agentChoice) bool { return choice.Selected }) {
		form.Agent = ""
	}
	row := containerRow{Agent: form.Agent}
	row.Badge, row.BadgeClass = notReportedBadge()
	if form.Agent != "" {
		row.Connected = server.controller.Connected(form.Agent)
	}
	base := server.layout(request, "Bind by typed key", "bindings")
	base.Problem, base.ProblemTab = problem, problemTab
	list := listContext(request.URL.Query())
	server.renderStatus(writer, request, status, "binding", bindingScreen{
		layout: base, Row: row, Typed: true, AgentChoices: choices, Policies: server.policyChoices(ctx, form.Policies), Form: form,
		Screen: typedBindingURL(list), Action: withQuery(bindingsPath, list), Back: addBindingURL(list),
	})
}
