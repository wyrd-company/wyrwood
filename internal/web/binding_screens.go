// ---
// relationships:
//   implements: web-interface
//   uses: controller
// ---

package web

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/wyrd-company/wyrwood/internal/controller"
	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// bindingScreen is the page data of the bind and bound container screens. The
// agent is always the one on Row, which comes from the agent's report or the
// binding record and never from the request.
type bindingScreen struct {
	layout
	Row      containerRow
	Reported bool
	// Readiness is a stored binding's answer to whether its consumers can use
	// their sockets now. The bind screen has no binding yet.
	Readiness *controller.BindingStatus
	Policies  []policyChoice
	Form      bindingForm
	// Typed marks the bind screen for a key the operator types, for a
	// container no agent needs to report. AgentChoices are the approved agents.
	Typed        bool
	AgentChoices []agentChoice
	Screen       string
	Action       string
	Recreate     string
	Unbind       string
	Back         string
}

// bindingForm is what the form shows: saved values, or the operator's entered
// text after a failed submission, including text that does not validate.
type bindingForm struct {
	Key string
	// Agent and Directory are the typed-key form's entered agent and directory
	// name. The other forms take the agent from the report or the record.
	Agent      string `json:",omitempty"`
	Directory  string `json:",omitempty"`
	Revision   int
	Policies   []string
	Settings   enteredSettings
	Understood bool
}

type enteredSettings struct {
	TokenTTL    string `json:"token-ttl"`
	TokenMaxTTL string `json:"token-max-ttl"`
	AccessGroup string `json:"access-group"`
	Enforcement string `json:"enforcement"`
	// Values holds the entered text of each binding value, valid or not.
	Values map[string]string `json:"values,omitempty"`
}

func savedForm(row containerRow) bindingForm {
	form := bindingForm{Revision: row.Revision, Policies: row.Policies, Settings: enteredSettings{
		TokenTTL: row.Settings.TokenTTL, TokenMaxTTL: row.Settings.TokenMaxTTL, Enforcement: string(row.Settings.Enforcement), Values: row.Settings.Values}}
	if row.Settings.AccessGroup != nil {
		form.Settings.AccessGroup = strconv.FormatUint(uint64(*row.Settings.AccessGroup), 10)
	}
	return form
}

func enteredForm(request *http.Request) bindingForm {
	// A revision that does not parse is kept as 0, which the controller refuses,
	// and a stale one is kept so that a retry cannot overwrite a concurrent edit.
	revision, _ := strconv.Atoi(request.PostFormValue("revision"))
	return bindingForm{
		Key: request.PostFormValue("key"), Revision: revision, Policies: request.PostForm["policies"],
		Understood: request.PostFormValue("understood") == "yes",
		Settings: enteredSettings{TokenTTL: request.PostFormValue("token-ttl"), TokenMaxTTL: request.PostFormValue("token-max-ttl"),
			AccessGroup: request.PostFormValue("access-group"), Enforcement: request.PostFormValue("enforcement"), Values: enteredValues(request)},
	}
}

// bindingValueField prefixes the form field of each binding value.
const bindingValueField = "value."

// enteredValues reads the binding values a form holds. An empty field is no
// value, so that the controller reports the policy that needs it.
func enteredValues(request *http.Request) map[string]string {
	var values map[string]string
	for field, entered := range request.PostForm {
		name, isValue := strings.CutPrefix(field, bindingValueField)
		if !isValue || len(entered) == 0 || strings.TrimSpace(entered[0]) == "" {
			continue
		}
		if values == nil {
			values = map[string]string{}
		}
		values[name] = strings.TrimSpace(entered[0])
	}
	return values
}

// listContext keeps only the list's filter and sort values, so that a screen
// can link back to the same list without following a request-supplied URL.
func listContext(query url.Values) url.Values {
	list := url.Values{}
	for _, name := range []string{"filter-agent", "q", "sort", "order"} {
		if value := query.Get(name); value != "" {
			list.Set(name, value)
		}
	}
	return list
}

// screenContext is a screen's list context and the container it was opened for.
func screenContext(request *http.Request) url.Values {
	query := request.URL.Query()
	values := listContext(query)
	if container := query.Get("container"); container != "" {
		values.Set("container", container)
	}
	if tab := query.Get("tab"); tab != "" {
		values.Set("tab", tab)
	}
	return values
}

func withQuery(path string, values url.Values) string {
	if len(values) == 0 {
		return path
	}
	return path + "?" + values.Encode()
}

func bindingPath(id string) string {
	return "/bindings/" + url.PathEscape(id)
}

// containerScreenURL is the screen for a row, opened from the given list.
func containerScreenURL(row containerRow, list url.Values) string {
	values := maps.Clone(list)
	if row.Bound {
		values.Set("container", row.ID)
		return withQuery(bindingPath(row.BindingID), values)
	}
	values.Set("agent", row.Agent)
	values.Set("container", row.ID)
	return withQuery("/bindings/new", values)
}

// reportedContainer finds a container in an approved agent's last report. Found
// is false only when the reads succeed and show no such container.
func (server *Server) reportedContainer(ctx context.Context, agentName, id string) (containerRow, bool, error) {
	agent, err := server.controller.Store().ApprovedAgent(ctx, agentName)
	if errors.Is(err, store.ErrNotFound) {
		return containerRow{}, false, nil
	}
	if err != nil {
		return containerRow{}, false, err
	}
	rows, err := server.agentRows(ctx, server.inventoryView(ctx), agent)
	if err != nil {
		return containerRow{}, false, err
	}
	for _, row := range rows {
		if row.ID == id {
			return row, true, nil
		}
	}
	return containerRow{}, false, nil
}

// boundContainer finds the reported container that a binding's key selects. A
// key can select several containers; preferred chooses among those only, so it
// cannot show a container this binding does not select. With no reported match
// the row shows the binding record alone. A failed read is an error, so that it
// cannot read as the container not being reported.
func (server *Server) boundContainer(ctx context.Context, binding store.Binding, preferred string) (containerRow, bool, error) {
	view := server.inventoryView(ctx)
	agent, err := server.controller.Store().ApprovedAgent(ctx, binding.Agent)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return containerRow{}, false, err
	}
	if err == nil {
		rows, err := server.agentRows(ctx, view, agent)
		if err != nil {
			return containerRow{}, false, err
		}
		var found *containerRow
		for _, row := range rows {
			if row.BindingID != binding.ID {
				continue
			}
			if row.ID == preferred {
				return row, true, nil
			}
			if found == nil {
				selected := row
				found = &selected
			}
		}
		if found != nil {
			return *found, true, nil
		}
	}
	row := containerRow{AssignableGroups: server.controller.AssignableGroups(binding.Agent), Agent: binding.Agent,
		Connected: server.controller.Connected(binding.Agent), Name: binding.Key.Value}
	view.applyBinding(&row, binding)
	row.Badge, row.BadgeClass = notReportedBadge()
	return row, false, nil
}

func (server *Server) policyChoices(ctx context.Context, selected []string) []policyChoice {
	policies, _ := server.controller.Store().Policies(ctx)
	choices := make([]policyChoice, 0, len(policies))
	for _, stored := range policies {
		choices = append(choices, policyChoice{Name: stored.Policy.Name, Selected: slices.Contains(selected, stored.Policy.Name), Values: stored.Policy.ValueNames()})
	}
	return choices
}

func (server *Server) renderBindScreen(writer http.ResponseWriter, request *http.Request, status int, row containerRow, form bindingForm, problem string, problemTab string) {
	if !slices.ContainsFunc(row.Candidates, func(item candidate) bool { return item.Encoded == form.Key }) {
		form.Key = ""
		if len(row.Candidates) > 0 {
			form.Key = row.Candidates[0].Encoded
		}
	}
	base := server.layout(request, "Add binding", "bindings")
	base.Problem, base.ProblemTab = problem, problemTab
	list := listContext(request.URL.Query())
	server.renderStatus(writer, request, status, "binding", bindingScreen{
		layout: base, Row: row, Reported: true, Policies: server.policyChoices(request.Context(), form.Policies), Form: form,
		Screen: containerScreenURL(row, list), Action: withQuery(bindingsPath, list), Back: addBindingURL(list),
	})
}

func (server *Server) renderBoundScreen(writer http.ResponseWriter, request *http.Request, status int, binding store.Binding, preferred string, form *bindingForm, problem string, problemTab string) {
	row, reported, err := server.boundContainer(request.Context(), binding, preferred)
	if err != nil {
		server.renderContainersUnreadable(writer, problem)
		return
	}
	readiness, err := server.controller.BindingStatus(request.Context(), binding.ID)
	if err != nil {
		server.renderContainersUnreadable(writer, problem)
		return
	}
	shown := savedForm(row)
	if form != nil {
		shown = *form
	}
	base := server.layout(request, "Binding", "bindings")
	base.Problem, base.ProblemTab = problem, problemTab
	list := listContext(request.URL.Query())
	values := maps.Clone(list)
	if reported {
		values.Set("container", row.ID)
	}
	path := bindingPath(binding.ID)
	server.renderStatus(writer, request, status, "binding", bindingScreen{
		layout: base, Row: row, Reported: reported, Readiness: &readiness, Policies: server.policyChoices(request.Context(), shown.Policies), Form: shown,
		Screen: withQuery(path, values), Action: withQuery(path+"/policy", values), Recreate: withQuery(path+"/recreate", values),
		Unbind: withQuery(path+"/unbind", values), Back: listURL(list),
	})
}

// renderContainersUnreadable answers a failed store read, which no screen can
// show as a container's state. Problem is why the submission that led to the
// read failed, so that the operator keeps the reason.
func (server *Server) renderContainersUnreadable(writer http.ResponseWriter, problem string) {
	renderUnreadable(writer, "Containers could not be read.", problem)
}

// renderBindingsUnreadable answers a failed read of a policy's bindings, so that
// it cannot read as the policy having none.
func renderBindingsUnreadable(writer http.ResponseWriter, problem string) {
	renderUnreadable(writer, "Bindings could not be read.", problem)
}

func renderUnreadable(writer http.ResponseWriter, message, problem string) {
	if problem != "" {
		message += " The request failed: " + problem
	}
	http.Error(writer, message, http.StatusInternalServerError)
}

func (server *Server) renderNotFound(writer http.ResponseWriter, request *http.Request, heading, body, back string) {
	server.renderStatus(writer, request, http.StatusNotFound, "confirm", confirmPage{
		layout: server.layout(request, heading, "bindings"), Heading: heading, Body: body, Back: back,
	})
}

func (server *Server) renderBindingNotFound(writer http.ResponseWriter, request *http.Request) {
	server.renderNotFound(writer, request, "Binding not found", "This binding does not exist. It may have been removed. Return to the bindings list to find its container.",
		listURL(listContext(request.URL.Query())))
}

func (server *Server) renderContainerNotReported(writer http.ResponseWriter, request *http.Request, problem string) {
	body := "No approved agent reports this container now. Return to Add binding to choose a container that is reported."
	if problem != "" {
		body += " The binding was not saved: " + problem
	}
	server.renderNotFound(writer, request, "Container not reported", body, addBindingURL(listContext(request.URL.Query())))
}

// loadBinding answers for the request when the binding cannot be read.
func (server *Server) loadBinding(writer http.ResponseWriter, request *http.Request) (store.Binding, bool) {
	binding, err := server.controller.Store().Binding(request.Context(), request.PathValue("id"))
	switch {
	case err == nil:
		return binding, true
	case errors.Is(err, store.ErrNotFound):
		server.renderBindingNotFound(writer, request)
	default:
		http.Error(writer, "The binding could not be loaded.", http.StatusInternalServerError)
	}
	return store.Binding{}, false
}

func (server *Server) handleBindScreen(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	row, ok, err := server.reportedContainer(request.Context(), query.Get("agent"), query.Get("container"))
	if err != nil {
		server.renderContainersUnreadable(writer, "")
		return
	}
	if !ok {
		server.renderContainerNotReported(writer, request, "")
		return
	}
	if row.Bound {
		http.Redirect(writer, request, containerScreenURL(row, listContext(query)), http.StatusSeeOther)
		return
	}
	server.renderBindScreen(writer, request, http.StatusOK, row, bindingForm{}, "", "")
}

func (server *Server) handleBindingScreen(writer http.ResponseWriter, request *http.Request) {
	if binding, ok := server.loadBinding(writer, request); ok {
		server.renderBoundScreen(writer, request, http.StatusOK, binding, request.URL.Query().Get("container"), nil, "", "")
	}
}

func (server *Server) handleCreateBinding(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	agent, container := request.PostFormValue("agent"), request.PostFormValue("container")
	typed := request.PostFormValue("typed") == "yes"
	kind, value, _ := strings.Cut(request.PostFormValue("key"), ":")
	bindingRequest, err := bindingFromForm(request)
	if err == nil && bindingRequest.Settings.Enforcement == policy.EnforcementRecreate && request.PostFormValue("understood") != "yes" {
		err = &controller.OperationError{Message: "recreate discards the container writable layer; confirm before binding", Part: policy.PartSettings}
	}
	var binding store.Binding
	if err == nil {
		target := controller.BindingTarget{Agent: agent, Key: protocol.Key{Kind: protocol.KeyKind(kind), Value: value}, Directory: request.PostFormValue("directory")}
		binding, err = server.controller.CreateBindingFor(ctx, target, bindingRequest, operatorSubject(request))
	}
	values := listContext(request.URL.Query())
	if err == nil {
		if container != "" {
			values.Set("container", container)
		}
		values.Set("notice", "bound")
		if tab := request.URL.Query().Get("tab"); tab != "" {
			values.Set("tab", tab)
		}
		http.Redirect(writer, request, withQuery(bindingPath(binding.ID), values), http.StatusSeeOther)
		return
	}
	problem := problemMessage(err)
	// A binding can be saved before OpenBao refuses its assignment.
	if binding.ID != "" {
		server.renderBoundScreen(writer, request, http.StatusUnprocessableEntity, binding, container, nil, problem, "")
		return
	}
	if typed {
		form := enteredForm(request)
		form.Agent, form.Directory = agent, request.PostFormValue("directory")
		server.renderTypedBindScreen(writer, request, http.StatusUnprocessableEntity, form, problem, bindingProblemTab(err, false))
		return
	}
	row, ok, readErr := server.reportedContainer(ctx, agent, container)
	if readErr != nil {
		server.renderContainersUnreadable(writer, problem)
		return
	}
	if !ok {
		server.renderContainerNotReported(writer, request, problem)
		return
	}
	if row.Bound {
		// Another operator bound it first, so the saved binding is the current state.
		if current, readErr := server.controller.Store().Binding(ctx, row.BindingID); readErr == nil {
			server.renderBoundScreen(writer, request, http.StatusUnprocessableEntity, current, container, nil, problem, "")
			return
		}
	}
	server.renderBindScreen(writer, request, http.StatusUnprocessableEntity, row, enteredForm(request), problem, bindingProblemTab(err, false))
}

func (server *Server) handleChangeBinding(writer http.ResponseWriter, request *http.Request) {
	binding, ok := server.loadBinding(writer, request)
	if !ok {
		return
	}
	bindingRequest, err := bindingFromForm(request)
	if err == nil {
		err = server.controller.ChangeBinding(request.Context(), binding.ID, bindingRequest, operatorSubject(request))
	}
	if err != nil {
		form := enteredForm(request)
		server.renderBoundScreen(writer, request, http.StatusUnprocessableEntity, binding, request.URL.Query().Get("container"), &form, problemMessage(err), bindingProblemTab(err, true))
		return
	}
	server.redirectToBinding(writer, request, binding.ID, "changed")
}

func (server *Server) redirectToBinding(writer http.ResponseWriter, request *http.Request, id, notice string) {
	values := screenContext(request)
	values.Set("notice", notice)
	http.Redirect(writer, request, withQuery(bindingPath(id), values), http.StatusSeeOther)
}

type confirmPage struct {
	layout
	Heading string
	Body    string
	Action  string
	Button  string
	Danger  bool
	Back    string
}

func (server *Server) handleConfirmRecreate(writer http.ResponseWriter, request *http.Request) {
	binding, ok := server.loadBinding(writer, request)
	if !ok {
		return
	}
	values := screenContext(request)
	path := bindingPath(binding.ID)
	server.render(writer, request, "confirm", confirmPage{
		layout: server.layout(request, "Request recreate", "bindings"), Heading: "Recreate this container?",
		Body:   "The agent stops the container bound by " + string(binding.Key.Kind) + " key, removes it with its volumes kept, and creates it again with the contract's mount and environment applied. Its writable layer is discarded and attached editors reconnect. The host must allow recreate.",
		Action: withQuery(path+"/recreate", values), Button: "Recreate container", Danger: true, Back: withQuery(path, values),
	})
}

func (server *Server) handleRecreate(writer http.ResponseWriter, request *http.Request) {
	binding, ok := server.loadBinding(writer, request)
	if !ok {
		return
	}
	if err := server.controller.RequestRecreate(request.Context(), binding.ID, operatorSubject(request)); err != nil {
		server.renderBoundScreen(writer, request, http.StatusUnprocessableEntity, binding, request.URL.Query().Get("container"), nil, problemMessage(err), "")
		return
	}
	server.redirectToBinding(writer, request, binding.ID, "recreate")
}

func (server *Server) handleConfirmUnbind(writer http.ResponseWriter, request *http.Request) {
	binding, ok := server.loadBinding(writer, request)
	if !ok {
		return
	}
	values := screenContext(request)
	path := bindingPath(binding.ID)
	server.render(writer, request, "confirm", confirmPage{
		layout: server.layout(request, "Unbind", "bindings"), Heading: "Unbind and revoke?",
		Body:   "This deletes the binding of policies " + strings.Join(binding.Policies, ", ") + " and its AppRole. The controller revokes the container's token in OpenBao, even when the agent is not connected, and the container's sockets stop answering. The agent removes the sockets and leaves their directory in place.",
		Action: withQuery(path+"/unbind", values), Button: "Unbind and revoke AppRole", Danger: true, Back: withQuery(path, values),
	})
}

func (server *Server) handleUnbind(writer http.ResponseWriter, request *http.Request) {
	binding, ok := server.loadBinding(writer, request)
	if !ok {
		return
	}
	err := server.controller.DeleteBinding(request.Context(), binding.ID, operatorSubject(request))
	var operation *controller.OperationError
	notice := "unbound"
	if errors.As(err, &operation) && operation.TokenLive {
		// The binding is gone; only its token may still be valid.
		notice, err = "unbound-token-live", nil
	}
	if err != nil {
		server.renderBoundScreen(writer, request, http.StatusUnprocessableEntity, binding, request.URL.Query().Get("container"), nil, problemMessage(err), "")
		return
	}
	values := listContext(request.URL.Query())
	if !values.Has("filter-agent") {
		values.Set("filter-agent", binding.Agent)
	}
	values.Set("notice", notice)
	http.Redirect(writer, request, listURL(values), http.StatusSeeOther)
}
