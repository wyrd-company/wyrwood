// ---
// relationships:
//   implements: web-interface
//   uses: controller
// ---

package web

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/wyrd-company/wyrwood/internal/controller"
	"github.com/wyrd-company/wyrwood/internal/controller/store"
)

// policyRenamePage is the screen that takes a policy's new name.
type policyRenamePage struct {
	layout
	Name        string
	NewName     string
	Revision    int
	Generation  int
	Identity    string
	Consequence string
	Action      string
	Back        string
	Bindings    []bindingRow
}

func (server *Server) policyRenamePage(request *http.Request, stored store.StoredPolicy, rows []bindingRow) policyRenamePage {
	name := stored.Policy.Name
	consequence := "No binding selects this policy."
	switch len(rows) {
	case 0:
	case 1:
		consequence = "1 binding selects this policy. It gets a fresh credential, and its token lifetime is unchanged."
	default:
		consequence = strconv.Itoa(len(rows)) + " bindings select this policy. Each gets a fresh credential, and its token lifetime is unchanged."
	}
	return policyRenamePage{
		layout: server.layout(request, "Rename policy", "policies"), Name: name, NewName: name,
		Revision: stored.Policy.Revision, Generation: stored.Policy.Generation, Identity: stored.Policy.OpenBaoPolicyName(),
		Consequence: consequence, Action: "/policies/rename?name=" + url.QueryEscape(name), Back: policyPath(name), Bindings: rows,
	}
}

func (server *Server) handleConfirmPolicyRename(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	name := request.URL.Query().Get("name")
	stored, err := server.controller.Store().Policy(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		server.renderPolicyMissing(writer, request)
		return
	}
	if err != nil {
		renderUnreadable(writer, "The policy could not be read.", "")
		return
	}
	rows, err := server.policyBindingRows(ctx, name)
	if err != nil {
		renderBindingsUnreadable(writer, "")
		return
	}
	server.render(writer, request, "policy-rename", server.policyRenamePage(request, stored, rows))
}

func (server *Server) handleRenamePolicy(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	name := request.URL.Query().Get("name")
	newName := strings.TrimSpace(request.PostFormValue("new-name"))
	revision, _ := strconv.Atoi(request.PostFormValue("revision"))
	generation, _ := strconv.Atoi(request.PostFormValue("generation"))
	renamed, err := server.controller.RenamePolicy(ctx, controller.PolicyRename{Name: name, NewName: newName, Revision: revision, Generation: generation}, operatorSubject(request))
	switch {
	case err == nil && newName == name:
		http.Redirect(writer, request, policyPath(name)+"&notice=name-unchanged", http.StatusSeeOther)
		return
	case err == nil:
		http.Redirect(writer, request, policyPath(renamed.Name)+"&notice=policy-renamed", http.StatusSeeOther)
		return
	case renamed.Name != "":
		http.Redirect(writer, request, policyPath(renamed.Name)+"&notice=rename-pending", http.StatusSeeOther)
		return
	}
	var operation *controller.OperationError
	if errors.As(err, &operation) && operation.PolicyMissing {
		server.renderPolicyMissing(writer, request)
		return
	}
	stored, readErr := server.controller.Store().Policy(ctx, name)
	if readErr != nil {
		renderUnreadable(writer, "The policy could not be read.", problemMessage(err))
		return
	}
	rows, readErr := server.policyBindingRows(ctx, name)
	if readErr != nil {
		renderBindingsUnreadable(writer, problemMessage(err))
		return
	}
	page := server.policyRenamePage(request, stored, rows)
	page.Problem, page.NewName = problemMessage(err), newName
	server.renderStatus(writer, request, http.StatusUnprocessableEntity, "policy-rename", page)
}
