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

	"github.com/wyrd-company/wyrwood/internal/controller"
	"github.com/wyrd-company/wyrwood/internal/controller/store"
)

// policyDeletePage is the confirm screen of a policy, with the bindings that
// block the delete when any do.
type policyDeletePage struct {
	confirmPage
	Blockers []bindingRow
}

const policyEditPath = "/policies/edit?name="

func policyPath(name string) string { return policyEditPath + url.QueryEscape(name) }

func (server *Server) policyDeleteConfirm(request *http.Request, stored store.StoredPolicy) policyDeletePage {
	name := stored.Policy.Name
	return policyDeletePage{confirmPage: confirmPage{
		layout: server.layout(request, "Delete policy", "policies"), Heading: "Delete policy " + name + "?",
		Body:   "This removes the policy " + name + " and its OpenBao policy " + stored.Policy.OpenBaoPolicyName() + ". No binding selects it. A new policy with this name starts at revision 1 and is a different policy with its own OpenBao policy, so a token of this one has no access to it.",
		Action: "/policies/delete?name=" + url.QueryEscape(name), Button: "Delete policy", Danger: true, Back: policyPath(name),
	}}
}

func (server *Server) policyDeleteRefusal(request *http.Request, name string, rows []bindingRow) policyDeletePage {
	body := "1 binding selects this policy."
	if len(rows) != 1 {
		body = strconv.Itoa(len(rows)) + " bindings select this policy."
	}
	return policyDeletePage{Blockers: rows, confirmPage: confirmPage{
		layout: server.layout(request, "Delete policy", "policies"), Heading: name + " cannot be deleted",
		Body: body + " Change or unbind each one, then delete the policy. A binding blocks the delete even when its container is no longer reported.",
		Back: policyPath(name),
	}}
}

func (server *Server) renderPolicyMissing(writer http.ResponseWriter, request *http.Request) {
	server.renderStatus(writer, request, http.StatusNotFound, "confirm", confirmPage{
		layout: server.layout(request, "Policy not found", "policies"), Heading: "Policy not found",
		Body: "This policy does not exist. Another operator may have deleted it.", Back: "/policies",
	})
}

func (server *Server) handleConfirmPolicyDelete(writer http.ResponseWriter, request *http.Request) {
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
	if len(rows) > 0 {
		server.render(writer, request, "policy-delete", server.policyDeleteRefusal(request, name, rows))
		return
	}
	server.render(writer, request, "policy-delete", server.policyDeleteConfirm(request, stored))
}

func (server *Server) handleDeletePolicy(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	name := request.URL.Query().Get("name")
	err := server.controller.DeletePolicy(ctx, name, operatorSubject(request))
	if err == nil {
		http.Redirect(writer, request, "/policies?notice=policy-deleted", http.StatusSeeOther)
		return
	}
	var operation *controller.OperationError
	errors.As(err, &operation)
	if operation != nil && operation.PolicyMissing {
		server.renderPolicyMissing(writer, request)
		return
	}
	if operation != nil && operation.PolicyBound {
		rows, readErr := server.policyBindingRows(ctx, name)
		if readErr != nil {
			renderBindingsUnreadable(writer, problemMessage(err))
			return
		}
		page := server.policyDeleteRefusal(request, name, rows)
		page.Problem = problemMessage(err)
		server.renderStatus(writer, request, http.StatusUnprocessableEntity, "policy-delete", page)
		return
	}
	stored, readErr := server.controller.Store().Policy(ctx, name)
	if readErr != nil {
		renderUnreadable(writer, "The policy could not be read.", problemMessage(err))
		return
	}
	page := server.policyDeleteConfirm(request, stored)
	page.Problem = problemMessage(err)
	server.renderStatus(writer, request, http.StatusUnprocessableEntity, "policy-delete", page)
}
