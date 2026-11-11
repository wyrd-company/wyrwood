// ---
// relationships:
//   implements: web-interface
//   uses: authenticate-operator-keys-over-ssh
// ---

package web

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	operatorclient "github.com/wyrd-company/wyrwood/operator"
)

type operatorKeysPage struct {
	layout
	HostKey     string
	PendingKeys []pendingOperatorKey
	Approved    []operatorKeyRow
	Ended       []operatorKeyRow
	// GrantAgents and GrantPolicies are the names the approval form offers as
	// choices: the approved agents and the stored policies. Both lists are
	// already shown on the Agents and Policies screens.
	GrantAgents   []string
	GrantPolicies []string
}

type pendingOperatorKey struct {
	Label       string
	Fingerprint string
	FirstSeen   time.Time
}

type operatorKeyRow struct {
	Label       string
	Fingerprint string
	State       string
	Agents      []string
	Policies    []string
	Actions     []operatorclient.Action
	DecidedAt   time.Time
	DecidedBy   string
	RevokedAt   time.Time
	RevokedBy   string
	LastUsed    time.Time
}

func newOperatorKeyRow(key store.OperatorKey) operatorKeyRow {
	return operatorKeyRow{
		Label: key.Label, Fingerprint: key.Fingerprint, State: string(key.State),
		Agents: key.Grant.Agents, Policies: key.Grant.Policies, Actions: key.Grant.Actions,
		DecidedAt: key.DecidedAt, DecidedBy: key.DecidedBy, RevokedAt: key.RevokedAt, RevokedBy: key.RevokedBy, LastUsed: key.LastUsed,
	}
}

func (server *Server) handleOperatorKeys(writer http.ResponseWriter, request *http.Request) {
	keys, err := server.controller.Store().OperatorKeys(request.Context())
	if err != nil {
		http.Error(writer, "Operator keys could not be read.", http.StatusInternalServerError)
		return
	}
	page := operatorKeysPage{layout: server.layout(request, "Operator keys", "operator-keys"), HostKey: server.controller.HostKeyFingerprint()}
	for _, key := range keys {
		switch key.State {
		case store.OperatorKeyPending:
			page.PendingKeys = append(page.PendingKeys, pendingOperatorKey{Label: key.Label, Fingerprint: key.Fingerprint, FirstSeen: key.FirstSeen})
		case store.OperatorKeyApproved:
			page.Approved = append(page.Approved, newOperatorKeyRow(key))
		default:
			page.Ended = append(page.Ended, newOperatorKeyRow(key))
		}
	}
	if len(page.PendingKeys) > 0 {
		if page.GrantAgents, page.GrantPolicies, err = server.grantChoices(request.Context()); err != nil {
			http.Error(writer, "Operator keys could not be read.", http.StatusInternalServerError)
			return
		}
	}
	server.render(writer, request, "operator-keys", page)
}

// grantChoices returns the approved agent names and the stored policy names.
func (server *Server) grantChoices(ctx context.Context) ([]string, []string, error) {
	agents, err := server.controller.Store().Agents(ctx)
	if err != nil {
		return nil, nil, err
	}
	policies, err := server.controller.Store().Policies(ctx)
	if err != nil {
		return nil, nil, err
	}
	agentNames, policyNames := []string{}, []string{}
	for _, agent := range agents {
		if agent.State == store.AgentApproved {
			agentNames = append(agentNames, agent.Name)
		}
	}
	for _, stored := range policies {
		policyNames = append(policyNames, stored.Policy.Name)
	}
	slices.Sort(agentNames)
	slices.Sort(policyNames)
	return agentNames, policyNames, nil
}

// grantNames reads one grant list from every value posted for a field. The
// form posts one value per selected name, and one more for names typed in, so
// each value can hold several names separated by commas or white space.
func grantNames(values []string) []string {
	names := []string{}
	for _, value := range values {
		names = append(names, grantList(value)...)
	}
	return names
}

// grantList reads one list of names, separated by commas or white space.
func grantList(value string) []string {
	names := strings.FieldsFunc(value, func(character rune) bool {
		return character == ',' || character == ' ' || character == '\n' || character == '\r' || character == '\t'
	})
	if names == nil {
		return []string{}
	}
	return names
}

func (server *Server) handleApproveOperatorKey(writer http.ResponseWriter, request *http.Request) {
	_ = request.ParseForm()
	grant := operatorclient.Grant{
		Agents: grantNames(request.PostForm["agents"]), Policies: grantNames(request.PostForm["policies"]),
		Actions: []operatorclient.Action{},
	}
	for _, action := range request.PostForm["actions"] {
		grant.Actions = append(grant.Actions, operatorclient.Action(action))
	}
	err := server.controller.ApproveOperatorKey(request.Context(), request.PostFormValue("fingerprint"), request.PostFormValue("label"), grant, operatorSubject(request))
	server.finishOperatorKeyDecision(writer, request, err, "operator-approved")
}

func (server *Server) handleRejectOperatorKey(writer http.ResponseWriter, request *http.Request) {
	err := server.controller.RejectOperatorKey(request.Context(), request.PostFormValue("fingerprint"), operatorSubject(request))
	server.finishOperatorKeyDecision(writer, request, err, "operator-rejected")
}

func (server *Server) handleConfirmRevokeOperatorKey(writer http.ResponseWriter, request *http.Request) {
	fingerprint := request.URL.Query().Get("fingerprint")
	key, err := server.controller.Store().OperatorKey(request.Context(), fingerprint)
	if err != nil || key.State != store.OperatorKeyApproved {
		base := server.layout(request, "Operator keys", "operator-keys")
		base.Problem = "No approved key has this fingerprint."
		server.renderProblem(writer, request, base, "/operator-keys")
		return
	}
	server.render(writer, request, "confirm", confirmPage{
		layout: server.layout(request, "Revoke operator key", "operator-keys"), Heading: "Revoke " + key.Label + "?",
		Body: "This key's next request fails, and so does every later connection. It cannot be approved again, and its label stays with it in the audit history. " +
			"Bindings and policies this key made stay in place.",
		Action: "/operator-keys/revoke?" + url.Values{"fingerprint": {fingerprint}}.Encode(), Button: "Revoke key", Danger: true, Back: "/operator-keys",
	})
}

func (server *Server) handleRevokeOperatorKey(writer http.ResponseWriter, request *http.Request) {
	err := server.controller.RevokeOperatorKey(request.Context(), request.URL.Query().Get("fingerprint"), operatorSubject(request))
	server.finishOperatorKeyDecision(writer, request, err, "operator-revoked")
}

func (server *Server) finishOperatorKeyDecision(writer http.ResponseWriter, request *http.Request, err error, notice string) {
	if err != nil {
		base := server.layout(request, "Operator keys", "operator-keys")
		base.Problem = problemMessage(err)
		server.renderProblem(writer, request, base, "/operator-keys")
		return
	}
	http.Redirect(writer, request, "/operator-keys?notice="+notice, http.StatusSeeOther)
}
