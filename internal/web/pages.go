// ---
// relationships:
//   implements:
//     - web-interface
//     - container-contract
// ---

package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/wyrd-company/wyrwood/internal/controller"
	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// layout is the data every authenticated page shares.
type layout struct {
	Title       string
	Current     string
	CSRF        string
	Operator    string
	Pending     int
	OpenBaoOK   bool
	Controller  string
	Notice      string
	Problem     string
	ProblemPage bool
}

type signInPage struct {
	layout
	Provider   string
	IssuerHost string
	Version    string
	Account    string
}

func (server *Server) layout(request *http.Request, title, current string) layout {
	session, _ := operatorFrom(request.Context())
	name := session.operator.DisplayName
	if session.operator.Email != "" {
		name = session.operator.Email
	}
	pending := 0
	if agents, err := server.controller.Store().Agents(request.Context()); err == nil {
		for _, agent := range agents {
			if agent.State == store.AgentPending {
				pending++
			}
		}
	}
	return layout{
		Title: title, Current: current, CSRF: session.session.CSRF, Operator: name, Pending: pending,
		OpenBaoOK: server.controller.OpenBaoReachable(request.Context()), Controller: server.controllerHost(),
		Notice: notices[request.URL.Query().Get("notice")],
	}
}

// notices are fixed messages selected by a redirect's query, so no request
// data is ever echoed into a page.
var notices = map[string]string{
	"approved": "Agent approved. It can connect now.",
	"rejected": "Agent key rejected.",
	"bound":    "Policy bound. The agent receives it on its next report.",
	"changed":  "Binding moved to the new policy. The agent obtains a fresh token.",
	"recreate": "Recreate requested. The agent reports the result.",
	"unbound":  "Binding removed and its AppRole deleted. The agent revokes the token.",
	"unbound-offline": "Binding removed and its AppRole deleted. The agent is not connected, so the container's token " +
		"stays valid until the agent reconnects and revokes it, or until the token expires.",
	"saved":      "Policy saved and accepted by OpenBao.",
	"key":        "Transit key created.",
	"rotated":    "Transit key rotated. Agents list the new version on the next request.",
	"role":       "SSH role created.",
	"sessions":   "Your other sessions were ended.",
	"signed-out": "Signed out.",
}

func operatorSubject(request *http.Request) string {
	session, _ := operatorFrom(request.Context())
	return session.session.Subject
}

func problemMessage(err error) string {
	var operation *controller.OperationError
	if errors.As(err, &operation) {
		return operation.Message
	}
	return "The operation failed."
}

// --- Agents

type agentsPage struct {
	layout
	HostKey     string
	PendingKeys []pendingAgent
	Approved    []approvedAgent
}

type pendingAgent struct {
	Name        string
	Fingerprint string
	FirstSeen   time.Time
}

type approvedAgent struct {
	Name       string
	Connected  bool
	Containers int
	Bound      int
	Health     []healthCount
	LastReport time.Time
}

type healthCount struct {
	Category string
	Count    int
}

func (server *Server) handleAgents(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	page := agentsPage{layout: server.layout(request, "Agents", "agents"), HostKey: server.controller.HostKeyFingerprint()}
	agents, err := server.controller.Store().Agents(ctx)
	if err != nil {
		http.Error(writer, "Agents could not be read.", http.StatusInternalServerError)
		return
	}
	results, _ := server.controller.Store().ContractResults(ctx)
	for _, agent := range agents {
		switch agent.State {
		case store.AgentPending:
			page.PendingKeys = append(page.PendingKeys, pendingAgent{Name: agent.Name, Fingerprint: agent.Fingerprint, FirstSeen: agent.FirstSeen})
		case store.AgentApproved:
			containers, _, _ := server.controller.Store().Inventory(ctx, agent.Name)
			bindings, _ := server.controller.Store().Bindings(ctx, agent.Name)
			entry := approvedAgent{Name: agent.Name, Connected: server.controller.Connected(agent.Name), Containers: len(containers), LastReport: agent.LastReport}
			counts := map[string]int{}
			for _, container := range containers {
				if binding, ok := controller.ContainerBinding(container, bindings); ok {
					entry.Bound++
					counts[bindingHealth(results[binding.ID])]++
				}
			}
			for _, category := range []string{"healthy", "degraded", "denied", "unknown"} {
				if counts[category] > 0 {
					entry.Health = append(entry.Health, healthCount{category, counts[category]})
				}
			}
			page.Approved = append(page.Approved, entry)
		}
	}
	server.render(writer, request, "agents", page)
}

func bindingHealth(result store.ContractResult) string {
	switch result.Outcome {
	case protocol.OutcomeConforming, protocol.OutcomeRecreated:
		return "healthy"
	case protocol.OutcomeNonConforming, protocol.OutcomeRecreateFailed, protocol.OutcomeRecreating:
		return "degraded"
	default:
		return "unknown"
	}
}

func (server *Server) handleDecideAgent(writer http.ResponseWriter, request *http.Request) {
	approve := request.PostFormValue("decision") == "approve"
	if err := server.controller.DecideAgent(request.Context(), request.PostFormValue("fingerprint"), approve, operatorSubject(request)); err != nil {
		page := agentsPage{layout: server.layout(request, "Agents", "agents")}
		page.Problem = problemMessage(err)
		server.renderProblem(writer, request, page.layout, "/agents")
		return
	}
	notice := "rejected"
	if approve {
		notice = "approved"
	}
	http.Redirect(writer, request, "/agents?notice="+notice, http.StatusSeeOther)
}

// renderProblem shows a fixed operation failure with a way back.
func (server *Server) renderProblem(writer http.ResponseWriter, request *http.Request, base layout, back string) {
	server.render(writer, request, "confirm", confirmPage{layout: base, Heading: "That did not work", Body: base.Problem, Back: back})
}

// --- Containers

type containersPage struct {
	layout
	Agents    []agentChoice
	Agent     string
	Connected bool
	Rows      []containerRow
	Selected  *containerRow
	Policies  []policyChoice
	Recreate  []string
}

type agentChoice struct {
	Name       string
	Containers int
	Selected   bool
}

type containerRow struct {
	ID         string
	Name       string
	Image      string
	State      string
	KeyKind    string
	Policy     string
	Badge      string
	BadgeClass string
	Bound      bool
	BindingID  string
	KeyValue   string
	Token      string
	Checks     []check
	Candidates []candidate
}

type check struct {
	Label  string
	Mark   string
	Status string
}

type candidate struct {
	Kind    string
	Value   string
	Note    string
	Encoded string
	First   bool
}

type policyChoice struct {
	Name        string
	Enforcement string
	Selected    bool
}

func (server *Server) handleContainers(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	page := containersPage{layout: server.layout(request, "Containers", "containers")}
	agents, _ := server.controller.Store().Agents(ctx)
	chosen := request.URL.Query().Get("agent")
	for _, agent := range agents {
		if agent.State != store.AgentApproved {
			continue
		}
		containers, _, _ := server.controller.Store().Inventory(ctx, agent.Name)
		if chosen == "" {
			chosen = agent.Name
		}
		page.Agents = append(page.Agents, agentChoice{Name: agent.Name, Containers: len(containers), Selected: agent.Name == chosen})
	}
	page.Agent = chosen
	page.Connected = server.controller.Connected(chosen)
	policies, _ := server.controller.Store().Policies(ctx)
	for _, stored := range policies {
		page.Policies = append(page.Policies, policyChoice{Name: stored.Policy.Name, Enforcement: string(stored.Policy.Contract.Enforcement)})
		if stored.Policy.Contract.Enforcement == policy.EnforcementRecreate {
			page.Recreate = append(page.Recreate, stored.Policy.Name)
		}
	}
	containers, _, _ := server.controller.Store().Inventory(ctx, chosen)
	bindings, _ := server.controller.Store().Bindings(ctx, chosen)
	results, _ := server.controller.Store().ContractResults(ctx)
	issued := lastCredential(server.controller.Events().Recent(10_000))
	selectedID := request.URL.Query().Get("container")
	for _, container := range containers {
		row := containerRow{ID: container.ID, Name: container.Name, Image: container.Image, State: string(container.State), Badge: "Not bound", BadgeClass: "neutral"}
		if len(container.Keys) > 0 {
			row.KeyKind = string(container.Keys[0].Kind)
		}
		if binding, ok := controller.ContainerBinding(container, bindings); ok {
			row.Bound, row.BindingID, row.Policy = true, binding.ID, binding.Policy
			row.KeyKind, row.KeyValue = string(binding.Key.Kind), binding.Key.Value
			result := results[binding.ID]
			row.Badge, row.BadgeClass = stateBadge(result)
			row.Token = "No credential issued yet"
			if when, ok := issued[binding.ID]; ok {
				row.Token = "Credential issued " + ago(when)
			}
			if stored, err := server.controller.Store().Policy(ctx, binding.Policy); err == nil {
				row.Checks = contractChecks(stored.Policy.Contract, container, result)
			}
		} else {
			for index, key := range container.Keys {
				note := "most stable"
				if index > 0 {
					note = "less stable"
				}
				if key.Kind == protocol.KeyName {
					note = "breaks on rename"
					if len(container.Keys) == 1 {
						note = "only key offered"
					}
				}
				row.Candidates = append(row.Candidates, candidate{Kind: string(key.Kind), Value: key.Value, Note: note,
					Encoded: string(key.Kind) + ":" + key.Value, First: index == 0})
			}
		}
		page.Rows = append(page.Rows, row)
	}
	sort.Slice(page.Rows, func(left, right int) bool { return page.Rows[left].Name < page.Rows[right].Name })
	for index := range page.Rows {
		if page.Rows[index].ID == selectedID || (selectedID == "" && index == 0) {
			page.Selected = &page.Rows[index]
		}
	}
	if page.Selected != nil {
		for index := range page.Policies {
			page.Policies[index].Selected = page.Policies[index].Name == page.Selected.Policy
		}
	}
	server.render(writer, request, "containers", page)
}

func stateBadge(result store.ContractResult) (string, string) {
	switch result.Outcome {
	case protocol.OutcomeConforming, protocol.OutcomeRecreated:
		return "Conforms", "good"
	case protocol.OutcomeNonConforming:
		return "Non-conforming", "bad"
	case protocol.OutcomeRecreating:
		return "Degraded · recreating", "warn"
	case protocol.OutcomeRecreateFailed:
		return "Degraded · recreate failed", "warn"
	default:
		return "Degraded · no report yet", "warn"
	}
}

// contractChecks shows each contract item as present or missing from the
// inventory the agent reported and its latest contract result.
func contractChecks(contract policy.Contract, container protocol.Container, result store.ContractResult) []check {
	failed := map[protocol.FailedItem]bool{}
	for _, item := range result.FailedItems {
		failed[item] = true
	}
	known := result.Outcome != ""
	mark := func(label string, present bool) check {
		switch {
		case !known:
			return check{Label: label, Mark: "UNKNOWN", Status: "neutral"}
		case present:
			return check{Label: label, Mark: "OK", Status: "good"}
		default:
			return check{Label: label, Mark: "MISSING", Status: "bad"}
		}
	}
	checks := []check{mark("mount "+contract.MountTarget, !failed[protocol.FailedMount])}
	names := map[string]bool{}
	for _, name := range container.EnvNames {
		names[name] = true
	}
	for _, entry := range contract.ExpandedEnv() {
		item := mark(entry.Name, names[entry.Name] && !failed[protocol.FailedEnv])
		if known && names[entry.Name] && failed[protocol.FailedEnv] {
			item = check{Label: entry.Name, Mark: "CHECK", Status: "warn"}
		}
		checks = append(checks, item)
	}
	if contract.AccessGroup != nil {
		checks = append(checks, mark("access group "+strconv.FormatUint(uint64(*contract.AccessGroup), 10), !failed[protocol.FailedAccessGroup]))
	}
	if failed[protocol.FailedRecreateNotAllowed] {
		checks = append(checks, check{Label: "recreate is not allowed on this host", Mark: "BLOCKED", Status: "bad"})
	}
	return checks
}

func lastCredential(recent []events.Event) map[string]time.Time {
	issued := map[string]time.Time{}
	for _, event := range recent {
		if event.Operation == events.OperationCredentialIssued && event.Outcome == events.OutcomeOK && event.Binding != "" {
			issued[event.Binding] = event.Time
		}
	}
	return issued
}

func (server *Server) handleCreateBinding(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	agent := request.PostFormValue("agent")
	back := "/containers?agent=" + url.QueryEscape(agent) + "&container=" + url.QueryEscape(request.PostFormValue("container"))
	kind, value, _ := strings.Cut(request.PostFormValue("key"), ":")
	policyName := request.PostFormValue("policy")
	base := server.layout(request, "Containers", "containers")
	if stored, err := server.controller.Store().Policy(ctx, policyName); err == nil &&
		stored.Policy.Contract.Enforcement == policy.EnforcementRecreate && request.PostFormValue("understood") != "yes" {
		base.Problem = "This policy recreates the container once and discards its writable layer. Confirm that before binding."
		server.renderProblem(writer, request, base, back)
		return
	}
	if _, err := server.controller.CreateBinding(ctx, agent, protocol.Key{Kind: protocol.KeyKind(kind), Value: value}, policyName, operatorSubject(request)); err != nil {
		base.Problem = problemMessage(err)
		server.renderProblem(writer, request, base, back)
		return
	}
	http.Redirect(writer, request, back+"&notice=bound", http.StatusSeeOther)
}

func (server *Server) bindingBack(ctx context.Context, id string) (store.Binding, string) {
	binding, err := server.controller.Store().Binding(ctx, id)
	if err != nil {
		return store.Binding{}, "/containers"
	}
	return binding, "/containers?agent=" + url.QueryEscape(binding.Agent)
}

func (server *Server) handleChangeBinding(writer http.ResponseWriter, request *http.Request) {
	id := request.PathValue("id")
	_, back := server.bindingBack(request.Context(), id)
	if err := server.controller.ChangeBinding(request.Context(), id, request.PostFormValue("policy"), operatorSubject(request)); err != nil {
		base := server.layout(request, "Containers", "containers")
		base.Problem = problemMessage(err)
		server.renderProblem(writer, request, base, back)
		return
	}
	http.Redirect(writer, request, back+"&notice=changed", http.StatusSeeOther)
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
	binding, back := server.bindingBack(request.Context(), request.PathValue("id"))
	server.render(writer, request, "confirm", confirmPage{
		layout: server.layout(request, "Request recreate", "containers"), Heading: "Recreate this container?",
		Body:   "The agent stops the container bound by " + string(binding.Key.Kind) + " key, removes it with its volumes kept, and creates it again with the contract's mount and environment applied. Its writable layer is discarded and attached editors reconnect. The host must allow recreate.",
		Action: "/bindings/" + url.PathEscape(binding.ID) + "/recreate", Button: "Recreate container", Danger: true, Back: back,
	})
}

func (server *Server) handleRecreate(writer http.ResponseWriter, request *http.Request) {
	id := request.PathValue("id")
	_, back := server.bindingBack(request.Context(), id)
	if err := server.controller.RequestRecreate(request.Context(), id, operatorSubject(request)); err != nil {
		base := server.layout(request, "Containers", "containers")
		base.Problem = problemMessage(err)
		server.renderProblem(writer, request, base, back)
		return
	}
	http.Redirect(writer, request, back+"&notice=recreate", http.StatusSeeOther)
}

func (server *Server) handleConfirmUnbind(writer http.ResponseWriter, request *http.Request) {
	binding, back := server.bindingBack(request.Context(), request.PathValue("id"))
	server.render(writer, request, "confirm", confirmPage{
		layout: server.layout(request, "Unbind", "containers"), Heading: "Unbind and revoke?",
		Body:   "This deletes the binding of policy " + binding.Policy + " and its AppRole. The agent revokes the container's token and removes its consumer directory; the container's sockets stop answering. If the agent is not connected, the token stays valid until the agent reconnects or the token expires.",
		Action: "/bindings/" + url.PathEscape(binding.ID) + "/unbind", Button: "Unbind and revoke AppRole", Danger: true, Back: back,
	})
}

func (server *Server) handleUnbind(writer http.ResponseWriter, request *http.Request) {
	id := request.PathValue("id")
	_, back := server.bindingBack(request.Context(), id)
	err := server.controller.DeleteBinding(request.Context(), id, operatorSubject(request))
	var operation *controller.OperationError
	if errors.As(err, &operation) && operation.Code == events.ErrorControllerUnavailable {
		// The binding is gone; only the revocation waits for the agent.
		http.Redirect(writer, request, back+"&notice=unbound-offline", http.StatusSeeOther)
		return
	}
	if err != nil {
		base := server.layout(request, "Containers", "containers")
		base.Problem = problemMessage(err)
		server.renderProblem(writer, request, base, back)
		return
	}
	http.Redirect(writer, request, back+"&notice=unbound", http.StatusSeeOther)
}

// --- Policies

type policiesPage struct {
	layout
	Policies []policySummary
}

type policySummary struct {
	Name        string
	Revision    int
	Enforcement string
	Bindings    int
	Agents      int
	SavedAt     time.Time
	SavedBy     string
}

func (server *Server) handlePolicies(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	page := policiesPage{layout: server.layout(request, "Policies", "policies")}
	policies, _ := server.controller.Store().Policies(ctx)
	bindings, _ := server.controller.Store().Bindings(ctx, "")
	operators, _ := server.controller.Store().Operators(ctx)
	for _, stored := range policies {
		summary := policySummary{Name: stored.Policy.Name, Revision: stored.Policy.Revision, Enforcement: string(stored.Policy.Contract.Enforcement),
			SavedAt: stored.SavedAt, SavedBy: operatorName(operators, stored.SavedBy)}
		summary.Bindings, summary.Agents = boundCounts(bindings, stored.Policy.Name)
		page.Policies = append(page.Policies, summary)
	}
	server.render(writer, request, "policies", page)
}

func boundCounts(bindings []store.Binding, name string) (int, int) {
	agents := map[string]bool{}
	count := 0
	for _, binding := range bindings {
		if binding.Policy == name {
			count++
			agents[binding.Agent] = true
		}
	}
	return count, len(agents)
}

func operatorName(operators map[string]store.Operator, subject string) string {
	if operator, ok := operators[subject]; ok {
		if operator.Email != "" {
			return operator.Email
		}
		if operator.DisplayName != "" {
			return operator.DisplayName
		}
	}
	return subject
}

type policyPage struct {
	layout
	New         bool
	Name        string
	Revision    int
	Bindings    int
	Agents      int
	HCL         string
	TokenTTL    string
	TransitKeys string
	CARoles     string
	MountTarget string
	Env         string
	AccessGroup string
	Enforcement string
	Unpermitted []string
	PolicyPath  string
}

func (server *Server) handlePolicyEditor(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	name := request.URL.Query().Get("name")
	page := policyPage{layout: server.layout(request, "Policy editor", "policies")}
	document := policy.New("", "")
	if name == "" {
		page.New = true
	} else {
		stored, err := server.controller.Store().Policy(ctx, name)
		if err != nil {
			http.Redirect(writer, request, "/policies", http.StatusSeeOther)
			return
		}
		document = stored.Policy
		bindings, _ := server.controller.Store().Bindings(ctx, "")
		page.Bindings, page.Agents = boundCounts(bindings, name)
	}
	server.fillPolicyPage(&page, document)
	server.render(writer, request, "policy", page)
}

func (server *Server) fillPolicyPage(page *policyPage, document policy.Policy) {
	mounts := server.controller.Configuration().OpenBao
	page.Name, page.Revision, page.HCL, page.TokenTTL = document.Name, document.Revision, document.OpenBao.Policy, document.OpenBao.TokenTTL
	if page.TokenTTL == "" {
		page.TokenTTL = "1h"
	}
	page.TransitKeys = strings.Join(document.TransitKeys(), "\n")
	page.CARoles = strings.Join(document.CARoles(), "\n")
	page.MountTarget = document.Contract.MountTarget
	var env []string
	names := make([]string, 0, len(document.Contract.Env))
	for name := range document.Contract.Env {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		env = append(env, name+"="+document.Contract.Env[name])
	}
	page.Env = strings.Join(env, "\n")
	if document.Contract.AccessGroup != nil {
		page.AccessGroup = strconv.FormatUint(uint64(*document.Contract.AccessGroup), 10)
	}
	page.Enforcement = string(document.Contract.Enforcement)
	page.PolicyPath = "sys/policies/acl/" + document.OpenBaoPolicyName()
	for _, key := range document.TransitKeys() {
		if !permits(document.OpenBao.Policy, mounts.TransitMount+"/sign/"+key) {
			page.Unpermitted = append(page.Unpermitted, "Transit key "+key)
		}
	}
	for _, role := range document.CARoles() {
		if !permits(document.OpenBao.Policy, mounts.SSHMount+"/sign/"+role) {
			page.Unpermitted = append(page.Unpermitted, "SSH role "+role)
		}
	}
}

var hclPath = regexp.MustCompile(`path\s+"([^"]+)"\s*\{[^}]*capabilities\s*=\s*\[([^\]]*)\]`)

// permits reports whether an HCL policy grants update on target, using
// OpenBao's glob rules for a trailing * and + segments. It is advisory: the
// definitive answer is OpenBao's at request time.
func permits(hcl, target string) bool {
	for _, match := range hclPath.FindAllStringSubmatch(hcl, -1) {
		if !strings.Contains(match[2], `"update"`) && !strings.Contains(match[2], `"create"`) && !strings.Contains(match[2], `"sudo"`) {
			continue
		}
		if strings.Contains(match[2], `"deny"`) {
			continue
		}
		if globMatch(match[1], target) {
			return true
		}
	}
	return false
}

// globMatch applies OpenBao path glob rules: a "+" segment matches one
// segment and a trailing "*" matches any suffix.
func globMatch(pattern, target string) bool {
	expression := "^"
	trailing := strings.HasSuffix(pattern, "*")
	pattern = strings.TrimSuffix(pattern, "*")
	for index, segment := range strings.Split(pattern, "/") {
		if index > 0 {
			expression += "/"
		}
		if segment == "+" {
			expression += "[^/]+"
		} else {
			expression += regexp.QuoteMeta(segment)
		}
	}
	if trailing {
		expression += ".*"
	}
	matched, err := regexp.MatchString(expression+"$", target)
	return err == nil && matched
}

func sshFingerprint(key gossh.PublicKey) string { return gossh.FingerprintSHA256(key) }

func (server *Server) handleSavePolicy(writer http.ResponseWriter, request *http.Request) {
	document, parseErr := policyFromForm(request)
	page := policyPage{layout: server.layout(request, "Policy editor", "policies"), New: request.PostFormValue("new") == "yes"}
	if parseErr == nil {
		saved, err := server.controller.SavePolicy(request.Context(), document, operatorSubject(request))
		if err == nil {
			http.Redirect(writer, request, "/policies/edit?name="+url.QueryEscape(saved.Name)+"&notice=saved", http.StatusSeeOther)
			return
		}
		page.Problem = problemMessage(err)
	} else {
		page.Problem = parseErr.Error()
	}
	server.fillPolicyPage(&page, document)
	page.TransitKeys, page.CARoles, page.Env, page.AccessGroup = request.PostFormValue("transit-keys"), request.PostFormValue("ca-roles"),
		request.PostFormValue("env"), request.PostFormValue("access-group")
	if stored, err := server.controller.Store().Policy(request.Context(), document.Name); err == nil {
		page.Revision = stored.Policy.Revision
	}
	writer.WriteHeader(http.StatusUnprocessableEntity)
	server.render(writer, request, "policy", page)
}

func policyFromForm(request *http.Request) (policy.Policy, error) {
	document := policy.New(strings.TrimSpace(request.PostFormValue("name")), strings.ReplaceAll(request.PostFormValue("hcl"), "\r\n", "\n"))
	document.OpenBao.TokenTTL = strings.TrimSpace(request.PostFormValue("token-ttl"))
	transit, roles := lines(request.PostFormValue("transit-keys")), lines(request.PostFormValue("ca-roles"))
	if len(transit) > 0 || len(roles) > 0 {
		document.SSH = &policy.SSH{TransitKeys: transit, CARoles: roles}
	}
	document.Contract.MountTarget = strings.TrimSpace(request.PostFormValue("mount-target"))
	document.Contract.Env = map[string]string{}
	for _, line := range lines(request.PostFormValue("env")) {
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			return document, fmt.Errorf("each environment line must be NAME=value")
		}
		document.Contract.Env[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}
	if group := strings.TrimSpace(request.PostFormValue("access-group")); group != "" {
		parsed, err := strconv.ParseUint(group, 10, 32)
		if err != nil {
			return document, fmt.Errorf("the access group must be a number")
		}
		value := uint32(parsed)
		document.Contract.AccessGroup = &value
	}
	document.Contract.Enforcement = policy.Enforcement(request.PostFormValue("enforcement"))
	return document, nil
}

func lines(value string) []string {
	var result []string
	for _, line := range strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			result = append(result, line)
		}
	}
	return result
}

// --- Keys

type keysPage struct {
	layout
	TransitMount string
	SSHMount     string
	Transit      []transitRow
	Roles        []roleRow
	Unavailable  bool
}

type transitRow struct {
	Name        string
	Type        string
	Version     int
	Fingerprint string
	UsedBy      []string
}

type roleRow struct {
	Name         string
	AllowedUsers string
	TTL          string
	UsedBy       []string
}

func (server *Server) handleKeys(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	mounts := server.controller.Configuration().OpenBao
	page := keysPage{layout: server.layout(request, "OpenBao keys", "keys"), TransitMount: mounts.TransitMount, SSHMount: mounts.SSHMount}
	policies, _ := server.controller.Store().Policies(ctx)
	usage := func(match func(policy.Policy) []string, name string) []string {
		var users []string
		for _, stored := range policies {
			for _, candidate := range match(stored.Policy) {
				if candidate == name {
					users = append(users, stored.Policy.Name)
				}
			}
		}
		return users
	}
	keys, keyErr := server.controller.OpenBao().ListTransitKeys(ctx)
	roles, roleErr := server.controller.OpenBao().ListSSHRoles(ctx)
	page.Unavailable = keyErr != nil || roleErr != nil
	for _, key := range keys {
		row := transitRow{Name: key.Name, Type: key.Type, Version: key.LatestVersion, UsedBy: usage(policy.Policy.TransitKeys, key.Name)}
		if key.PublicKey != nil {
			row.Fingerprint = sshFingerprint(key.PublicKey)
		}
		page.Transit = append(page.Transit, row)
	}
	for _, role := range roles {
		page.Roles = append(page.Roles, roleRow{Name: role.Name, AllowedUsers: role.AllowedUsers, TTL: role.TTL, UsedBy: usage(policy.Policy.CARoles, role.Name)})
	}
	server.render(writer, request, "keys", page)
}

var keyNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

func (server *Server) keyProblem(writer http.ResponseWriter, request *http.Request, message string) {
	base := server.layout(request, "OpenBao keys", "keys")
	base.Problem = message
	server.renderProblem(writer, request, base, "/keys")
}

func (server *Server) handleCreateTransitKey(writer http.ResponseWriter, request *http.Request) {
	name := request.PostFormValue("name")
	if !keyNamePattern.MatchString(name) {
		server.keyProblem(writer, request, "Key names use letters, digits, dot, dash, and underscore.")
		return
	}
	if err := server.controller.OpenBao().CreateTransitKey(request.Context(), name, request.PostFormValue("type")); err != nil {
		server.keyProblem(writer, request, "OpenBao did not create the key.")
		return
	}
	http.Redirect(writer, request, "/keys?notice=key", http.StatusSeeOther)
}

func (server *Server) handleRotateTransitKey(writer http.ResponseWriter, request *http.Request) {
	name := request.PostFormValue("name")
	if !keyNamePattern.MatchString(name) {
		server.keyProblem(writer, request, "Unknown key.")
		return
	}
	if err := server.controller.OpenBao().RotateTransitKey(request.Context(), name); err != nil {
		server.keyProblem(writer, request, "OpenBao did not rotate the key.")
		return
	}
	http.Redirect(writer, request, "/keys?notice=rotated", http.StatusSeeOther)
}

var ttlPattern = regexp.MustCompile(`^[0-9]{1,6}[smh]$`)

func (server *Server) handleCreateSSHRole(writer http.ResponseWriter, request *http.Request) {
	name, users, ttl := request.PostFormValue("name"), strings.TrimSpace(request.PostFormValue("allowed-users")), request.PostFormValue("ttl")
	if !keyNamePattern.MatchString(name) || users == "" || !ttlPattern.MatchString(ttl) {
		server.keyProblem(writer, request, "A role needs a name, allowed users, and a time-to-live such as 30m.")
		return
	}
	if err := server.controller.OpenBao().CreateSSHRole(request.Context(), name, users, ttl); err != nil {
		server.keyProblem(writer, request, "OpenBao did not create the role.")
		return
	}
	http.Redirect(writer, request, "/keys?notice=role", http.StatusSeeOther)
}

// --- Events

type eventsPage struct {
	layout
	Outcome  string
	Outcomes []string
	Events   []eventRow
}

type eventRow struct {
	Time      time.Time
	Operation string
	Outcome   string
	Error     string
	Class     string
	Subject   string
	Operator  string
	Latency   string
}

func (server *Server) handleEvents(writer http.ResponseWriter, request *http.Request) {
	page := eventsPage{layout: server.layout(request, "Events", "events"), Outcome: request.URL.Query().Get("outcome"),
		Outcomes: []string{"ok", "denied", "failed", "timeout"}}
	operators, _ := server.controller.Store().Operators(request.Context())
	recent := server.controller.Events().Recent(10_000)
	for index := len(recent) - 1; index >= 0 && len(page.Events) < 500; index-- {
		event := recent[index]
		if page.Outcome != "" && string(event.Outcome) != page.Outcome {
			continue
		}
		var subject []string
		for _, part := range []string{event.Agent, event.ContainerKey, event.Policy, event.Binding} {
			if part != "" {
				subject = append(subject, part)
			}
		}
		row := eventRow{Time: event.Time, Operation: string(event.Operation), Outcome: string(event.Outcome), Error: string(event.ErrorCode),
			Subject: strings.Join(subject, " · "), Latency: event.Latency.Round(time.Millisecond).String()}
		if event.Operator != "" {
			row.Operator = operatorName(operators, event.Operator)
		}
		row.Class = map[string]string{"ok": "good", "denied": "bad", "failed": "warn", "timeout": "warn"}[row.Outcome]
		page.Events = append(page.Events, row)
	}
	server.render(writer, request, "events", page)
}

// --- Security

type securityPage struct {
	layout
	Email         string
	Name          string
	AdmittedGroup string
	AllowedGroups []string
	Provider      string
	Issuer        string
	ClientID      string
	RedirectURL   string
	Reachable     bool
	Fetched       time.Time
	Sessions      []sessionRow
}

type sessionRow struct {
	Current   bool
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (server *Server) handleSecurity(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	current, _ := operatorFrom(ctx)
	configuration := server.controller.Configuration().OIDC
	page := securityPage{
		layout: server.layout(request, "Security", "security"), Email: current.operator.Email, Name: current.operator.DisplayName,
		AdmittedGroup: current.session.AdmittedGroup, AllowedGroups: configuration.AllowedGroups, Provider: configuration.ProviderName,
		Issuer: configuration.Issuer, ClientID: configuration.ClientID, RedirectURL: configuration.RedirectURL,
	}
	page.Reachable, page.Fetched = server.provider.reachable(ctx)
	sessions, _ := server.controller.Store().OperatorSessions(ctx, current.session.Subject, server.now())
	for _, session := range sessions {
		page.Sessions = append(page.Sessions, sessionRow{Current: session.IDHash == current.session.IDHash, CreatedAt: session.CreatedAt, ExpiresAt: session.ExpiresAt})
	}
	server.render(writer, request, "security", page)
}

func (server *Server) handleEndOtherSessions(writer http.ResponseWriter, request *http.Request) {
	current, _ := operatorFrom(request.Context())
	_, _ = server.controller.Store().DeleteOtherSessions(request.Context(), current.session.Subject, current.session.IDHash)
	http.Redirect(writer, request, "/security?notice=sessions", http.StatusSeeOther)
}
