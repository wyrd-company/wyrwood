// ---
// relationships:
//   implements: web-interface
//   uses: controller
// ---

package web

import (
	"context"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/wyrd-company/wyrwood/internal/controller"
	"github.com/wyrd-company/wyrwood/internal/controller/store"
)

const (
	bindingsPath   = "/bindings"
	addBindingPath = "/bindings/add"
)

// bindingRow is one stored binding of an approved agent, with the containers
// that agent reports for it and the binding's state. It is the read projection
// for every page that lists bindings.
type bindingRow struct {
	ID               string
	Agent            string
	AgentNotApproved bool
	Connected        bool
	LastReport       time.Time
	KeyKind          string
	KeyValue         string
	Policies         []string
	Containers       []observedContainer
	Badge            string
	BadgeClass       string
	Screen           string
}

// observedContainer is one reported container that a binding governs.
type observedContainer struct {
	ID     string
	Name   string
	Image  string
	State  string
	Screen string
}

// bindingRows reads every stored binding of the approved agents. A failed read
// is an error and not an empty result, so that a store failure cannot read as
// bindings being absent or their containers being not reported.
func (server *Server) bindingRows(ctx context.Context) ([]bindingRow, error) {
	data := server.controller.Store()
	agents, err := data.Agents(ctx)
	if err != nil {
		return nil, err
	}
	results, err := data.ContractResults(ctx)
	if err != nil {
		return nil, err
	}
	rows := []bindingRow{}
	for _, agent := range agents {
		if agent.State != store.AgentApproved {
			continue
		}
		agentRows, err := server.agentBindingRows(ctx, agent, results)
		if err != nil {
			return nil, err
		}
		rows = append(rows, agentRows...)
	}
	return rows, nil
}

// agentBindingRows projects one approved agent's bindings onto the containers
// that agent reports, so that a key on another agent cannot match.
func (server *Server) agentBindingRows(ctx context.Context, agent store.Agent, results map[string]store.ContractResult) ([]bindingRow, error) {
	data := server.controller.Store()
	bindings, err := data.Bindings(ctx, agent.Name)
	if err != nil {
		return nil, err
	}
	containers, _, err := data.Inventory(ctx, agent.Name)
	if err != nil {
		return nil, err
	}
	observed := map[string][]observedContainer{}
	for _, container := range containers {
		if binding, ok := controller.ContainerBinding(container, bindings); ok {
			observed[binding.ID] = append(observed[binding.ID], observedContainer{ID: container.ID, Name: container.Name, Image: container.Image, State: string(container.State)})
		}
	}
	connected := server.controller.Connected(agent.Name)
	rows := make([]bindingRow, 0, len(bindings))
	for _, binding := range bindings {
		row := storedBindingRow(binding)
		row.Connected, row.LastReport, row.Containers = connected, agent.LastReport, observed[binding.ID]
		sort.SliceStable(row.Containers, func(left, right int) bool { return row.Containers[left].Name < row.Containers[right].Name })
		if len(row.Containers) > 0 {
			row.Badge, row.BadgeClass = stateBadge(results[binding.ID])
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// storedBindingRow is what the stored binding alone says: no container matched,
// and therefore not reported.
func storedBindingRow(binding store.Binding) bindingRow {
	row := bindingRow{ID: binding.ID, Agent: binding.Agent, KeyKind: string(binding.Key.Kind), KeyValue: binding.Key.Value, Policies: binding.Policies}
	row.Badge, row.BadgeClass = notReportedBadge()
	return row
}

func sortBindingRows(rows []bindingRow, filter listFilter) {
	sortRows(rows, filter, func(row bindingRow) string { return row.sortValue(filter.Sort) },
		func(row bindingRow) string { return row.Agent }, func(row bindingRow) string { return row.ID })
}

// notReportedBadge is the state of a binding with no matching reported
// container. An earlier contract result does not describe a container that is gone.
func notReportedBadge() (string, string) {
	return "Not reported", "neutral"
}

// linkTo gives the row and its containers links to the binding's screen that
// retain the list they were opened from.
func (row *bindingRow) linkTo(list url.Values) {
	row.Screen = withQuery(bindingPath(row.ID), list)
	for index := range row.Containers {
		values := maps.Clone(list)
		values.Set("container", row.Containers[index].ID)
		row.Containers[index].Screen = withQuery(bindingPath(row.ID), values)
	}
}

func (row bindingRow) searchable() string {
	parts := []string{row.Agent, row.KeyKind, row.KeyValue, row.Badge, strings.Join(row.Policies, " ")}
	for _, container := range row.Containers {
		parts = append(parts, container.ID, container.Name, container.Image, container.State)
	}
	return strings.Join(parts, " ")
}

func (row bindingRow) sortValue(column string) string {
	name, image := row.KeyValue, ""
	if len(row.Containers) > 0 {
		name, image = row.Containers[0].Name, row.Containers[0].Image
	}
	switch column {
	case "agent":
		return row.Agent
	case "image":
		return image
	case "key":
		return row.KeyKind + ":" + row.KeyValue
	case "policies":
		return strings.Join(row.Policies, ", ")
	case "state":
		return row.Badge
	default:
		return name
	}
}

// listFilter is a list page's agent filter, text filter and sort.
type listFilter struct {
	FilterAgent string
	Query       string
	Sort        string
	Order       string
}

func parseListFilter(query url.Values, columns ...string) listFilter {
	filter := listFilter{FilterAgent: query.Get("filter-agent"), Query: query.Get("q"), Sort: query.Get("sort"), Order: query.Get("order")}
	if !slices.Contains(columns, filter.Sort) {
		filter.Sort = "name"
	}
	if filter.Order != "desc" {
		filter.Order = "asc"
	}
	return filter
}

func (filter listFilter) matches(agent, searchable string) bool {
	if filter.FilterAgent != "" && agent != filter.FilterAgent {
		return false
	}
	return strings.Contains(strings.ToLower(searchable), strings.ToLower(strings.TrimSpace(filter.Query)))
}

// sortRows orders rows by the filter's column and order. Equal values order by
// agent and then by id, so that a list keeps one order between requests.
func sortRows[Row any](rows []Row, filter listFilter, value func(Row) string, agent func(Row) string, id func(Row) string) {
	sort.Slice(rows, func(left, right int) bool {
		a, b := rows[left], rows[right]
		comparison := strings.Compare(strings.ToLower(value(a)), strings.ToLower(value(b)))
		if comparison == 0 {
			comparison = strings.Compare(agent(a), agent(b))
		}
		if comparison == 0 {
			comparison = strings.Compare(id(a), id(b))
		}
		if filter.Order == "desc" {
			return comparison > 0
		}
		return comparison < 0
	})
}

type agentChoice struct {
	Name     string
	Count    int
	Selected bool
}

type bindingsPage struct {
	layout
	listFilter
	Agents []agentChoice
	Rows   []bindingRow
	Add    string
}

func (server *Server) handleBindings(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	agents, err := server.controller.Store().Agents(ctx)
	if err != nil {
		http.Error(writer, "Bindings could not be read.", http.StatusInternalServerError)
		return
	}
	rows, err := server.bindingRows(ctx)
	if err != nil {
		http.Error(writer, "Bindings could not be read.", http.StatusInternalServerError)
		return
	}
	query := request.URL.Query()
	list := listContext(query)
	page := bindingsPage{layout: server.layout(request, "Bindings", "bindings"), Add: addBindingURL(list),
		listFilter: parseListFilter(query, "name", "agent", "image", "key", "policies", "state")}
	counts := map[string]int{}
	for _, row := range rows {
		counts[row.Agent]++
		if page.matches(row.Agent, row.searchable()) {
			row.linkTo(list)
			page.Rows = append(page.Rows, row)
		}
	}
	page.Agents = agentChoices(agents, counts, page.FilterAgent)
	sortBindingRows(page.Rows, page.listFilter)
	server.render(writer, request, "bindings", page)
}

func agentChoices(agents []store.Agent, counts map[string]int, selected string) []agentChoice {
	choices := []agentChoice{}
	for _, agent := range agents {
		if agent.State == store.AgentApproved {
			choices = append(choices, agentChoice{Name: agent.Name, Count: counts[agent.Name], Selected: agent.Name == selected})
		}
	}
	return choices
}

type addBindingPage struct {
	layout
	listFilter
	Agents []agentChoice
	Rows   []containerRow
	Back   string
	// TypedScreen is the bind screen for a key the operator types.
	TypedScreen string
}

// handleAddBinding lists the reported containers that have no binding, so that
// together with the Bindings list every reported container stays visible.
func (server *Server) handleAddBinding(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	agents, err := server.controller.Store().Agents(ctx)
	if err != nil {
		server.renderContainersUnreadable(writer, "")
		return
	}
	query := request.URL.Query()
	list := listContext(query)
	page := addBindingPage{layout: server.layout(request, "Add binding", "bindings"), Back: listURL(list), TypedScreen: typedBindingURL(list),
		listFilter: parseListFilter(query, "name", "agent", "image", "state")}
	view := server.inventoryView(ctx)
	counts := map[string]int{}
	for _, agent := range agents {
		if agent.State != store.AgentApproved {
			continue
		}
		rows, err := server.agentRows(ctx, view, agent)
		if err != nil {
			server.renderContainersUnreadable(writer, "")
			return
		}
		for _, row := range rows {
			if row.Bound {
				continue
			}
			counts[agent.Name]++
			if page.matches(row.Agent, row.addSearchable()) {
				row.Screen = containerScreenURL(row, list)
				page.Rows = append(page.Rows, row)
			}
		}
	}
	page.Agents = agentChoices(agents, counts, page.FilterAgent)
	sortRows(page.Rows, page.listFilter, func(row containerRow) string { return row.addSortValue(page.Sort) },
		func(row containerRow) string { return row.Agent }, func(row containerRow) string { return row.ID })
	server.render(writer, request, "add-binding", page)
}

func (row containerRow) addSearchable() string {
	parts := []string{row.Agent, row.ID, row.Name, row.Image, row.State}
	for _, candidate := range row.Candidates {
		parts = append(parts, candidate.Kind, candidate.Value)
	}
	return strings.Join(parts, " ")
}

func (row containerRow) addSortValue(column string) string {
	switch column {
	case "agent":
		return row.Agent
	case "image":
		return row.Image
	case "state":
		return row.State
	default:
		return row.Name
	}
}

// handleContainersRedirect keeps a saved link to the page's former address
// working. The agent-only form linked from the Agents page becomes the agent
// filter; a filter that is present wins, as it did on the former page.
func (server *Server) handleContainersRedirect(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	list := listContext(query)
	if agent := query.Get("agent"); agent != "" && !query.Has("filter-agent") {
		list.Set("filter-agent", agent)
	}
	http.Redirect(writer, request, listURL(list), http.StatusMovedPermanently)
}

func listURL(list url.Values) string {
	return withQuery(bindingsPath, list)
}

func addBindingURL(list url.Values) string {
	return withQuery(addBindingPath, list)
}
