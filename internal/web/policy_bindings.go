// ---
// relationships:
//   implements: web-interface
//   uses: controller
// ---

package web

import (
	"context"
	"net/url"
	"slices"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
)

// policyBindingRows reads every stored binding that selects the policy. Unlike
// the Bindings list it keeps a binding on an agent that is not approved: its
// agent's reports are not read, and the row says so. It reads only the agents
// that hold such a binding, so that an unrelated agent's report cannot fail the
// page.
func (server *Server) policyBindingRows(ctx context.Context, name string) ([]bindingRow, error) {
	data := server.controller.Store()
	bindings, err := data.Bindings(ctx, "")
	if err != nil {
		return nil, err
	}
	agents, err := data.Agents(ctx)
	if err != nil {
		return nil, err
	}
	results, err := data.ContractResults(ctx)
	if err != nil {
		return nil, err
	}
	approved := map[string]store.Agent{}
	for _, agent := range agents {
		if agent.State == store.AgentApproved {
			approved[agent.Name] = agent
		}
	}
	rows := []bindingRow{}
	read := map[string]bool{}
	for _, binding := range bindings {
		if !binding.HasPolicy(name) {
			continue
		}
		agent, ok := approved[binding.Agent]
		if !ok {
			row := storedBindingRow(binding)
			row.AgentNotApproved = true
			rows = append(rows, row)
			continue
		}
		if read[agent.Name] {
			continue
		}
		read[agent.Name] = true
		agentRows, err := server.agentBindingRows(ctx, agent, results)
		if err != nil {
			return nil, err
		}
		for _, row := range agentRows {
			if slices.Contains(row.Policies, name) {
				rows = append(rows, row)
			}
		}
	}
	for index := range rows {
		rows[index].linkTo(url.Values{})
	}
	sortBindingRows(rows, listFilter{Sort: "name", Order: "asc"})
	return rows, nil
}

// fillPolicyBindings gives a saved policy's page its section and the header
// counts, both from the same rows, so that they cannot disagree.
func (server *Server) fillPolicyBindings(ctx context.Context, page *policyPage, name string) error {
	rows, err := server.policyBindingRows(ctx, name)
	if err != nil {
		return err
	}
	agents := map[string]bool{}
	for _, row := range rows {
		agents[row.Agent] = true
	}
	page.BindingRows, page.Bindings, page.Agents = rows, len(rows), len(agents)
	return nil
}
