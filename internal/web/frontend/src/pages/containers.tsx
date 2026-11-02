// ---
// relationships:
//   implements: web-interface
// ---
import {
  Button,
  Notice,
  Status,
  Table,
  Input,
  Field,
} from "@/components/shared";
import type { ContainersData } from "@/types";
import { ago } from "@/lib/time";
export function Containers({ data: d }: { data: ContainersData }) {
  return (
    <main className="wide">
      <div className="flex flex-col gap-4">
        <Notice text={d.Notice} />
        {d.Agents?.length ? (
          <>
            <form
              method="get"
              action="/containers"
              className="filters container-filters"
            >
              <Field label="Agent" id="filter-agent">
                <select
                  id="filter-agent"
                  name="filter-agent"
                  className="w-auto"
                  defaultValue={d.FilterAgent}
                >
                  <option value="">All agents</option>
                  {d.Agents.map((agent) => (
                    <option key={agent.Name} value={agent.Name}>
                      {agent.Name} · {agent.Containers} containers
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Filter containers" id="container-search">
                <Input
                  id="container-search"
                  name="q"
                  type="search"
                  defaultValue={d.Query}
                  placeholder="Name, image, policy, state…"
                />
              </Field>
              <Field label="Sort by" id="container-sort">
                <select
                  id="container-sort"
                  name="sort"
                  className="w-auto"
                  defaultValue={d.Sort}
                >
                  <option value="name">Container</option>
                  <option value="agent">Agent</option>
                  <option value="image">Image</option>
                  <option value="state">State</option>
                </select>
              </Field>
              <Field label="Order" id="container-order">
                <select
                  id="container-order"
                  name="order"
                  className="w-auto"
                  defaultValue={d.Order}
                >
                  <option value="asc">Ascending</option>
                  <option value="desc">Descending</option>
                </select>
              </Field>
              <div className="container-filter-actions">
                <Button variant="outline" type="submit" className="small">
                  Apply filters
                </Button>
                <a href="/containers">Clear filters</a>
              </div>
            </form>
            <section aria-label="Reported containers">
              <Table
                columns={["Container", "Agent", "Key", "Policies", "State"]}
                count={d.Rows?.length ?? 0}
                empty={
                  d.FilterAgent || d.Query
                    ? "No containers match these filters."
                    : "No containers have been reported."
                }
              >
                {d.Rows?.map((row) => (
                  <tr key={JSON.stringify([row.Agent, row.ID])}>
                    <th scope="row">
                      <a className="row-link" href={row.Screen}>
                        <span>{row.Name}</span>
                        <span className="mono">{row.Image}</span>
                      </a>
                    </th>
                    <td>
                      <span>{row.Agent}</span>
                      <div className="hint">
                        {row.Connected
                          ? "Connected"
                          : "Disconnected · last report shown"}
                      </div>
                      <div className="hint">
                        Last report {ago(row.LastReport)}
                      </div>
                    </td>
                    <td>
                      <span className="tag">{row.KeyKind}</span>
                    </td>
                    <td className="mono">
                      {row.Policies?.join(", ") || (
                        <span className="hint">none</span>
                      )}
                    </td>
                    <td>
                      <Status kind={row.BadgeClass}>{row.Badge}</Status>
                    </td>
                  </tr>
                ))}
              </Table>
            </section>
          </>
        ) : (
          <p className="hint">No approved agent has reported yet.</p>
        )}
      </div>
    </main>
  );
}
