// ---
// relationships:
//   implements: web-interface
// ---
import { Button, Notice, Status, Table } from "@/components/shared";
import type { BindingsData } from "@/types";
import { AgentReport, ListFilters } from "./list-filters";

export function Bindings({ data: d }: { data: BindingsData }) {
  return (
    <main className="wide">
      <div className="flex flex-col gap-4">
        <Notice text={d.Notice} />
        {d.Agents?.length ? (
          <>
            <div className="list-actions">
              <Button asChild>
                <a href={d.Add}>Add binding</a>
              </Button>
            </div>
            <ListFilters
              data={d}
              action="/bindings"
              searchLabel="Filter bindings"
              placeholder="Name, image, key, policy…"
              sorts={[
                ["name", "Container"],
                ["agent", "Agent"],
                ["image", "Image"],
                ["key", "Key"],
                ["policies", "Policies"],
                ["state", "State"],
              ]}
              countLabel={(count) =>
                count === 1 ? "1 binding" : `${count} bindings`
              }
            />
            <section aria-label="Bindings">
              <Table
                columns={["Container", "Agent", "Key", "Policies", "State"]}
                count={d.Rows?.length ?? 0}
                empty={
                  d.FilterAgent || d.Query ? (
                    <>
                      No bindings match these filters.{" "}
                      <a href="/bindings">Clear filters</a>
                    </>
                  ) : (
                    "No bindings yet. Select Add binding to bind a reported container."
                  )
                }
              >
                {d.Rows?.map((row) => (
                  <tr key={row.ID}>
                    <th scope="row">
                      {row.Containers?.length ? (
                        row.Containers.map((container) => (
                          <a
                            key={container.ID}
                            className="row-link"
                            href={container.Screen}
                          >
                            <span>{container.Name}</span>
                            <span className="mono">{container.Image}</span>
                          </a>
                        ))
                      ) : (
                        <a className="row-link" href={row.Screen}>
                          <span>{row.KeyValue}</span>
                          <span className="hint">No container reported</span>
                        </a>
                      )}
                    </th>
                    <td>
                      <AgentReport
                        agent={row.Agent}
                        connected={row.Connected}
                        lastReport={row.LastReport}
                      />
                    </td>
                    <td>
                      <span className="tag">{row.KeyKind}</span>
                      <div className="mono">{row.KeyValue}</div>
                    </td>
                    <td className="mono">{row.Policies?.join(", ")}</td>
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
