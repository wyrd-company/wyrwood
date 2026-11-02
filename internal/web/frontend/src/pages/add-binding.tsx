// ---
// relationships:
//   implements: web-interface
// ---
import { Notice, Table } from "@/components/shared";
import type { AddBindingData } from "@/types";
import { AgentReport, ListFilters } from "./list-filters";

export function AddBinding({ data: d }: { data: AddBindingData }) {
  return (
    <main className="wide">
      <a href={d.Back}>Back to bindings</a>
      <div className="flex flex-col gap-4">
        <Notice text={d.Notice} />
        <p className="hint">
          Reported containers that have no binding. Select one to bind policies
          to it. Containers that have a binding are in the bindings list.
        </p>
        {d.Agents?.length ? (
          <>
            <ListFilters
              data={d}
              action="/bindings/add"
              searchLabel="Filter containers"
              placeholder="Name, image, key, state…"
              sorts={[
                ["name", "Container"],
                ["agent", "Agent"],
                ["image", "Image"],
                ["state", "State"],
              ]}
              countLabel={(count) =>
                count === 1 ? "1 container" : `${count} containers`
              }
            />
            <section aria-label="Reported containers with no binding">
              <Table
                columns={["Container", "Agent", "Keys offered", "State"]}
                count={d.Rows?.length ?? 0}
                empty={
                  d.FilterAgent || d.Query ? (
                    <>
                      No containers match these filters.{" "}
                      <a href="/bindings/add">Clear filters</a>
                    </>
                  ) : (
                    "Every reported container has a binding."
                  )
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
                      <AgentReport
                        agent={row.Agent}
                        connected={row.Connected}
                        lastReport={row.LastReport}
                      />
                    </td>
                    <td>
                      {row.Candidates?.map((candidate) => (
                        <span className="tag" key={candidate.Encoded}>
                          {candidate.Kind}
                        </span>
                      ))}
                    </td>
                    <td>{row.State}</td>
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
