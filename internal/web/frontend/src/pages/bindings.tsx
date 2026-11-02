// ---
// relationships:
//   implements: web-interface
// ---
import { Button, Notice, Table } from "@/components/shared";
import type { BindingsData } from "@/types";
import {
  BindingAgentCell,
  BindingContainerCell,
  BindingKeyCell,
  BindingStateCell,
} from "./binding-cells";
import { ListFilters } from "./list-filters";

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
                    <BindingContainerCell row={row} />
                    <BindingAgentCell row={row} />
                    <BindingKeyCell row={row} />
                    <td className="mono">{row.Policies?.join(", ")}</td>
                    <BindingStateCell row={row} />
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
