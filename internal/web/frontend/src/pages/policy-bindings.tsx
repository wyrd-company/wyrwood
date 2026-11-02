// ---
// relationships:
//   implements: web-interface
// ---
import { Panel, Table } from "@/components/shared";
import type { BindingRow } from "@/types";
import {
  BindingActionCell,
  BindingAgentCell,
  BindingContainerCell,
  BindingKeyCell,
  BindingStateCell,
} from "./binding-cells";
export function PolicyBindings({
  rows,
  hint,
  editable = false,
}: {
  rows: BindingRow[] | null;
  hint: string;
  editable?: boolean;
}) {
  return (
    <Panel aria-labelledby="h-bindings">
      <div>
        <h2 id="h-bindings">Bindings</h2>
        <span className="hint">{hint}</span>
      </div>
      <Table
        columns={[
          "Container",
          "Agent",
          "Key",
          "State",
          ...(editable ? ["Actions"] : []),
        ]}
        count={rows?.length ?? 0}
        empty="No binding selects this policy."
      >
        {rows?.map((row) => (
          <tr key={row.ID}>
            <BindingContainerCell row={row} />
            <BindingAgentCell row={row} />
            <BindingKeyCell row={row} />
            <BindingStateCell row={row} />
            {editable && <BindingActionCell row={row} />}
          </tr>
        ))}
      </Table>
    </Panel>
  );
}
