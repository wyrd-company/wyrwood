// ---
// relationships:
//   implements: web-interface
// ---
import { RowAction } from "@/components/row-action";
import { Status } from "@/components/shared";
import type { BindingRow } from "@/types";
import { AgentReport } from "./list-filters";

// The cells of a binding row, shared by every page that lists bindings.
export function BindingContainerCell({ row }: { row: BindingRow }) {
  return (
    <th scope="row">
      {row.Containers?.length ? (
        row.Containers.map((container) => (
          <a key={container.ID} className="row-link" href={container.Screen}>
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
  );
}

// A row with several containers or none is named by its binding key, so that each
// row's action has its own name.
function bindingTarget(row: BindingRow) {
  return row.Containers?.length === 1
    ? `for ${row.Containers[0].Name}`
    : row.KeyValue;
}

export function BindingActionCell({ row }: { row: BindingRow }) {
  return (
    <td>
      <RowAction
        href={row.Screen}
        text="Edit"
        icon="edit"
        name={`Edit binding ${bindingTarget(row)} on ${row.Agent}`}
      />
    </td>
  );
}

export function BindingAgentCell({ row }: { row: BindingRow }) {
  return (
    <td>
      {row.AgentNotApproved ? (
        <>
          <span>{row.Agent}</span>
          <div className="hint">Agent not approved</div>
        </>
      ) : (
        <AgentReport
          agent={row.Agent}
          connected={row.Connected}
          lastReport={row.LastReport}
        />
      )}
    </td>
  );
}

export function BindingKeyCell({ row }: { row: BindingRow }) {
  return (
    <td>
      <span className="tag">{row.KeyKind}</span>
      <div className="mono">{row.KeyValue}</div>
    </td>
  );
}

export function BindingStateCell({ row }: { row: BindingRow }) {
  return (
    <td>
      <Status kind={row.BadgeClass}>{row.Badge}</Status>
    </td>
  );
}
