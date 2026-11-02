// ---
// relationships:
//   implements: web-interface
// ---
import type { PolicyDeleteData } from "@/types";
import { Confirm } from "./confirm";
import { PolicyBindings } from "./policy-bindings";
export function PolicyDelete({ data: d }: { data: PolicyDeleteData }) {
  return (
    <Confirm data={d}>
      {d.Blockers?.length ? (
        <PolicyBindings
          rows={d.Blockers}
          hint="Open a binding to change its policies or unbind it."
        />
      ) : null}
    </Confirm>
  );
}
