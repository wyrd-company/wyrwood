// ---
// relationships:
//   implements: web-interface
// ---
import { Button, Notice, Table, policyURL } from "@/components/shared";
import { ago } from "@/lib/time";
import type { PoliciesData } from "@/types";
export function Policies({ data: d }: { data: PoliciesData }) {
  return (
    <main>
      <Notice text={d.Notice} />
      <div className="section-head">
        <p className="hint">
          Each policy pairs an OpenBao HCL policy with a container contract.
        </p>
        <Button asChild className="primary">
          <a href="/policies/edit">New policy</a>
        </Button>
      </div>
      <Table
        columns={["Policy", "Revision", "Bound", "Saved"]}
        count={d.Policies?.length ?? 0}
        empty="No policies yet."
      >
        {d.Policies?.map((policy) => (
          <tr key={policy.Name}>
            <th scope="row" className="mono">
              <a href={policyURL(policy.Name)}>{policy.Name}</a>
            </th>
            <td>{policy.Revision}</td>
            <td>
              {policy.Bindings} container{policy.Bindings !== 1 && "s"} on{" "}
              {policy.Agents} agent{policy.Agents !== 1 && "s"}
            </td>
            <td>
              {ago(policy.SavedAt)}
              {policy.SavedBy && ` by ${policy.SavedBy}`}
            </td>
          </tr>
        ))}
      </Table>
    </main>
  );
}
