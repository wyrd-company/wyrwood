// ---
// relationships:
//   implements: web-interface
// ---
import {
  Button,
  CSRF,
  Notice,
  Status,
  Table,
  containerURL,
  policyURL,
} from "@/components/shared";
import type { ContainerRow, ContainersData, PolicyChoice } from "@/types";
function PolicyOptions({ policies }: { policies: PolicyChoice[] | null }) {
  return policies?.map((policy) => (
    <option key={policy.Name} value={policy.Name}>
      {policy.Name} · {policy.Enforcement}
    </option>
  ));
}
export function Containers({ data: d }: { data: ContainersData }) {
  return (
    <main className="split">
      <div className="main-column flex flex-col gap-4">
        <Notice text={d.Notice} />
        {d.Agents?.length ? (
          <>
            <form method="get" action="/containers" className="filters">
              <label htmlFor="agent">Agent</label>
              <select
                id="agent"
                name="agent"
                className="w-auto"
                defaultValue={d.Agents.find((agent) => agent.Selected)?.Name}
              >
                <>
                  {d.Agents.map((agent) => (
                    <option key={agent.Name} value={agent.Name}>
                      {agent.Name} · {agent.Containers} containers
                    </option>
                  ))}
                </>
              </select>
              <Button variant="outline" type="submit" className="small">
                Show
              </Button>
              {!d.Connected && (
                <span className="hint">Disconnected · last report shown</span>
              )}
            </form>
            <section aria-label={`Containers on ${d.Agent}`}>
              <Table
                columns={["Container", "Key", "Policy", "State"]}
                count={d.Rows?.length ?? 0}
                empty="This agent has not reported any container."
              >
                {d.Rows?.map((row) => (
                  <tr
                    key={row.ID}
                    className={
                      row.ID === d.Selected?.ID ? "selected" : undefined
                    }
                  >
                    <th scope="row">
                      <a
                        className="row-link"
                        href={containerURL(d.Agent, row.ID)}
                        aria-current={
                          row.ID === d.Selected?.ID ? "true" : undefined
                        }
                      >
                        <span>{row.Name}</span>
                        <span className="mono">{row.Image}</span>
                      </a>
                    </th>
                    <td>
                      <span className="tag">{row.KeyKind}</span>
                    </td>
                    <td className="mono">
                      {row.Policy || <span className="hint">none</span>}
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
      {d.Selected && <ContainerDetails data={d} row={d.Selected} />}
    </main>
  );
}
function ContainerDetails({
  data: d,
  row: r,
}: {
  data: ContainersData;
  row: ContainerRow;
}) {
  const bindingURL = `/bindings/${encodeURIComponent(r.BindingID)}`;
  return (
    <aside className="card" aria-labelledby="h-sel">
      <div>
        <h2 id="h-sel">{r.Name}</h2>
        <span className="hint">
          on {d.Agent} · <span className="mono">{r.Image}</span> · {r.State}
        </span>
      </div>
      {r.Bound ? (
        <>
          <dl className="facts">
            <div>
              <dt>Policy</dt>
              <dd className="mono">
                <a href={policyURL(r.Policy)}>{r.Policy}</a>
              </dd>
            </div>
            <div>
              <dt>Token</dt>
              <dd>{r.Token}</dd>
            </div>
            <div className="col-span-full">
              <dt>Bound by {r.KeyKind} key</dt>
              <dd className="mono">{r.KeyValue}</dd>
            </div>
          </dl>
          <div>
            <h3>Contract check</h3>
            <ul className="plain">
              {r.Checks?.map((check) => (
                <li key={check.Label}>
                  <Status kind={`mark ${check.Status}`}>{check.Mark}</Status>
                  <span className="mono">{check.Label}</span>
                </li>
              ))}
            </ul>
          </div>
          <form method="post" action={`${bindingURL}/policy`} className="field">
            <CSRF token={d.CSRF} />
            <label htmlFor="change-policy">Change policy</label>
            <select
              id="change-policy"
              name="policy"
              defaultValue={d.Policies?.find((policy) => policy.Selected)?.Name}
            >
              <PolicyOptions policies={d.Policies} />
            </select>
            <Button variant="outline" type="submit">
              Change policy
            </Button>
          </form>
          <div className="actions">
            <Button asChild variant="outline">
              <a href={`${bindingURL}/recreate`}>Request recreate</a>
            </Button>
            <Button asChild variant="outline" className="danger">
              <a href={`${bindingURL}/unbind`}>Unbind and revoke AppRole</a>
            </Button>
          </div>
        </>
      ) : d.Policies?.length ? (
        <form method="post" action="/bindings" className="flex flex-col gap-5">
          <CSRF token={d.CSRF} />
          <input type="hidden" name="agent" value={d.Agent} />
          <input type="hidden" name="container" value={r.ID} />
          <fieldset>
            <legend>Bind by key</legend>
            {r.Candidates?.map((candidate) => (
              <label className="choice" key={candidate.Encoded}>
                <input
                  type="radio"
                  name="key"
                  value={candidate.Encoded}
                  defaultChecked={candidate.First}
                />
                <span className="flex min-w-0 flex-col">
                  <strong>
                    {candidate.Kind}{" "}
                    <span className="hint font-normal">{candidate.Note}</span>
                  </strong>
                  <span className="mono">{candidate.Value}</span>
                </span>
              </label>
            ))}
          </fieldset>
          <div className="field">
            <label htmlFor="bind-policy">Policy</label>
            <select id="bind-policy" name="policy">
              <PolicyOptions policies={d.Policies} />
            </select>
          </div>
          {!!d.Recreate?.length && (
            <div className="caution" role="note">
              <strong>
                Policies marked recreate ({d.Recreate.join(", ")}) recreate the
                container once.
              </strong>{" "}
              The agent stops it, removes it with its volumes kept, and creates
              it again with the mount and environment applied. Its writable
              layer is discarded and attached editors reconnect.
              <label className="choice mt-2">
                <input type="checkbox" name="understood" value="yes" />
                <span>I understand, if I chose a recreate policy</span>
              </label>
            </div>
          )}
          <p className="hint">
            Report policies only check the container and show what is missing
            until its definition mounts the consumer directory and sets the
            contract environment.
          </p>
          <Button type="submit" className="primary">
            Bind policy
          </Button>
        </form>
      ) : (
        <p className="hint">
          Create a policy before binding.{" "}
          <a href="/policies/edit">New policy</a>
        </p>
      )}
    </aside>
  );
}
