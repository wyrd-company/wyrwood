// ---
// relationships:
//   implements: web-interface
// ---
import {
  Button,
  CSRF,
  Notice,
  Panel,
  Status,
  Table,
  containerURL,
} from "@/components/shared";
import { ago } from "@/lib/time";
import type { AgentsData } from "@/types";
export function Agents({ data: d }: { data: AgentsData }) {
  return (
    <main>
      <Notice text={d.Notice} />
      <Panel aria-labelledby="h-version">
        <h2 id="h-version">Controller version</h2>
        <p>
          <code>{d.Version}</code>
        </p>
      </Panel>
      <Panel aria-labelledby="h-hk">
        <div className="section-head">
          <div>
            <h2 id="h-hk" className="hint">
              Controller SSH host key
            </h2>
            <code className="break-all">{d.HostKey}</code>
          </div>
          <p className="hint max-w-sm">
            Compare with the fingerprint <code>wyrwood agent login</code> shows
            on the host before accepting it there.
          </p>
        </div>
      </Panel>
      {!!d.PendingKeys?.length && (
        <section aria-labelledby="h-pend" className="flex flex-col gap-3">
          <div className="section-head">
            <h2 id="h-pend">Pending approval</h2>
            <span className="sub">
              {d.PendingKeys.length} key{d.PendingKeys.length > 1 && "s"}
            </span>
          </div>
          {d.PendingKeys.map((key) => (
            <Panel key={key.Fingerprint} className="pending-key">
              <div className="min-w-0 flex-1">
                <div>
                  <strong>{key.Name}</strong>{" "}
                  <span className="hint">
                    presented hostname · first seen {ago(key.FirstSeen)}
                  </span>
                </div>
                <code className="break-all">{key.Fingerprint}</code>
                <p className="hint">
                  Approve only if this matches the fingerprint printed by{" "}
                  <code>wyrwood agent login</code> on {key.Name}.
                </p>
              </div>
              <form method="post" action="/agents/decide" className="actions">
                <CSRF token={d.CSRF} />
                <input
                  type="hidden"
                  name="fingerprint"
                  value={key.Fingerprint}
                />
                <Button
                  variant="outline"
                  type="submit"
                  name="decision"
                  value="reject"
                  className="danger"
                >
                  Reject
                </Button>
                <Button
                  type="submit"
                  name="decision"
                  value="approve"
                  className="primary"
                >
                  Approve agent
                </Button>
              </form>
            </Panel>
          ))}
        </section>
      )}
      <section aria-labelledby="h-appr" className="flex flex-col gap-3">
        <h2 id="h-appr">Approved agents</h2>
        {d.Approved?.length ? (
          <Table
            columns={[
              "Agent",
              "Version",
              "Session",
              "Containers",
              "Bound",
              "Binding health",
              "Last report",
            ]}
            count={d.Approved.length}
            empty=""
          >
            {d.Approved.map((agent) => (
              <tr key={agent.Name}>
                <th scope="row">
                  <a href={containerURL(agent.Name)}>{agent.Name}</a>
                </th>
                <td>
                  <code>{agent.Version || "unknown"}</code>
                  {!agent.Version && (
                    <>
                      {" "}
                      <Status kind="degraded">Update available</Status>
                    </>
                  )}
                </td>
                <td>
                  <span className={`dot ${agent.Connected ? "" : "off"}`} />
                  {agent.Connected ? "Connected" : "Disconnected"}
                </td>
                <td>{agent.Containers}</td>
                <td>{agent.Bound}</td>
                <td>
                  {agent.Health?.length ? (
                    agent.Health.map((health) => (
                      <Status key={health.Category} kind={health.Category}>
                        {health.Count} {health.Category}
                      </Status>
                    ))
                  ) : (
                    <span className="hint">none bound</span>
                  )}
                </td>
                <td>
                  {ago(agent.LastReport)}
                  {!agent.Connected && " · serving from cache"}
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <p className="hint">
            No agent is approved yet. Run <code>wyrwood agent login</code> on a
            host, then approve its key here.
          </p>
        )}
        <p className="hint">
          A disconnected agent keeps serving its containers from cached policy
          until their tokens expire.
        </p>
      </section>
    </main>
  );
}
