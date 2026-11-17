// ---
// relationships:
//   implements: web-interface
// ---
import { Fragment } from "react";
import { Status, Table } from "@/components/shared";
import { stamp } from "@/lib/time";
import type { EventsData, GrantChange } from "@/types";

// GrantChangeDetails shows the old and new grant of an operator key grant edit,
// or says that the history no longer holds all of it.
function GrantChangeDetails({
  subject,
  change,
}: {
  subject: string;
  change: GrantChange;
}) {
  return (
    <details className="grant-change">
      <summary>Old and new grant</summary>
      <code className="break-all hint">{change.Fingerprint}</code>
      {change.Complete ? (
        <table className="grant-diff">
          <caption className="visually-hidden">
            Old and new grant of {subject}
          </caption>
          <thead>
            <tr>
              <th scope="col">Grant</th>
              <th scope="col">Before</th>
              <th scope="col">After</th>
            </tr>
          </thead>
          <tbody>
            {change.Rows?.map((row) => (
              <tr key={row.Name}>
                <th scope="row">{row.Name}</th>
                <td>{row.Before}</td>
                <td className={row.Changed ? "changed" : undefined}>
                  {row.After}
                  {row.Changed && <strong> · Changed</strong>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="hint">
          Part of this edit is no longer in the event history, so its old and
          new grant are not shown.
        </p>
      )}
      {change.EditURL && <a href={change.EditURL}>View current key grant</a>}
    </details>
  );
}
export function Events({ data: d }: { data: EventsData }) {
  return (
    <main>
      <div className="filters" role="group" aria-label="Filter by outcome">
        <a href="/events" aria-current={!d.Outcome ? "true" : undefined}>
          All
        </a>
        {d.Outcomes.map((outcome) => (
          <a
            key={outcome}
            href={`/events?outcome=${encodeURIComponent(outcome)}`}
            aria-current={d.Outcome === outcome ? "true" : undefined}
          >
            {outcome}
          </a>
        ))}
        <span className="hint">
          Controller events, newest first · retention 10,000
        </span>
      </div>
      <section aria-label="Event history">
        <Table
          columns={[
            "Time",
            "Operation",
            "Outcome",
            "Subject",
            "Operator",
            "Latency",
          ]}
          count={d.Events?.length ?? 0}
          empty="No events."
        >
          {d.Events?.map((event, index) => (
            <Fragment key={index}>
              <tr className={event.Grant ? "has-detail" : undefined}>
                <td className="mono whitespace-nowrap text-xs">
                  {stamp(event.Time)}
                </td>
                <td className="mono text-sm">{event.Operation}</td>
                <td>
                  <Status kind={event.Class}>{event.Outcome}</Status>
                  {event.Error && (
                    <span className="hint mono"> {event.Error}</span>
                  )}
                </td>
                <td className="mono text-xs">{event.Subject}</td>
                <td>{event.Operator}</td>
                <td className="mono text-xs">{event.Latency}</td>
              </tr>
              {event.Grant && (
                <tr className="event-detail">
                  {/* The old and new grant spans the row, so the columns above
                    keep their widths. */}
                  <td colSpan={6}>
                    <GrantChangeDetails
                      subject={event.Subject}
                      change={event.Grant}
                    />
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </Table>
      </section>
      <p className="hint">
        Events hold categorical outcomes only: no tokens, secret values, HCL,
        request paths beyond the mount category, or raw upstream errors. Each
        agent keeps its own history; read it with{" "}
        <code>wyrwood agent events</code> on the host.
      </p>
    </main>
  );
}
