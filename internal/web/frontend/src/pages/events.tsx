// ---
// relationships:
//   implements: web-interface
// ---
import { Status, Table } from "@/components/shared";
import { stamp } from "@/lib/time";
import type { EventsData } from "@/types";
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
            <tr key={index}>
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
