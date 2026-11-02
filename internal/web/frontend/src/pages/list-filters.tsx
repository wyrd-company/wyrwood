// ---
// relationships:
//   implements: web-interface
// ---
import { Button, Field, Input } from "@/components/shared";
import { ago } from "@/lib/time";
import type { ListData } from "@/types";

export function ListFilters({
  data: d,
  action,
  searchLabel,
  placeholder,
  sorts,
  countLabel,
}: {
  data: ListData;
  action: string;
  searchLabel: string;
  placeholder: string;
  sorts: [string, string][];
  countLabel: (count: number) => string;
}) {
  return (
    <form method="get" action={action} className="filters list-filters">
      <Field label="Agent" id="filter-agent">
        <select
          id="filter-agent"
          name="filter-agent"
          className="w-auto"
          defaultValue={d.FilterAgent}
        >
          <option value="">All agents</option>
          {d.Agents?.map((agent) => (
            <option key={agent.Name} value={agent.Name}>
              {agent.Name} · {countLabel(agent.Count)}
            </option>
          ))}
        </select>
      </Field>
      <Field label={searchLabel} id="list-search">
        <Input
          id="list-search"
          name="q"
          type="search"
          defaultValue={d.Query}
          placeholder={placeholder}
        />
      </Field>
      <Field label="Sort by" id="list-sort">
        <select
          id="list-sort"
          name="sort"
          className="w-auto"
          defaultValue={d.Sort}
        >
          {sorts.map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Order" id="list-order">
        <select
          id="list-order"
          name="order"
          className="w-auto"
          defaultValue={d.Order}
        >
          <option value="asc">Ascending</option>
          <option value="desc">Descending</option>
        </select>
      </Field>
      <div className="list-filter-actions">
        <Button variant="outline" type="submit" className="small">
          Apply filters
        </Button>
        <a href={action}>Clear filters</a>
      </div>
    </form>
  );
}

// AgentReport states how current a row's agent is.
export function AgentReport({
  agent,
  connected,
  lastReport,
}: {
  agent: string;
  connected: boolean;
  lastReport: string;
}) {
  return (
    <>
      <span>{agent}</span>
      <div className="hint">
        {connected ? "Connected" : "Disconnected · last report shown"}
      </div>
      <div className="hint">Last report {ago(lastReport)}</div>
    </>
  );
}
