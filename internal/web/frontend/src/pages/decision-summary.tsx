// ---
// relationships:
//   implements: web-interface
// ---
import type { BindingData } from "@/types";

// Decisions are the values a binding saves, which can sit on a tab the operator
// has not opened.
export interface Decisions {
  key: string;
  policies: string[];
  ttl: string;
  maxTTL: string;
  group: string;
  enforcement: string;
}

export function savedDecisions(d: BindingData): Decisions {
  return {
    key: d.Form.Key,
    policies: d.Policies?.filter((p) => p.Selected).map((p) => p.Name) ?? [],
    ttl: d.Form.Settings?.["token-ttl"] || "1h",
    maxTTL: d.Form.Settings?.["token-max-ttl"] || "8h",
    group: String(d.Form.Settings?.["access-group"] ?? ""),
    enforcement: d.Form.Settings?.enforcement || "report",
  };
}

export function enteredDecisions(form: HTMLFormElement): Decisions {
  const entered = new FormData(form);
  const text = (name: string) => String(entered.get(name) ?? "");
  return {
    key: text("key"),
    policies: entered.getAll("policies").map(String),
    ttl: text("token-ttl"),
    maxTTL: text("token-max-ttl"),
    group: text("access-group"),
    enforcement: text("enforcement"),
  };
}

function groupLabel(value: string, d: BindingData) {
  if (value === "") return "Owner-only";
  const name = d.Row.AssignableGroups?.groups.find(
    (g) => String(g.gid) === value,
  )?.name;
  return name ? `${name} (${value})` : value;
}

const enforcementLabels: Record<string, string> = {
  report: "Report conformance",
  recreate: "Recreate on first bind",
};

export function DecisionSummary({
  data: d,
  decisions,
}: {
  data: BindingData;
  decisions: Decisions;
}) {
  const key = d.Row.Candidates?.find((c) => c.Encoded === decisions.key);
  const missing = <span className="hint">Not set</span>;
  return (
    <dl className="facts decision-summary" aria-label="Binding decisions">
      {!d.Row.Bound && (
        <div>
          <dt>Key</dt>
          <dd className="mono">
            {key ? `${key.Kind} · ${key.Value}` : missing}
          </dd>
        </div>
      )}
      <div>
        <dt>Policies</dt>
        <dd className="mono">{decisions.policies.join(", ") || missing}</dd>
      </div>
      <div>
        <dt>Token time-to-live</dt>
        <dd>{decisions.ttl || missing}</dd>
      </div>
      <div>
        <dt>Token maximum lifetime</dt>
        <dd>{decisions.maxTTL || missing}</dd>
      </div>
      <div>
        <dt>Access group</dt>
        <dd>{groupLabel(decisions.group, d)}</dd>
      </div>
      <div>
        <dt>Enforcement</dt>
        <dd>{enforcementLabels[decisions.enforcement]}</dd>
      </div>
    </dl>
  );
}
