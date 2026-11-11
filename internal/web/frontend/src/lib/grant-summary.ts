// ---
// relationships:
//   implements: web-interface
//   uses: operator-interface
// ---

// The summary states what an operator key's grant allows, in the terms of the
// grant rules: a grant covers a binding when it allows the binding's agent and
// every policy the binding holds. `read` returns the allowed policies and the
// covered bindings, `bind` creates and removes covered bindings, and
// `policy-write` writes an allowed policy when the grant covers every binding
// that holds it.

export const allNames = "*";

export type GrantAction = "read" | "bind" | "policy-write";

export const grantActions: GrantAction[] = ["read", "bind", "policy-write"];

export interface GrantChoice {
  agents: string[];
  policies: string[];
  actions: string[];
}

export interface SummaryLine {
  action: GrantAction;
  allowed: boolean;
  text: string;
}

export interface GrantSummary {
  // refusals name each reason the server refuses the choice.
  refusals: string[];
  lines: SummaryLine[];
}

// grantNames reads names separated by commas, spaces, tabs, or line breaks,
// as the server does.
export function grantNames(value: string): string[] {
  return value.split(/[, \t\r\n]+/).filter(Boolean);
}

function unique(names: string[]) {
  return [...new Set(names)];
}

function isAll(names: string[]) {
  return names.length === 1 && names[0] === allNames;
}

function join(names: string[]) {
  if (names.length <= 2) return names.join(" and ");
  return `${names.slice(0, -1).join(", ")}, and ${names[names.length - 1]}`;
}

function agentsText(agents: string[]) {
  return isAll(agents) ? "every agent" : join(agents);
}

function policiesText(policies: string[]) {
  return isAll(policies) ? "every policy" : join(policies);
}

// coveredBindings names the bindings the grant covers. Both lists hold at
// least one entry.
function coveredBindings(agents: string[], policies: string[]) {
  if (isAll(agents) && isAll(policies)) return "every binding";
  const on = `bindings on ${agentsText(agents)}`;
  if (isAll(policies)) return on;
  return `${on} that hold no policy other than ${join(policies)}`;
}

function readLine(agents: string[], policies: string[]): SummaryLine {
  const line = (allowed: boolean, text: string): SummaryLine => ({
    action: "read",
    allowed,
    text,
  });
  if (!policies.length)
    return line(
      false,
      "Cannot read policies or bindings: no policy is selected.",
    );
  if (!agents.length)
    return line(
      true,
      `Can read ${policiesText(policies)}. Cannot read bindings: no agent is selected.`,
    );
  return line(
    true,
    `Can read ${policiesText(policies)}, and ${coveredBindings(agents, policies)}.`,
  );
}

function bindLine(agents: string[], policies: string[]): SummaryLine {
  const line = (allowed: boolean, text: string): SummaryLine => ({
    action: "bind",
    allowed,
    text,
  });
  if (!agents.length)
    return line(false, "Cannot bind or unbind: no agent is selected.");
  if (!policies.length)
    return line(false, "Cannot bind or unbind: no policy is selected.");
  return line(
    true,
    `Can create and remove ${coveredBindings(agents, policies)}.`,
  );
}

function policyWriteLine(agents: string[], policies: string[]): SummaryLine {
  const line = (allowed: boolean, text: string): SummaryLine => ({
    action: "policy-write",
    allowed,
    text,
  });
  if (!policies.length)
    return line(false, "Cannot change policies: no policy is selected.");
  const can = `Can create and change ${policiesText(policies)}`;
  if (!agents.length)
    return line(true, `${can}, when no binding holds the policy.`);
  const conditions = [
    ...(isAll(agents) ? [] : [`is on ${agentsText(agents)}`]),
    ...(isAll(policies)
      ? []
      : [`holds no policy other than ${join(policies)}`]),
  ];
  if (!conditions.length) return line(true, `${can}.`);
  return line(
    true,
    `${can}, when every binding that holds the policy ${conditions.join(" and ")}.`,
  );
}

const denied: Record<GrantAction, string> = {
  read: "Cannot read policies or bindings.",
  bind: "Cannot bind or unbind.",
  "policy-write": "Cannot change policies.",
};

export const immutableText =
  "A grant cannot be changed after approval. To change it, revoke this key and approve a new key.";

// summarizeGrant states, for each action, whether the key can do it and where.
// A choice the server refuses states no action as allowed.
export function summarizeGrant(choice: GrantChoice): GrantSummary {
  const agents = unique(choice.agents);
  const policies = unique(choice.policies);
  const refusals: string[] = [];
  if (!choice.actions.length)
    refusals.push("Approval is refused: select at least one action.");
  for (const [what, names] of [
    ["agents", agents],
    ["policies", policies],
  ] as const) {
    if (names.includes(allNames) && names.length > 1)
      refusals.push(
        `Approval is refused: the ${what} list holds * and names. Use * alone, or names alone.`,
      );
  }
  const lines = grantActions.map((action): SummaryLine => {
    if (refusals.length || !choice.actions.includes(action))
      return { action, allowed: false, text: denied[action] };
    if (action === "read") return readLine(agents, policies);
    if (action === "bind") return bindLine(agents, policies);
    return policyWriteLine(agents, policies);
  });
  return { refusals, lines };
}
