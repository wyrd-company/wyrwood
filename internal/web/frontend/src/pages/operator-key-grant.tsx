// ---
// relationships:
//   implements: web-interface
// ---
import { useState } from "react";
import { Field, Input, Status } from "@/components/shared";
import {
  allNames,
  grantActions,
  grantNames,
  immutableText,
  summarizeGrant,
  type GrantAction,
} from "@/lib/grant-summary";

const actionText: Record<GrantAction, string> = {
  read: "Read policies and bindings",
  bind: "Create and remove bindings",
  "policy-write": "Create and change policies",
};

interface ListState {
  all: boolean;
  selected: string[];
  other: string;
}

// listNames is the list a grant stores for the state: * alone when all is
// selected, otherwise the selected names and then the names typed in. The form
// posts the same values, since disabled controls are not sent.
function listNames(state: ListState) {
  if (state.all) return [allNames];
  return [...state.selected, ...grantNames(state.other)];
}

function NameList({
  field,
  id,
  legend,
  allText,
  names,
  emptyText,
  hint,
  otherLabel,
  otherHint,
  state,
  onChange,
}: {
  field: "agents" | "policies";
  id: string;
  legend: string;
  allText: string;
  names: string[];
  emptyText: string;
  hint?: string;
  otherLabel: string;
  otherHint: string;
  state: ListState;
  onChange: (state: ListState) => void;
}) {
  return (
    <fieldset>
      <legend>{legend}</legend>
      <label className="choice">
        <input
          type="checkbox"
          name={field}
          value={allNames}
          checked={state.all}
          onChange={(event) =>
            onChange({ ...state, all: event.target.checked })
          }
        />
        <span>{allText}</span>
      </label>
      {names.map((name) => (
        <label className="choice" key={name}>
          <input
            type="checkbox"
            name={field}
            value={name}
            disabled={state.all}
            checked={state.selected.includes(name)}
            onChange={(event) =>
              onChange({
                ...state,
                selected: event.target.checked
                  ? names.filter(
                      (item) => item === name || state.selected.includes(item),
                    )
                  : state.selected.filter((item) => item !== name),
              })
            }
          />
          <span>{name}</span>
        </label>
      ))}
      {!names.length && <p className="hint">{emptyText}</p>}
      {hint && <p className="hint">{hint}</p>}
      <Field label={otherLabel} id={`${field}-other-${id}`} hint={otherHint}>
        <Input
          id={`${field}-other-${id}`}
          name={field}
          type="text"
          disabled={state.all}
          value={state.other}
          onChange={(event) =>
            onChange({ ...state, other: event.target.value })
          }
        />
      </Field>
    </fieldset>
  );
}

function GrantSummaryView({
  id,
  agents,
  policies,
  actions,
}: {
  id: string;
  agents: string[];
  policies: string[];
  actions: string[];
}) {
  const summary = summarizeGrant({ agents, policies, actions });
  return (
    <section
      className="grant-summary"
      aria-labelledby={`grant-summary-${id}`}
      aria-live="polite"
    >
      <h3 id={`grant-summary-${id}`}>What this key can do</h3>
      <ul>
        {summary.refusals.map((text) => (
          <li key={text}>
            <span aria-hidden="true">
              <Status kind="denied">Refused</Status>
            </span>{" "}
            <span className="grant-line">{text}</span>
          </li>
        ))}
        {summary.lines.map((line) => (
          <li key={line.action}>
            {/* The sentence states the answer; the badge only repeats it. */}
            <span aria-hidden="true">
              <Status kind={line.allowed ? "good" : "neutral"}>
                {line.allowed ? "Allowed" : "Denied"}
              </Status>
            </span>{" "}
            <span className="grant-line">{line.text}</span>
          </li>
        ))}
      </ul>
      <p className="hint">{immutableText}</p>
    </section>
  );
}

// GrantChoices are the agents, policies, and actions of the grant a pending key
// is approved with, and a summary of what that grant allows.
export function GrantChoices({
  id,
  agents,
  policies,
}: {
  id: string;
  agents: string[];
  policies: string[];
}) {
  const empty: ListState = { all: false, selected: [], other: "" };
  const [agentState, setAgentState] = useState(empty);
  const [policyState, setPolicyState] = useState(empty);
  const [actions, setActions] = useState<string[]>(["read"]);
  return (
    <div className="grant-choices">
      <NameList
        field="agents"
        id={id}
        legend="Agents"
        allText="All agents, including agents approved later"
        names={agents}
        emptyText="No agent is approved yet."
        otherLabel="Other agent names"
        otherHint="Names separated by commas, for agents that are not approved yet."
        state={agentState}
        onChange={setAgentState}
      />
      <NameList
        field="policies"
        id={id}
        legend="Policies"
        allText="All policies, including policies created later"
        names={policies}
        emptyText="No policy exists yet."
        otherLabel="Other policy names"
        hint="This key cannot read or touch a binding that holds a policy outside this list, and cannot change a policy that a binding outside its grant holds."
        otherHint="Names separated by commas, for policies that do not exist yet, such as a policy this key will create."
        state={policyState}
        onChange={setPolicyState}
      />
      <fieldset>
        <legend>Actions</legend>
        {grantActions.map((value) => (
          <label key={value} className="choice">
            <input
              type="checkbox"
              name="actions"
              value={value}
              checked={actions.includes(value)}
              onChange={(event) =>
                setActions(
                  grantActions.filter((item) =>
                    item === value
                      ? event.target.checked
                      : actions.includes(item),
                  ),
                )
              }
            />
            <span>{actionText[value]}</span>
          </label>
        ))}
      </fieldset>
      <GrantSummaryView
        id={id}
        agents={listNames(agentState)}
        policies={listNames(policyState)}
        actions={actions}
      />
    </div>
  );
}
