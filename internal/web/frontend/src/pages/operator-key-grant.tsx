// ---
// relationships:
//   implements: web-interface
// ---
import { useState } from "react";
import {
  Button,
  CSRF,
  Field,
  Input,
  Notice,
  Panel,
  Status,
} from "@/components/shared";
import {
  allNames,
  grantActions,
  grantNames,
  summarizeGrant,
  type GrantAction,
  type GrantChoice,
} from "@/lib/grant-summary";
import type { Grant, OperatorKeyGrantData } from "@/types";

const actionText: Record<GrantAction, string> = {
  read: "Read policies and bindings",
  bind: "Create, change, and remove bindings",
  "policy-write": "Create and change policies",
};

const actionNames: Record<GrantAction, string> = {
  read: "Read",
  bind: "Bind",
  "policy-write": "Policy write",
};

interface ListState {
  all: boolean;
  selected: string[];
  other: string;
}

// listState shows a stored list: * alone selects all, a name the screen offers
// is checked, and any other name is in the text field.
function listState(names: string[] | null, offered: string[]): ListState {
  const list = names ?? [];
  if (list.length === 1 && list[0] === allNames)
    return { all: true, selected: [], other: "" };
  return {
    all: false,
    selected: offered.filter((name) => list.includes(name)),
    other: list.filter((name) => !offered.includes(name)).join(", "),
  };
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
  choice,
  refused,
}: {
  id: string;
  choice: GrantChoice;
  refused?: string;
}) {
  const summary = summarizeGrant(choice, refused);
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
    </section>
  );
}

// useGrant holds the agents, policies, and actions a form chooses, starting
// from a grant, and the grant they make.
function useGrant(start: Grant, agents: string[], policies: string[]) {
  const [agentState, setAgentState] = useState(() =>
    listState(start.agents, agents),
  );
  const [policyState, setPolicyState] = useState(() =>
    listState(start.policies, policies),
  );
  const [actions, setActions] = useState<string[]>(start.actions ?? []);
  const choice: GrantChoice = {
    agents: listNames(agentState),
    policies: listNames(policyState),
    actions,
  };
  return {
    agentState,
    setAgentState,
    policyState,
    setPolicyState,
    actions,
    setActions,
    choice,
  };
}

function ActionChoices({
  actions,
  setActions,
  labels,
}: {
  actions: string[];
  setActions: (actions: string[]) => void;
  labels: Record<GrantAction, string>;
}) {
  return grantActions.map((value) => (
    <label key={value} className="choice">
      <input
        type="checkbox"
        name="actions"
        value={value}
        checked={actions.includes(value)}
        onChange={(event) =>
          setActions(
            grantActions.filter((item) =>
              item === value ? event.target.checked : actions.includes(item),
            ),
          )
        }
      />
      <span>{labels[value]}</span>
    </label>
  ));
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
  const grant = useGrant(
    { agents: [], policies: [], actions: ["read"] },
    agents,
    policies,
  );
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
        state={grant.agentState}
        onChange={grant.setAgentState}
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
        state={grant.policyState}
        onChange={grant.setPolicyState}
      />
      <fieldset>
        <legend>Actions</legend>
        <ActionChoices
          actions={grant.actions}
          setActions={grant.setActions}
          labels={actionText}
        />
      </fieldset>
      <GrantSummaryView id={id} choice={grant.choice} />
    </div>
  );
}

// OperatorKeyGrant edits the grant of an approved key. Validate checks the
// grant without saving it; Save applies it.
export function OperatorKeyGrant({ data: d }: { data: OperatorKeyGrantData }) {
  const id = "edit";
  const agents = d.GrantAgents ?? [];
  const policies = d.GrantPolicies ?? [];
  const grant = useGrant(d.Grant, agents, policies);
  const [check, setCheck] = useState<string[] | null>(null);
  return (
    <main>
      <Notice text={d.Notice} />
      {d.Problem && (
        <p className="problem" role="alert">
          {d.Problem}
        </p>
      )}
      <a href="/operator-keys">← Operator keys</a>
      <Panel aria-labelledby="h-grant" className="flex flex-col gap-4">
        <div className="key-identity">
          <div className="flex flex-wrap items-center gap-2">
            <h2>{d.Label}</h2>
            <Status kind="good">Approved</Status>
          </div>
          <code className="break-all hint">{d.Fingerprint}</code>
        </div>
        <h2 id="h-grant">Edit grant</h2>
        <form
          method="post"
          action="/operator-keys/grant"
          className="flex flex-col gap-4"
          onChange={() => setCheck(null)}
        >
          <CSRF token={d.CSRF} />
          <input type="hidden" name="fingerprint" value={d.Fingerprint} />
          <input type="hidden" name="previous" value={d.Previous} />
          <div className="grant-grid">
            <NameList
              field="agents"
              id={id}
              legend="Agents"
              allText="All agents, including agents approved later"
              names={agents}
              emptyText="No agent is approved yet."
              otherLabel="Other agent names"
              otherHint="Comma-separated names."
              state={grant.agentState}
              onChange={grant.setAgentState}
            />
            <NameList
              field="policies"
              id={id}
              legend="Policies"
              allText="All policies, including policies created later"
              names={policies}
              emptyText="No policy exists yet."
              otherLabel="Other policy names"
              otherHint="Comma-separated names."
              state={grant.policyState}
              onChange={grant.setPolicyState}
            />
            <fieldset className="span-all">
              <legend>Actions</legend>
              <div className="grant-actions">
                <ActionChoices
                  actions={grant.actions}
                  setActions={grant.setActions}
                  labels={actionNames}
                />
              </div>
            </fieldset>
          </div>
          <GrantSummaryView
            id={id}
            choice={grant.choice}
            refused="Saving is refused"
          />
          {check?.length ? (
            <p className="problem" role="alert">
              {check.join(" ")}
            </p>
          ) : (
            check && (
              <p className="hint" role="status">
                Valid grant.
              </p>
            )
          )}
          <div className="actions">
            <Button
              type="button"
              variant="outline"
              onClick={() =>
                setCheck(summarizeGrant(grant.choice, "Not valid").refusals)
              }
            >
              Validate
            </Button>
            <Button type="submit" className="primary">
              Save
            </Button>
          </div>
        </form>
      </Panel>
    </main>
  );
}
