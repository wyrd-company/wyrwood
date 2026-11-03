// ---
// relationships:
//   implements: web-interface
// ---
import { Field, Input, Status } from "@/components/shared";
import type { BindingData } from "@/types";
import { useState, type ReactNode } from "react";

export function BindingHeading({
  data: d,
  actions,
}: {
  data: BindingData;
  actions?: ReactNode;
}) {
  const r = d.Row;
  return (
    <div className="screen-heading">
      <div>
        <h2 id="h-container">{r.Name}</h2>
        <span className="hint">
          on {r.Agent}
          {d.Reported && (
            <>
              {" "}
              · <span className="mono">{r.Image}</span> · {r.State}
            </>
          )}
        </span>
      </div>
      <div className="screen-heading-end">
        <Status kind={r.BadgeClass}>{r.Badge}</Status>
        {actions}
      </div>
    </div>
  );
}

export function KeyChoice({ data: d }: { data: BindingData }) {
  return (
    <fieldset>
      <legend>Bind by key</legend>
      {d.Row.Candidates?.map((candidate) => (
        <label className="choice" key={candidate.Encoded}>
          <input
            type="radio"
            name="key"
            value={candidate.Encoded}
            defaultChecked={candidate.Encoded === d.Form.Key}
          />
          <span>
            {candidate.Kind} · {candidate.Note}
            <br />
            <span className="mono">{candidate.Value}</span>
          </span>
        </label>
      ))}
    </fieldset>
  );
}

function ValueField({
  name,
  saved,
  hint,
  required = false,
}: {
  name: string;
  saved?: string;
  hint?: string;
  required?: boolean;
}) {
  const id = `binding-value-${name}`;
  return (
    <Field label={name} id={id} hint={hint}>
      <Input
        id={id}
        name={`value.${name}`}
        required={required}
        maxLength={128}
        pattern="[A-Za-z0-9_\-]+"
        defaultValue={saved ?? ""}
      />
    </Field>
  );
}

export function PolicyChoices({ data: d }: { data: BindingData }) {
  const [selected, setSelected] = useState(
    () => new Set(d.Policies?.filter((p) => p.Selected).map((p) => p.Name)),
  );
  const valueNames = [
    ...new Set(
      d.Policies?.filter((p) => selected.has(p.Name)).flatMap(
        (p) => p.Values ?? [],
      ),
    ),
  ].sort();
  // A saved value that no selected policy uses stays visible, so that saving the
  // form keeps it and the operator can clear it.
  const savedValues = d.Form.Settings?.values ?? {};
  const unusedNames = Object.keys(savedValues)
    .filter((name) => !valueNames.includes(name))
    .sort();
  return (
    <>
      <fieldset>
        <legend>Policies</legend>
        {d.Policies?.map((p) => (
          <label className="choice" key={p.Name}>
            <input
              type="checkbox"
              name="policies"
              value={p.Name}
              defaultChecked={p.Selected}
              onChange={(event) => {
                const next = new Set(selected);
                if (event.target.checked) next.add(p.Name);
                else next.delete(p.Name);
                setSelected(next);
              }}
            />
            <span>{p.Name}</span>
          </label>
        ))}
      </fieldset>
      <p className="hint">
        Select one or more policies. Conflicting mount or environment
        requirements are rejected. Agent token renewal is enabled when any
        selected policy enables it. Binding tokens have no default policy.
      </p>
      {valueNames.length + unusedNames.length > 0 && (
        <fieldset>
          <legend>Values for this binding</legend>
          {valueNames.map((name) => (
            <ValueField
              name={name}
              saved={savedValues[name]}
              key={name}
              required
            />
          ))}
          {unusedNames.map((name) => (
            <ValueField
              name={name}
              saved={savedValues[name]}
              key={name}
              hint="No selected policy uses this value now. Clear it to remove it."
            />
          ))}
          <p className="hint">
            The selected policies use these values in their paths. Use letters,
            digits, underscores, and hyphens. Values are not secret.
          </p>
        </fieldset>
      )}
    </>
  );
}

export function BindingStatus({ data: d }: { data: BindingData }) {
  const r = d.Row;
  return (
    <>
      <div className="binding-summary">
        <dl className="facts">
          <div>
            <dt>Policies</dt>
            <dd className="mono">{r.Policies?.join(", ")}</dd>
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
        {d.Reported && (
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
        )}
      </div>
      <p className="hint">
        {r.Applied
          ? "AppRole assignment applied"
          : "Token transition pending; fresh issuance is blocked"}
      </p>
    </>
  );
}
