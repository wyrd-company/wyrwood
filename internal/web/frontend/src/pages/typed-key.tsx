// ---
// relationships:
//   implements: web-interface
// ---
import { Field, Input } from "@/components/shared";
import type { BindingData } from "@/types";
import { useState } from "react";

// keyKinds are the container key kinds in precedence order.
const keyKinds: { kind: string; label: string; hint: string }[] = [
  {
    kind: "devcontainer",
    label: "Dev container",
    hint: "The local folder, then | and the configuration file when the container has one.",
  },
  {
    kind: "compose",
    label: "Compose service",
    hint: "The Compose project and service, as project/service.",
  },
  {
    kind: "name",
    label: "Container name",
    hint: "The container name. It also names the consumer directory.",
  },
];

function splitKey(encoded: string) {
  const at = encoded.indexOf(":");
  if (at < 0) return { kind: "compose", value: "" };
  return { kind: encoded.slice(0, at), value: encoded.slice(at + 1) };
}

// TypedKey is the key fieldset of a binding for a container that no agent needs
// to report: an approved agent, a key kind and value, and the directory name
// that a key other than name needs.
export function TypedKey({ data: d }: { data: BindingData }) {
  const saved = splitKey(d.Form.Key);
  const [kind, setKind] = useState(
    keyKinds.some((k) => k.kind === saved.kind) ? saved.kind : "compose",
  );
  const [value, setValue] = useState(saved.value);
  const chosen = keyKinds.find((k) => k.kind === kind) ?? keyKinds[1];
  return (
    <fieldset className="flex flex-col gap-4">
      <legend>Container key</legend>
      <input type="hidden" name="typed" value="yes" />
      <input type="hidden" name="key" value={`${kind}:${value}`} readOnly />
      <Field
        label="Agent"
        id="typed-agent"
        hint="Only approved agents are listed."
      >
        <select
          id="typed-agent"
          name="agent"
          required
          defaultValue={d.Form.Agent ?? ""}
        >
          <option value="" disabled>
            Select an agent
          </option>
          {d.AgentChoices?.map((agent) => (
            <option key={agent.Name} value={agent.Name}>
              {agent.Name}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Key kind" id="typed-kind">
        <select
          id="typed-kind"
          value={kind}
          onChange={(event) => setKind(event.target.value)}
        >
          {keyKinds.map((k) => (
            <option key={k.kind} value={k.kind}>
              {k.label} ({k.kind})
            </option>
          ))}
        </select>
      </Field>
      <Field label="Key value" id="typed-value" hint={chosen.hint}>
        <Input
          id="typed-value"
          className="mono"
          required
          maxLength={512}
          value={value}
          onChange={(event) => setValue(event.target.value)}
        />
      </Field>
      {kind === "name" ? (
        <p className="hint">
          The agent prepares the consumer directory named after the container
          now, before the container exists.
        </p>
      ) : (
        <Field
          label="Directory name"
          id="typed-directory"
          hint="The consumer directory the agent prepares now, under its consumers root. Mount it into the container. Required when no agent reports a container with this key. Letters, digits, '.', '_', and '-'; it starts with a letter or digit."
        >
          <Input
            id="typed-directory"
            name="directory"
            className="mono"
            maxLength={255}
            pattern="[A-Za-z0-9][A-Za-z0-9_.\-]*"
            defaultValue={d.Form.Directory ?? ""}
          />
        </Field>
      )}
    </fieldset>
  );
}
