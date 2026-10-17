// ---
// relationships:
//   implements: composable-policy-bindings
// ---
import { Field, Input } from "@/components/shared";
import type { BindingSettings as Settings } from "@/types";

export function BindingSettings({ settings }: { settings?: Settings }) {
  return (
    <fieldset className="flex flex-col gap-4">
      <legend>Binding settings</legend>
      <Field
        label="Token time-to-live"
        id="binding-ttl"
        hint="Minutes or hours. Applies only to this binding."
      >
        <Input
          id="binding-ttl"
          name="token-ttl"
          defaultValue={settings?.["token-ttl"] || "1h"}
          required
        />
      </Field>
      <Field
        label="Token maximum lifetime"
        id="binding-max-ttl"
        hint="At least the TTL. After this the agent needs a fresh controller credential."
      >
        <Input
          id="binding-max-ttl"
          name="token-max-ttl"
          defaultValue={settings?.["token-max-ttl"] || "8h"}
          required
        />
      </Field>
      <Field
        label="Access group (numeric)"
        id="binding-group"
        hint="The agent and container processes must belong to this host group. Restart the agent after changing host membership. Group members can use the binding’s sockets."
      >
        <Input
          id="binding-group"
          name="access-group"
          inputMode="numeric"
          defaultValue={settings?.["access-group"] ?? ""}
        />
      </Field>
      {settings?.["access-group"] == null && (
        <p className="caution">
          No access group: directory 0700 and sockets 0600. Non-root containers
          running as another UID need an access group.
        </p>
      )}
      <Field label="Enforcement" id="binding-enforcement">
        <select
          id="binding-enforcement"
          name="enforcement"
          defaultValue={settings?.enforcement || "report"}
        >
          <option value="report">Report conformance</option>
          <option value="recreate">
            Recreate on first bind, if the host allows it
          </option>
        </select>
      </Field>
      <p className="hint">
        Recreate discards the writable layer. Later binding edits report drift;
        use Request recreate deliberately.
      </p>
      <label className="choice">
        <input type="checkbox" name="understood" value="yes" />
        <span>
          I understand the writable layer is discarded if I select recreate for
          a new binding.
        </span>
      </label>
    </fieldset>
  );
}
