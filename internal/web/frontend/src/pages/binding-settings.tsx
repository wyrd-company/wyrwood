// ---
// relationships:
//   implements: composable-policy-bindings
// ---
import { useState } from "react";
import { Field, Input } from "@/components/shared";
import { DurationPicker } from "@/components/duration-picker";
import type { AssignableGroups, BindingSettings as Settings } from "@/types";

export function BindingSettings({
  settings,
  groups,
  connected,
}: {
  settings?: Settings;
  groups?: AssignableGroups | null;
  connected?: boolean;
}) {
  const [value, setValue] = useState(String(settings?.["access-group"] ?? ""));
  const [custom, setCustom] = useState(false);
  const known = connected && groups != null;
  const invalid =
    value !== "" &&
    known &&
    !groups.any &&
    !groups.groups.some((g) => String(g.gid) === value);
  const listed = groups?.groups.some((g) => String(g.gid) === value);

  return (
    <fieldset className="flex flex-col gap-4">
      <legend>Binding settings</legend>
      <Field
        label="Token time-to-live"
        id="binding-ttl"
        hint="Minutes or hours. Applies only to this binding."
      >
        <DurationPicker
          id="binding-ttl"
          name="token-ttl"
          value={settings?.["token-ttl"] || "1h"}
          binding
        />
      </Field>
      <Field
        label="Token maximum lifetime"
        id="binding-max-ttl"
        hint="At least the TTL. After this the agent needs a fresh controller credential."
      >
        <DurationPicker
          id="binding-max-ttl"
          name="token-max-ttl"
          value={settings?.["token-max-ttl"] || "8h"}
          binding
        />
      </Field>
      <Field
        label="Access group"
        id="binding-group"
        hint="Group members can use this binding’s sockets. Numeric GIDs are authoritative; host names are labels."
      >
        <select
          id="binding-group"
          name={custom ? undefined : "access-group"}
          value={custom ? "custom" : value}
          onChange={(e) => {
            if (e.target.value === "custom") {
              setCustom(true);
              setValue("");
            } else {
              setCustom(false);
              setValue(e.target.value);
            }
          }}
        >
          <option value="">Owner-only (omit access group)</option>
          {known &&
            groups.groups.map((g) => (
              <option key={g.gid} value={g.gid}>
                {g.name ? `${g.name} (${g.gid})` : String(g.gid)}
              </option>
            ))}
          {!custom && value !== "" && (!known || !listed) && (
            <option value={value}>
              {value} (
              {invalid
                ? "cannot assign"
                : known && groups.any
                  ? "assignable"
                  : "unverified"}
              )
            </option>
          )}
          {known && groups.any && (
            <option value="custom">
              Another numeric GID (privileged agent)
            </option>
          )}
        </select>
        {custom && (
          <Input
            aria-label="Numeric access group"
            name="access-group"
            inputMode="numeric"
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
        )}
      </Field>
      {!known && (
        <p className="caution">
          Group capabilities are unavailable or stale:{" "}
          {connected
            ? "this agent has not reported its process groups; upgrade or reconnect it"
            : "the agent is offline"}
          . Existing selections are unverified. Reconnect and reload before
          choosing a group.
        </p>
      )}
      {invalid && (
        <p className="caution" role="alert">
          The agent cannot assign group {value}. Select a reported group or
          owner-only access. The saved selection has not been changed.
        </p>
      )}
      {value === "" && (
        <p className="caution">
          No access group: directory 0700 and sockets 0600. Non-root containers
          running as another UID need an access group.
        </p>
      )}
      <p className="hint">
        To make another group available, add the host agent user to that group
        and restart the agent, then reload. Account membership changes do not
        update the running process’s groups.
      </p>
      <p className="hint">
        The application inside the container must retain the selected numeric
        group as its primary or supplementary group. Its primary GID need not
        match. An entrypoint such as s6-setuidgid can rebuild membership from
        the container account database and discard Compose group_add groups. The
        host choice does not prove application access.
      </p>
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
