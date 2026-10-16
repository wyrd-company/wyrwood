// ---
// relationships:
//   implements: web-interface
// ---
import {
  Button,
  CSRF,
  Field,
  Input,
  Notice,
  Panel,
  Textarea,
} from "@/components/shared";
import { OpenBaoLink } from "@/components/openbao-link";
import type { PolicyData } from "@/types";
export function PolicyEditor({ data: d }: { data: PolicyData }) {
  return (
    <main>
      <Notice text={d.Notice} />
      {d.Problem && (
        <p className="problem" role="alert">
          {d.Problem}
        </p>
      )}
      <form method="post" action="/policies" className="flex flex-col gap-6">
        <CSRF token={d.CSRF} />
        {d.New ? (
          <input type="hidden" name="new" value="yes" />
        ) : (
          <input type="hidden" name="name" value={d.Name} />
        )}
        <div className="section-head">
          <div>
            <h2 className="mono text-xl">{d.New ? "New policy" : d.Name}</h2>
            {!d.New && (
              <span className="sub">
                Revision {d.Revision} · bound to {d.Bindings} container
                {d.Bindings !== 1 && "s"} on {d.Agents} agent
                {d.Agents !== 1 && "s"}
              </span>
            )}
          </div>
          <Button type="submit" className="primary">
            Save and validate
          </Button>
        </div>
        {d.New && (
          <Panel>
            <Field
              label="Name"
              id="name"
              hint={
                <>
                  Lower-kebab-case. Written to OpenBao as{" "}
                  <code>wyrwood-&lt;name&gt;</code>.
                </>
              }
            >
              <Input
                id="name"
                name="name"
                type="text"
                defaultValue={d.Name}
                required
                pattern="[a-z][a-z0-9]*(-[a-z0-9]+)*"
                maxLength={64}
              />
            </Field>
          </Panel>
        )}
        <div className="split p-0">
          <div className="main-column flex flex-col gap-6">
            <OpenBaoPolicy data={d} />
            <SSHIdentities data={d} />
          </div>
          <ContainerContract data={d} />
        </div>
      </form>
    </main>
  );
}
function OpenBaoPolicy({ data: d }: { data: PolicyData }) {
  return (
    <Panel aria-labelledby="h-hcl">
      <div className="section-head">
        <h2 id="h-hcl">OpenBao policy</h2>
        <OpenBaoLink href={d.OpenBaoURL} className="sub">
          Manage secrets in the OpenBao UI
        </OpenBaoLink>
        {!d.New && (
          <span className="sub">
            Written to <code>{d.PolicyPath}</code> and parsed by OpenBao on
            save.
          </span>
        )}
      </div>
      <div className="field">
        <label htmlFor="hcl" className="visually-hidden">
          OpenBao policy HCL
        </label>
        <Textarea
          id="hcl"
          name="hcl"
          className="hcl"
          spellCheck={false}
          defaultValue={d.HCL}
        />
      </div>
      <div className="max-w-60">
        <Field
          label="Token time-to-live"
          id="ttl"
          hint="Minutes or hours, such as 30m or 1h. Applied to each binding's AppRole."
        >
          <Input
            id="ttl"
            name="token-ttl"
            type="text"
            defaultValue={d.TokenTTL}
          />
        </Field>
      </div>
      <div className="max-w-60">
        <Field
          label="Token maximum lifetime"
          id="max-ttl"
          hint="At least the time-to-live, such as 8h. After it the agent needs a fresh credential from the controller."
        >
          <Input
            id="max-ttl"
            name="token-max-ttl"
            type="text"
            defaultValue={d.TokenMaxTTL}
          />
        </Field>
      </div>
    </Panel>
  );
}
function SSHIdentities({ data: d }: { data: PolicyData }) {
  return (
    <Panel aria-labelledby="h-ssh">
      <div className="section-head">
        <h2 id="h-ssh">SSH agent identities</h2>
        <span className="sub">
          What <code>ssh-agent.sock</code> offers. Each must also be allowed by
          the HCL above.
        </span>
      </div>
      <div className="grid-2">
        <Field
          label="Transit keys"
          id="transit-keys"
          hint="One key name per line."
        >
          <Textarea
            id="transit-keys"
            name="transit-keys"
            rows={4}
            defaultValue={d.TransitKeys}
          />
        </Field>
        <Field
          label="SSH-engine roles"
          id="ca-roles"
          hint="One role name per line."
        >
          <Textarea
            id="ca-roles"
            name="ca-roles"
            rows={4}
            defaultValue={d.CARoles}
          />
        </Field>
      </div>
      <div className="grid-2">
        <Field
          label="Not-forwardable Transit keys"
          id="not-forwardable-transit-keys"
          hint="One offered key name per line. Refuse signing after a verified forwarding bind."
        >
          <Textarea
            id="not-forwardable-transit-keys"
            name="not-forwardable-transit-keys"
            rows={2}
            defaultValue={d.NotForwardableTransitKeys}
          />
        </Field>
        <Field
          label="Not-forwardable SSH-engine roles"
          id="not-forwardable-ca-roles"
          hint="One offered role name per line. Other identities remain forwardable."
        >
          <Textarea
            id="not-forwardable-ca-roles"
            name="not-forwardable-ca-roles"
            rows={2}
            defaultValue={d.NotForwardableCARoles}
          />
        </Field>
      </div>
      {d.Unpermitted?.map((name) => (
        <p className="caution" key={name}>
          {name} is not allowed by the HCL; using it will be denied.
        </p>
      ))}
    </Panel>
  );
}
function ContainerContract({ data: d }: { data: PolicyData }) {
  return (
    <Panel aria-labelledby="h-con" className="flex-[1_1_340px]">
      <div>
        <h2 id="h-con">Container contract</h2>
        <span className="hint">
          What a bound container must have to reach its sockets.
        </span>
      </div>
      <Field label="Mount target" id="mount-target">
        <Input
          id="mount-target"
          name="mount-target"
          type="text"
          defaultValue={d.MountTarget}
        />
      </Field>
      <Field
        label="Environment"
        id="env"
        hint={
          <>
            One NAME=value per line. <code>{"{mount-target}"}</code> is replaced
            by the mount target.
          </>
        }
      >
        <Textarea id="env" name="env" rows={4} defaultValue={d.Env} />
      </Field>
      <Field
        label="Access group (numeric)"
        id="access-group"
        hint="Use a host group available to the container processes. The agent user must belong to it; restart the agent after adding membership. Host group members can use these sockets with the binding’s permissions."
      >
        <Input
          id="access-group"
          name="access-group"
          type="text"
          inputMode="numeric"
          defaultValue={d.AccessGroup}
        />
      </Field>
      {!d.AccessGroup && (
        <p className="caution" role="status">
          No access group: the directory is 0700 and sockets are 0600, owned by
          the agent user. An access group is effectively required for non-root
          containers running as another UID.
        </p>
      )}
      <fieldset>
        <legend>Enforcement</legend>
        <label className="choice">
          <input
            type="radio"
            name="enforcement"
            value="report"
            defaultChecked={d.Enforcement !== "recreate"}
          />
          <span>
            <strong>Report</strong>
            <br />
            <span className="hint">
              Check and show what is missing. Never touch the container.
            </span>
          </span>
        </label>
        <label className="choice">
          <input
            type="radio"
            name="enforcement"
            value="recreate"
            defaultChecked={d.Enforcement === "recreate"}
          />
          <span>
            <strong>Recreate at bind time</strong>
            <br />
            <span className="hint">
              Recreate once when first bound, on hosts that allow it. Discards
              the writable layer.
            </span>
          </span>
        </label>
      </fieldset>
    </Panel>
  );
}
