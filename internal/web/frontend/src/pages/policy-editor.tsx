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
import { useRef, useState } from "react";
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
  const [warnings, setWarnings] = useState(d.Warnings ?? []);
  const latestCheck = useRef(0);

  async function checkHCL(hcl: string) {
    const check = ++latestCheck.current;
    try {
      const response = await fetch("/policies/warnings", {
        method: "POST",
        body: new URLSearchParams({ csrf: d.CSRF, hcl }),
      });
      if (!response.ok) throw new Error("Warning check unavailable");
      const result: { warnings: string[] } = await response.json();
      if (check === latestCheck.current) setWarnings(result.warnings);
    } catch {
      if (check === latestCheck.current) {
        setWarnings([
          "The HCL warning check is unavailable. Saving is still allowed; OpenBao validates the HCL on save.",
        ]);
      }
    }
  }

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
          onChange={() => {
            latestCheck.current++;
            setWarnings([]);
          }}
          onBlur={(event) => void checkHCL(event.currentTarget.value)}
        />
      </div>
      <p className="hint">
        Paths are checked when you leave the HCL field. Warnings do not block
        saving.
      </p>
      <p className="hint">
        Binding tokens have no OpenBao default policy. Include lookup-self
        (read), renew-self (update), and revoke-self (update) in your HCL. TTL,
        access group, and enforcement are set on each binding.
      </p>
      {warnings.map((warning) => (
        <p className="caution" role="status" key={warning}>
          {warning}
        </p>
      ))}
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
    </Panel>
  );
}
