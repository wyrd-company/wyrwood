// ---
// relationships:
//   implements: web-interface
// ---
import { Button, CSRF, Field, Input, Notice, Panel } from "@/components/shared";
import { OpenBaoLink } from "@/components/openbao-link";
import { HCLEditor } from "@/components/hcl-editor";
import { IdentityPicker } from "@/components/identity-picker";
import { EnvironmentEditor } from "@/components/environment-editor";
import { useRef, useState } from "react";
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
  const [warnings, setWarnings] = useState(d.Warnings ?? []);
  const latestCheck = useRef(0);
  const [renewal, setRenewal] = useState(d.AgentTokenRenewal);

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
      <fieldset className="flex flex-col gap-3" aria-label="Token lifecycle">
        <legend>Token lifecycle</legend>
        <input
          type="hidden"
          name="agent-token-renewal"
          value={String(renewal)}
        />
        <label className="editor-choice">
          <input
            type="checkbox"
            checked={renewal}
            onChange={(event) => setRenewal(event.target.checked)}
          />
          Agent token renewal
        </label>
        <p className="hint">
          The agent renews the real OpenBao token when any selected policy
          enables renewal. When disabled in all selected policies, the token
          expires at its TTL; the agent then requests a replacement credential.
          Without the controller, access stops at expiry.
        </p>
        <p className="hint">
          Container lookup returns real token metadata without its value.
          Container renewal stays local. The agent revokes the real token on
          retirement; container revoke requests are blocked.
        </p>
        <pre
          className="overflow-auto whitespace-pre-wrap"
          aria-label="Lifecycle grants"
        >
          <code>{`path "auth/token/lookup-self" { capabilities = ["read"] }\n${renewal ? 'path "auth/token/renew-self" { capabilities = ["update"] }\n' : ""}path "auth/token/revoke-self" { capabilities = ["update"] }\n`}</code>
        </pre>
      </fieldset>
      <HCLEditor
        value={d.HCL}
        mounts={d.KVMounts || []}
        onChange={() => {
          ++latestCheck.current;
          setWarnings([]);
        }}
        onCheck={checkHCL}
      />
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
      <p className="hint">
        Select the identities offered by the agent. Not-forwardable identities
        refuse signing after a verified forwarding bind. Each selected identity
        must also be permitted by HCL.
      </p>
      {d.IdentityProblems?.map((problem) => (
        <p className="caution" role="alert" key={problem}>
          {problem}
        </p>
      ))}
      <IdentityPicker
        title="Transit keys"
        name="transit-keys"
        available={d.AvailableTransitKeys || []}
        selected={d.TransitKeys}
        restricted={d.NotForwardableTransitKeys}
      />
      <IdentityPicker
        title="SSH-engine roles"
        name="ca-roles"
        available={d.AvailableCARoles || []}
        selected={d.CARoles}
        restricted={d.NotForwardableCARoles}
      />
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
      <EnvironmentEditor value={d.Env} />
    </Panel>
  );
}
