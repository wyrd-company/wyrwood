// ---
// relationships:
//   implements: composable-policy-bindings
// ---
import type { EffectivePolicy as Effective } from "@/types";
import { policyURL } from "@/components/shared";

export function EffectivePolicy({
  effective,
  warnings,
}: {
  effective: Effective;
  warnings?: string[] | null;
}) {
  return (
    <section aria-label="Effective policy" className="flex flex-col gap-3">
      <h3>Effective policy</h3>
      <p className="hint">
        OpenBao combines these named policies. Deny and path priority rules
        still apply. Combined HCL shows the compiled policy with managed
        lifecycle grants. Each policy document retains its authored source HCL.
      </p>
      <ul>
        {effective.sources.map((source) => (
          <li key={source.name}>
            <a href={policyURL(source.name)}>{source.name}</a> · revision{" "}
            {source.revision}
          </li>
        ))}
      </ul>
      {warnings?.map((warning) => (
        <p className="caution" role="status" key={warning}>
          {warning}
        </p>
      ))}
      <details open>
        <summary>Combined HCL</summary>
        <pre className="overflow-auto whitespace-pre-wrap">
          <code>{effective.openbao.policy}</code>
        </pre>
      </details>
      <p>
        Agent token renewal:{" "}
        {effective.openbao["agent-token-renewal"] ? "enabled" : "disabled"}.
        Lookup uses read; agent retirement uses update. Container renewal stays
        local and container revocation is blocked.
      </p>
      <dl className="facts">
        <div>
          <dt>Transit keys</dt>
          <dd>{effective.ssh?.["transit-keys"]?.join(", ") || "none"}</dd>
        </div>
        <div>
          <dt>SSH roles</dt>
          <dd>{effective.ssh?.["ca-roles"]?.join(", ") || "none"}</dd>
        </div>
        <div>
          <dt>Not-forwardable keys</dt>
          <dd>
            {effective.ssh?.["not-forwardable"]?.["transit-keys"]?.join(", ") ||
              "none"}
          </dd>
        </div>
        <div>
          <dt>Not-forwardable roles</dt>
          <dd>
            {effective.ssh?.["not-forwardable"]?.["ca-roles"]?.join(", ") ||
              "none"}
          </dd>
        </div>
      </dl>
      <details>
        <summary>Combined contract and binding settings</summary>
        <pre className="overflow-auto whitespace-pre-wrap">
          {JSON.stringify(
            { contract: effective.contract, settings: effective.settings },
            null,
            2,
          )}
        </pre>
      </details>
    </section>
  );
}
