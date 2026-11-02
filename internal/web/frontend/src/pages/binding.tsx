// ---
// relationships:
//   implements: web-interface
// ---
import { Button, Notice, Status } from "@/components/shared";
import type { BindingData } from "@/types";
import { BindingForm } from "./binding-form";
import { ContainerSetup } from "./container-setup";
import { EffectivePolicy } from "./effective-policy";

export function Binding({ data: d }: { data: BindingData }) {
  const r = d.Row;
  return (
    <main className="wide">
      <a href={d.Back}>Back to containers</a>
      <Notice text={d.Notice} />
      {d.Problem && (
        <p className="problem" role="alert">
          {d.Problem} {r.Bound && <a href={d.Screen}>Reload saved values</a>}
        </p>
      )}
      <section className="card" aria-labelledby="h-container">
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
          <Status kind={r.BadgeClass}>{r.Badge}</Status>
        </div>
        {!d.Reported && (
          <p className="caution">
            The agent does not report a container for this binding now. The
            contract check and setup examples return when it does.
          </p>
        )}
        {r.Bound ? (
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
                        <Status kind={`mark ${check.Status}`}>
                          {check.Mark}
                        </Status>
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
            {d.Reported && <ContainerSetup setup={r.Setup} />}
            <BindingForm data={d} />
            {r.Effective?.sources?.length > 0 && (
              <EffectivePolicy effective={r.Effective} warnings={r.Warnings} />
            )}
            <div className="actions">
              <Button asChild variant="outline">
                <a href={d.Recreate}>Request recreate</a>
              </Button>
              <Button asChild variant="outline" className="danger">
                <a href={d.Unbind}>Unbind and revoke AppRole</a>
              </Button>
            </div>
          </>
        ) : d.Policies?.length ? (
          <BindingForm data={d} />
        ) : (
          <p className="hint">
            Create a policy before binding.{" "}
            <a href="/policies/edit">New policy</a>
          </p>
        )}
      </section>
    </main>
  );
}
