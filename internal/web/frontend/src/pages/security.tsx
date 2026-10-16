// ---
// relationships:
//   implements: web-interface
// ---
import { Button, CSRF, Notice, Panel } from "@/components/shared";
import { ago, until } from "@/lib/time";
import type { SecurityData } from "@/types";
export function Security({ data: d }: { data: SecurityData }) {
  return (
    <main>
      <Notice text={d.Notice} />
      <Panel aria-labelledby="h-op">
        <h2 id="h-op">Operator</h2>
        <dl className="facts">
          <div>
            <dt>Signed in as</dt>
            <dd className="mono">{d.Email || d.Name}</dd>
          </div>
          <div>
            <dt>Admitted through group</dt>
            <dd>
              <span className="chip">{d.AdmittedGroup}</span>
            </dd>
          </div>
          <div>
            <dt>Groups allowed by the controller</dt>
            <dd>
              {d.AllowedGroups.map((group) => (
                <span className="chip" key={group}>
                  {group}{" "}
                </span>
              ))}
            </dd>
          </div>
        </dl>
        <p className="hint">
          Allowed groups are set in the controller's configuration file, not
          here. Membership is managed in {d.Provider} and checked at each
          sign-in.
        </p>
      </Panel>
      <Panel aria-labelledby="h-idp">
        <div className="section-head">
          <div>
            <h2 id="h-idp">Identity provider</h2>
            <p className="hint">
              Passkeys and account recovery are managed in {d.Provider}.
            </p>
          </div>
          <Button asChild variant="outline">
            <a href={d.Issuer} rel="noreferrer">
              Manage your account in {d.Provider}
            </a>
          </Button>
        </div>
        <dl className="facts">
          <div>
            <dt>Issuer</dt>
            <dd className="mono">{d.Issuer}</dd>
          </div>
          <div>
            <dt>Client ID</dt>
            <dd className="mono">{d.ClientID}</dd>
          </div>
          <div>
            <dt>Redirect URI</dt>
            <dd className="mono">{d.RedirectURL}</dd>
          </div>
          <div>
            <dt>Discovery</dt>
            <dd>
              {d.Reachable ? (
                <>
                  <span className="dot" />
                  Reachable · keys fetched {ago(d.Fetched)}
                </>
              ) : (
                <>
                  <span className="dot bad" />
                  Unreachable
                </>
              )}
            </dd>
          </div>
        </dl>
      </Panel>
      <Panel aria-labelledby="h-ss">
        <div className="section-head">
          <h2 id="h-ss">Sessions</h2>
          <form method="post" action="/security/sessions">
            <CSRF token={d.CSRF} />
            <Button variant="outline" type="submit">
              Sign out other sessions
            </Button>
          </form>
        </div>
        <ul className="plain">
          {d.Sessions?.map((session, index) => (
            <li key={index}>
              <strong className="font-medium">
                {session.Current ? "This browser" : "Other browser"}
              </strong>
              <span className="hint">
                signed in {ago(session.CreatedAt)} · expires{" "}
                {until(session.ExpiresAt)}
              </span>
            </li>
          ))}
        </ul>
        <p className="hint">
          Signing out ends the controller session only; your {d.Provider}{" "}
          session is the provider's.
        </p>
      </Panel>
    </main>
  );
}
