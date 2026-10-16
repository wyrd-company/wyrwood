// ---
// relationships:
//   implements: web-interface
// ---
import { Brand } from "@/components/sidebar";
import { Button } from "@/components/shared";
import type { SignInData } from "@/types";
export function SignIn({ data: d }: { data: SignInData }) {
  return (
    <div className="signin">
      <aside>
        <Brand />
        <div>
          <p className="lede">
            One place to decide what every container may reach.
          </p>
          <p>
            Policies, bindings and OpenBao keys for every host whose agent
            reports to this controller.
          </p>
        </div>
        <dl>
          <dt>Version</dt>
          <dd>{d.Version}</dd>
        </dl>
      </aside>
      <main>
        <div className="panel">
          {d.Problem === "denied" && (
            <div className="problem" role="alert">
              <h1>This account can't operate Wyrwood</h1>
              <p>
                {d.Provider} signed you in
                {d.Account && (
                  <>
                    {" "}
                    as <span className="mono">{d.Account}</span>
                  </>
                )}
                , but the account isn't in a group this controller allows. Ask
                an administrator to add you in {d.Provider}.
              </p>
            </div>
          )}
          {d.Problem === "unavailable" && (
            <div className="caution" role="alert">
              <h1>Can't reach {d.Provider}</h1>
              <p>
                The controller couldn't load the provider's discovery document.
                Agents keep serving containers meanwhile.
              </p>
            </div>
          )}
          {d.Problem === "invalid" && (
            <div className="problem" role="alert">
              <h1>Sign-in didn't complete</h1>
              <p>
                The response from {d.Provider} could not be verified or has
                expired. Start again.
              </p>
            </div>
          )}
          {d.Problem === "expired" && (
            <p className="caution" role="status">
              Your session ended. Sign in again.
            </p>
          )}
          {(!d.Problem || d.Problem === "expired") && (
            <div>
              <h1>Sign in</h1>
              <p className="hint text-base">
                Operator access is through your identity provider.
              </p>
            </div>
          )}
          <form method="post" action="/auth/start">
            <Button className="primary" type="submit">
              {d.Problem === "unavailable"
                ? "Try again"
                : d.Problem === "denied"
                  ? "Sign in with a different account"
                  : `Continue with ${d.Provider}`}
            </Button>
          </form>
          <p className="hint">
            You'll be sent to <span className="mono">{d.IssuerHost}</span> to
            sign in, then returned here.
          </p>
          <p className="foot">
            Wyrwood never sees your passkey or password; it receives only a
            signed ID token from the provider.
          </p>
        </div>
      </main>
    </div>
  );
}
