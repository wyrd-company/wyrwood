// ---
// relationships:
//   implements: web-interface
// ---
import { Fragment } from "react";
import { OpenBaoLink } from "@/components/openbao-link";
import type { Layout } from "@/types";
import { Account } from "./account";
export function Brand() {
  return (
    <a className="brand" href="/agents">
      <img
        className="logo"
        src="/static/emblem-dark.svg"
        width="26"
        height="26"
        alt=""
      />
      <span>Wyrwood</span>
    </a>
  );
}
// The new-issue form takes no query data, so that no site value leaves through
// this link.
const reportIssueURL = "https://github.com/wyrd-company/wyrwood/issues/new";
export function Sidebar({ data }: { data: Layout }) {
  return (
    <nav className="nav" aria-label="Primary">
      <Brand />
      <div className="nav-links">
        {[
          ["agents", "Agents"],
          ["bindings", "Bindings"],
          ["policies", "Policies"],
          ["keys", "OpenBao keys"],
          ["operator-keys", "Operator keys"],
          ["events", "Events"],
          ["settings", "Settings"],
        ].map(([path, label]) => (
          <Fragment key={path}>
            <a
              href={`/${path}`}
              aria-current={data.Current === path ? "page" : undefined}
            >
              {label}
              {path === "agents" && data.Pending > 0 && (
                <span className="count" aria-label={`${data.Pending} pending`}>
                  {data.Pending}
                </span>
              )}
              {path === "operator-keys" && !!data.PendingOperatorKeys && (
                <span
                  className="count"
                  aria-label={`${data.PendingOperatorKeys} pending`}
                >
                  {data.PendingOperatorKeys}
                </span>
              )}
            </a>
            {path === "keys" && <OpenBaoLink href={data.OpenBaoURL} />}
          </Fragment>
        ))}
      </div>
      <div className="nav-foot">
        {data.OpenBaoOK ? (
          <span>
            <span className="dot" />
            OpenBao reachable
          </span>
        ) : (
          <span>
            <span className="dot bad" />
            OpenBao unreachable · agents keep serving
          </span>
        )}
        <span className="mono">{data.Controller}</span>
        <a href={reportIssueURL} target="_blank" rel="noopener noreferrer">
          Report an issue{" "}
          <span className="visually-hidden">(opens GitHub in a new tab)</span>
        </a>
      </div>
      <Account data={data} />
    </nav>
  );
}
