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
export function Sidebar({ data }: { data: Layout }) {
  return (
    <nav className="nav" aria-label="Primary">
      <Brand />
      <div className="nav-links">
        {[
          ["agents", "Agents"],
          ["containers", "Containers"],
          ["policies", "Policies"],
          ["keys", "OpenBao keys"],
          ["events", "Events"],
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
      </div>
      <Account data={data} />
    </nav>
  );
}
