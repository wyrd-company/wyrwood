// ---
// relationships:
//   implements: web-interface
// ---
import type { Layout } from "@/types";
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
          ["security", "Security"],
        ].map(([path, label]) => (
          <a
            key={path}
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
    </nav>
  );
}
