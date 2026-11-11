// ---
// relationships:
//   implements: web-interface
// ---
import { Fragment, useId, useRef, useState } from "react";
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
// Above the page, the menu control shows and hides the panel. Beside the page,
// the control is not displayed and the panel always shows; style.css owns both.
export function Sidebar({ data }: { data: Layout }) {
  const panel = useId();
  const [open, setOpen] = useState(false);
  const toggle = useRef<HTMLButtonElement>(null);
  return (
    <nav
      className="nav"
      aria-label="Primary"
      onKeyDown={(event) => {
        // The account menu renders outside the navigation and closes itself.
        if (
          event.key !== "Escape" ||
          !open ||
          !event.currentTarget.contains(event.target as Node)
        )
          return;
        setOpen(false);
        toggle.current?.focus();
      }}
    >
      <div className="nav-bar">
        <Brand />
        <button
          ref={toggle}
          type="button"
          className="nav-toggle"
          aria-expanded={open}
          aria-controls={panel}
          onClick={() => setOpen(!open)}
        >
          <svg
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            aria-hidden="true"
          >
            {open ? (
              <path d="M6 6l12 12M18 6 6 18" />
            ) : (
              <path d="M4 7h16M4 12h16M4 17h16" />
            )}
          </svg>
          Menu
        </button>
      </div>
      <div id={panel} className="nav-panel" data-open={open || undefined}>
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
                  <span
                    className="count"
                    aria-label={`${data.Pending} pending`}
                  >
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
      </div>
    </nav>
  );
}
