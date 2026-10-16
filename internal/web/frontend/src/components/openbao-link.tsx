// ---
// relationships:
//   implements: web-interface
// ---
import type { ReactNode } from "react";

// OpenBaoLink opens the server-computed OpenBao UI address in a new tab. The
// OpenBao UI authenticates the person itself; no Wyrwood credential is sent.
export function OpenBaoLink({
  href,
  className,
  children = "OpenBao UI",
}: {
  href: string;
  className?: string;
  children?: ReactNode;
}) {
  return href ? (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className={className}
    >
      {children} <span className="visually-hidden">(opens in a new tab)</span>
    </a>
  ) : null;
}
