// ---
// relationships:
//   implements: web-interface
// ---
import type { ComponentProps, ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";

export { Button, Input, Textarea };
export function CSRF({ token }: { token: string }) {
  return <input type="hidden" name="csrf" value={token} />;
}
export function Notice({ text }: { text: string }) {
  return text ? (
    <p className="notice" role="status">
      {text}
    </p>
  ) : null;
}
export function Panel({ className = "", ...props }: ComponentProps<"section">) {
  return (
    <Card asChild className={`card ${className}`}>
      <section {...props} />
    </Card>
  );
}
export function Status({
  kind,
  children,
}: {
  kind: string;
  children: ReactNode;
}) {
  return (
    <Badge variant="outline" className={`badge ${kind}`}>
      {children}
    </Badge>
  );
}
export function Table({
  columns,
  children,
  empty,
  count,
}: {
  columns: string[];
  children: ReactNode;
  empty: string;
  count: number;
}) {
  return (
    <div className="table-box">
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column} scope="col">
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {count ? (
            children
          ) : (
            <tr>
              <td colSpan={columns.length} className="hint">
                {empty}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
export function Field({
  label,
  id,
  hint,
  children,
}: {
  label: string;
  id: string;
  hint?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {children}
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}
export function policyURL(name: string) {
  return `/policies/edit?name=${encodeURIComponent(name)}`;
}
export function containerURL(agent: string, id?: string) {
  return `/containers?${new URLSearchParams({ agent, ...(id ? { container: id } : {}) })}`;
}
export function PolicyLinks({ names }: { names: string[] | null }) {
  return names?.length ? (
    names.map((name, index) => (
      <span key={name}>
        {index > 0 && ", "}
        <a href={policyURL(name)}>{name}</a>
      </span>
    ))
  ) : (
    <span className="hint">No policy</span>
  );
}
