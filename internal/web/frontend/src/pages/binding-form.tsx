// ---
// relationships:
//   implements: web-interface
// ---
import { Button, CSRF } from "@/components/shared";
import type { BindingData, EffectivePolicy as Effective } from "@/types";
import { useRef, useState } from "react";
import { BindingSettings } from "./binding-settings";
import { EffectivePolicy } from "./effective-policy";

export function BindingForm({ data: d }: { data: BindingData }) {
  const r = d.Row;
  const [preview, setPreview] = useState<Effective | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [problem, setProblem] = useState("");
  const [busy, setBusy] = useState(false);
  const previewRequest = useRef(0);
  async function showPreview(form: HTMLFormElement) {
    const request = ++previewRequest.current;
    setBusy(true);
    setProblem("");
    setPreview(null);
    try {
      const body = new URLSearchParams();
      new FormData(form).forEach((value, key) => {
        if (typeof value === "string") body.append(key, value);
      });
      const response = await fetch("/bindings/preview", {
        method: "POST",
        body,
      });
      const result = await response.json();
      if (request !== previewRequest.current) return;
      if (!response.ok) setProblem(result.error || "Preview failed.");
      else {
        setPreview(result.effective);
        setWarnings(result.warnings || []);
      }
    } catch {
      if (request === previewRequest.current)
        setProblem("Preview could not be loaded.");
    } finally {
      if (request === previewRequest.current) setBusy(false);
    }
  }
  return (
    <form
      method="post"
      action={d.Action}
      className="flex flex-col gap-4"
      onChange={() => {
        previewRequest.current++;
        setBusy(false);
        setPreview(null);
        setProblem("");
      }}
    >
      <CSRF token={d.CSRF} />
      <input type="hidden" name="agent" value={r.Agent} />
      <input type="hidden" name="container" value={r.ID} />
      <input type="hidden" name="revision" value={d.Form.Revision || 0} />
      <div className="binding-sections">
        <div className="binding-choices">
          {!r.Bound && (
            <fieldset>
              <legend>Bind by key</legend>
              {r.Candidates?.map((candidate) => (
                <label className="choice" key={candidate.Encoded}>
                  <input
                    type="radio"
                    name="key"
                    value={candidate.Encoded}
                    defaultChecked={candidate.Encoded === d.Form.Key}
                  />
                  <span>
                    {candidate.Kind} · {candidate.Note}
                    <br />
                    <span className="mono">{candidate.Value}</span>
                  </span>
                </label>
              ))}
            </fieldset>
          )}
          <fieldset>
            <legend>Policies</legend>
            {d.Policies?.map((p) => (
              <label className="choice" key={p.Name}>
                <input
                  type="checkbox"
                  name="policies"
                  value={p.Name}
                  defaultChecked={p.Selected}
                />
                <span>{p.Name}</span>
              </label>
            ))}
          </fieldset>
          <p className="hint">
            Select one or more policies. Conflicting mount or environment
            requirements are rejected. Agent token renewal is enabled when any
            selected policy enables it. Binding tokens have no default policy.
          </p>
        </div>
        <BindingSettings
          settings={d.Form.Settings}
          groups={r.AssignableGroups}
          connected={r.Connected}
          understood={d.Form.Understood}
        />
      </div>
      <Button
        type="button"
        variant="outline"
        disabled={busy}
        onClick={(event) => {
          const form = event.currentTarget.form;
          if (form) void showPreview(form);
        }}
      >
        {busy ? "Composing…" : "Preview effective policy"}
      </Button>
      {problem && (
        <p className="problem" role="alert">
          {problem}
        </p>
      )}
      {preview && <EffectivePolicy effective={preview} warnings={warnings} />}
      <Button type="submit">
        {r.Bound ? "Save binding" : "Bind policies"}
      </Button>
    </form>
  );
}
