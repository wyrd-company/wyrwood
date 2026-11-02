// ---
// relationships:
//   implements: web-interface
// ---
import { ScreenTabs, useScreenTabs } from "@/components/screen-tabs";
import { Button, CSRF } from "@/components/shared";
import type { BindingData, EffectivePolicy as Effective } from "@/types";
import { useLayoutEffect, useRef, useState } from "react";
import {
  BindingHeading,
  BindingStatus,
  KeyChoice,
  PolicyChoices,
} from "./binding-sections";
import { BindingSettings, groupUnassignable } from "./binding-settings";
import { ContainerSetup } from "./container-setup";
import {
  DecisionSummary,
  enteredDecisions,
  savedDecisions,
} from "./decision-summary";
import { EffectivePolicy } from "./effective-policy";

const fragments = { "#h-setup": "container-setup" };

export function BindingForm({ data: d }: { data: BindingData }) {
  const r = d.Row;
  const ids = r.Bound
    ? [
        "status",
        "policies",
        "settings",
        "effective-policy",
        ...(d.Reported ? ["container-setup"] : []),
      ]
    : ["key-and-policies", "settings", "effective-policy"];
  const { tab, setTab, onInvalidCapture, withTab } = useScreenTabs(
    ids,
    d,
    fragments,
  );
  const form = useRef<HTMLFormElement>(null);
  const [decisions, setDecisions] = useState(() => savedDecisions(d));
  const [changes, setChanges] = useState(0);
  // Children keep their own field state, so the form is read after they commit.
  useLayoutEffect(() => {
    if (form.current) setDecisions(enteredDecisions(form.current));
  }, [changes]);
  const [preview, setPreview] = useState<Effective | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [problem, setProblem] = useState("");
  const [busy, setBusy] = useState(false);
  const previewRequest = useRef(0);
  async function showPreview(target: HTMLFormElement) {
    const request = ++previewRequest.current;
    setTab("effective-policy");
    setBusy(true);
    setProblem("");
    setPreview(null);
    try {
      const body = new URLSearchParams();
      new FormData(target).forEach((value, key) => {
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
  const saved = r.Bound && r.Effective?.sources?.length > 0;
  const effective = (
    <div className="flex flex-col gap-4">
      {problem && (
        <p className="problem" role="alert">
          {problem}
        </p>
      )}
      {preview && (
        <EffectivePolicy
          effective={preview}
          warnings={warnings}
          title="Previewed effective policy"
        />
      )}
      {saved && (
        <EffectivePolicy effective={r.Effective} warnings={r.Warnings} />
      )}
      {!preview && !saved && !problem && (
        <p className="hint">
          {busy
            ? "Composing the selected policies."
            : "Select Preview effective policy to see what these choices compose."}
        </p>
      )}
    </div>
  );
  const settings = (
    <BindingSettings
      settings={d.Form.Settings}
      groups={r.AssignableGroups}
      connected={r.Connected}
      understood={d.Form.Understood}
    />
  );
  const settingsTab = {
    id: "settings",
    label: "Settings",
    attention: groupUnassignable(
      decisions.group,
      r.AssignableGroups,
      r.Connected,
    ),
    content: settings,
  };
  const effectiveTab = {
    id: "effective-policy",
    label: "Effective policy",
    attention: Boolean(r.Warnings?.length || warnings.length),
    content: effective,
  };
  const tabs = r.Bound
    ? [
        {
          id: "status",
          label: "Status",
          content: <BindingStatus data={d} />,
        },
        {
          id: "policies",
          label: "Policies",
          content: (
            <div className="binding-choices">
              <PolicyChoices data={d} />
            </div>
          ),
        },
        settingsTab,
        effectiveTab,
        ...(d.Reported
          ? [
              {
                id: "container-setup",
                label: "Container setup",
                content: <ContainerSetup setup={r.Setup} />,
              },
            ]
          : []),
      ]
    : [
        {
          id: "key-and-policies",
          label: "Key and policies",
          content: (
            <div className="binding-choices">
              <KeyChoice data={d} />
              <PolicyChoices data={d} />
            </div>
          ),
        },
        settingsTab,
        effectiveTab,
      ];
  const actions = (
    <div className="actions">
      <Button type="submit" className="primary">
        {r.Bound ? "Save binding" : "Bind policies"}
      </Button>
      <Button
        type="button"
        variant="outline"
        disabled={busy}
        onClick={(event) => {
          const target = event.currentTarget.form;
          if (target) void showPreview(target);
        }}
      >
        {busy ? "Composing…" : "Preview effective policy"}
      </Button>
      {r.Bound && (
        <div className="actions-separate">
          <Button asChild variant="outline">
            <a href={withTab(d.Recreate)}>Request recreate</a>
          </Button>
          <Button asChild variant="outline" className="danger">
            <a href={withTab(d.Unbind)}>Unbind and revoke AppRole</a>
          </Button>
        </div>
      )}
    </div>
  );
  return (
    <form
      ref={form}
      method="post"
      action={withTab(d.Action)}
      className="flex flex-col gap-4"
      onInvalidCapture={onInvalidCapture}
      onChange={() => {
        previewRequest.current++;
        setBusy(false);
        setPreview(null);
        setProblem("");
        setChanges((count) => count + 1);
      }}
    >
      <CSRF token={d.CSRF} />
      <input type="hidden" name="agent" value={r.Agent} />
      <input type="hidden" name="container" value={r.ID} />
      <input type="hidden" name="revision" value={d.Form.Revision || 0} />
      {d.Problem && (
        <p className="problem" role="alert">
          {d.Problem}{" "}
          {r.Bound && <a href={withTab(d.Screen)}>Reload saved values</a>}
        </p>
      )}
      {!d.Reported && (
        <p className="caution">
          The agent does not report a container for this binding now. The
          contract check and setup examples return when it does.
        </p>
      )}
      <section
        className="card flex flex-col gap-4"
        aria-labelledby="h-container"
      >
        <BindingHeading data={d} actions={actions} />
        <DecisionSummary data={d} decisions={decisions} />
      </section>
      <section className="card" aria-label="Binding details">
        <ScreenTabs
          label="Binding sections"
          tabs={tabs}
          value={tab}
          onValueChange={setTab}
        />
      </section>
    </form>
  );
}
