// ---
// relationships:
//   implements: web-interface
// ---
import {
  Button,
  CSRF,
  Notice,
  Status,
  Table,
  Input,
  Field,
} from "@/components/shared";
import type {
  ContainerRow,
  ContainersData,
  EffectivePolicy as Effective,
} from "@/types";
import { ago } from "@/lib/time";
import { useRef, useState } from "react";
import { BindingSettings } from "./binding-settings";
import { EffectivePolicy } from "./effective-policy";
import { ContainerSetup } from "./container-setup";
export function Containers({ data: d }: { data: ContainersData }) {
  return (
    <main className="split">
      <div className="main-column flex flex-col gap-4">
        <Notice text={d.Notice} />
        {d.Agents?.length ? (
          <>
            <form
              method="get"
              action="/containers"
              className="filters container-filters"
            >
              {d.Selected && (
                <>
                  <input type="hidden" name="agent" value={d.Selected.Agent} />
                  <input type="hidden" name="container" value={d.Selected.ID} />
                </>
              )}
              <Field label="Agent" id="filter-agent">
                <select
                  id="filter-agent"
                  name="filter-agent"
                  className="w-auto"
                  defaultValue={d.FilterAgent}
                >
                  <option value="">All agents</option>
                  {d.Agents.map((agent) => (
                    <option key={agent.Name} value={agent.Name}>
                      {agent.Name} · {agent.Containers} containers
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Filter containers" id="container-search">
                <Input
                  id="container-search"
                  name="q"
                  type="search"
                  defaultValue={d.Query}
                  placeholder="Name, image, policy, state…"
                />
              </Field>
              <Field label="Sort by" id="container-sort">
                <select
                  id="container-sort"
                  name="sort"
                  className="w-auto"
                  defaultValue={d.Sort}
                >
                  <option value="name">Container</option>
                  <option value="agent">Agent</option>
                  <option value="image">Image</option>
                  <option value="state">State</option>
                </select>
              </Field>
              <Field label="Order" id="container-order">
                <select
                  id="container-order"
                  name="order"
                  className="w-auto"
                  defaultValue={d.Order}
                >
                  <option value="asc">Ascending</option>
                  <option value="desc">Descending</option>
                </select>
              </Field>
              <div className="container-filter-actions">
                <Button variant="outline" type="submit" className="small">
                  Apply filters
                </Button>
                <a href="/containers">Clear filters</a>
              </div>
            </form>
            <section aria-label="Reported containers">
              <Table
                columns={["Container", "Agent", "Key", "Policies", "State"]}
                count={d.Rows?.length ?? 0}
                empty={
                  d.FilterAgent || d.Query
                    ? "No containers match these filters."
                    : "No containers have been reported."
                }
              >
                {d.Rows?.map((row) => (
                  <tr
                    key={JSON.stringify([row.Agent, row.ID])}
                    className={
                      row.Agent === d.Selected?.Agent &&
                      row.ID === d.Selected?.ID
                        ? "selected"
                        : undefined
                    }
                  >
                    <th scope="row">
                      <a
                        className="row-link"
                        href={`/containers?${new URLSearchParams({
                          agent: row.Agent,
                          container: row.ID,
                          "filter-agent": d.FilterAgent,
                          q: d.Query,
                          sort: d.Sort,
                          order: d.Order,
                        })}`}
                        aria-current={
                          row.Agent === d.Selected?.Agent &&
                          row.ID === d.Selected?.ID
                            ? "true"
                            : undefined
                        }
                      >
                        <span>{row.Name}</span>
                        <span className="mono">{row.Image}</span>
                      </a>
                    </th>
                    <td>
                      <span>{row.Agent}</span>
                      <div className="hint">
                        {row.Connected
                          ? "Connected"
                          : "Disconnected · last report shown"}
                      </div>
                      <div className="hint">
                        Last report {ago(row.LastReport)}
                      </div>
                    </td>
                    <td>
                      <span className="tag">{row.KeyKind}</span>
                    </td>
                    <td className="mono">
                      {row.Policies?.join(", ") || (
                        <span className="hint">none</span>
                      )}
                    </td>
                    <td>
                      <Status kind={row.BadgeClass}>{row.Badge}</Status>
                    </td>
                  </tr>
                ))}
              </Table>
            </section>
          </>
        ) : (
          <p className="hint">No approved agent has reported yet.</p>
        )}
      </div>
      {d.Selected && (
        <ContainerDetails
          key={JSON.stringify([
            d.Selected.Agent,
            d.Selected.ID,
            d.Selected.Revision,
          ])}
          data={d}
          row={d.Selected}
        />
      )}
    </main>
  );
}
function ContainerDetails({
  data: d,
  row: r,
}: {
  data: ContainersData;
  row: ContainerRow;
}) {
  const bindingURL = `/bindings/${encodeURIComponent(r.BindingID)}`;
  return (
    <aside className="card" aria-labelledby="h-sel">
      <div>
        <h2 id="h-sel">{r.Name}</h2>
        <span className="hint">
          on {r.Agent} · <span className="mono">{r.Image}</span> · {r.State}
        </span>
      </div>
      {r.Bound ? (
        <>
          <dl className="facts">
            <div>
              <dt>Policies</dt>
              <dd className="mono">{r.Policies?.join(", ")}</dd>
            </div>
            <div>
              <dt>Token</dt>
              <dd>{r.Token}</dd>
            </div>
            <div className="col-span-full">
              <dt>Bound by {r.KeyKind} key</dt>
              <dd className="mono">{r.KeyValue}</dd>
            </div>
          </dl>
          <div>
            <h3>Contract check</h3>
            <ul className="plain">
              {r.Checks?.map((check) => (
                <li key={check.Label}>
                  <Status kind={`mark ${check.Status}`}>{check.Mark}</Status>
                  <span className="mono">{check.Label}</span>
                </li>
              ))}
            </ul>
          </div>
          <p className="hint">
            {r.Applied
              ? "AppRole assignment applied"
              : "Token transition pending; fresh issuance is blocked"}
          </p>
          <ContainerSetup setup={r.Setup} />
          <BindingForm data={d} row={r} />
          {r.Effective?.sources?.length > 0 && (
            <EffectivePolicy effective={r.Effective} warnings={r.Warnings} />
          )}
          <div className="actions">
            <Button asChild variant="outline">
              <a href={`${bindingURL}/recreate`}>Request recreate</a>
            </Button>
            <Button asChild variant="outline" className="danger">
              <a href={`${bindingURL}/unbind`}>Unbind and revoke AppRole</a>
            </Button>
          </div>
        </>
      ) : d.Policies?.length ? (
        <BindingForm data={d} row={r} />
      ) : (
        <p className="hint">
          Create a policy before binding.{" "}
          <a href="/policies/edit">New policy</a>
        </p>
      )}
    </aside>
  );
}

function BindingForm({
  data: d,
  row: r,
}: {
  data: ContainersData;
  row: ContainerRow;
}) {
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
      action={
        r.Bound
          ? `/bindings/${encodeURIComponent(r.BindingID)}/policy`
          : "/bindings"
      }
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
      <input type="hidden" name="revision" value={r.Revision || 0} />
      {!r.Bound && (
        <fieldset>
          <legend>Bind by key</legend>
          {r.Candidates?.map((candidate) => (
            <label className="choice" key={candidate.Encoded}>
              <input
                type="radio"
                name="key"
                value={candidate.Encoded}
                defaultChecked={candidate.First}
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
              defaultChecked={r.Policies?.includes(p.Name) || false}
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
      <BindingSettings settings={r.Settings} />
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
