// ---
// relationships:
//   implements: web-interface
// ---
import { useEffect, useState } from "react";
import { Button } from "@/components/shared";
import { isLiteralACLPath } from "@/lib/policy-hcl";

export function KVBrowser({
  mounts,
  add,
}: {
  mounts: string[];
  add: (path: string, caps: string[]) => void;
}) {
  const [mount, setMount] = useState(mounts[0] || "");
  const [prefix, setPrefix] = useState("");
  const [listing, setListing] = useState<{
    mount: string;
    prefix: string;
    paths: string[];
    problem: string;
  }>();
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (!mount) return;
    const abort = new AbortController();
    fetch(`/policies/kv?${new URLSearchParams({ mount, prefix })}`, {
      signal: abort.signal,
      headers: { Accept: "application/json" },
    })
      .then(async (response) => {
        if (!response.ok) throw new Error("unavailable");
        const data: { Paths: string[] } = await response.json();
        if (
          !Array.isArray(data.Paths) ||
          data.Paths.some((path) => typeof path !== "string")
        )
          throw new Error("invalid");
        if (!abort.signal.aborted)
          setListing({ mount, prefix, paths: data.Paths, problem: "" });
      })
      .catch(() => {
        if (!abort.signal.aborted)
          setListing({
            mount,
            prefix,
            paths: [],
            problem:
              "KV paths could not be listed. Check metadata LIST permission. You can still add a path below.",
          });
      });
    return () => abort.abort();
  }, [mount, prefix, attempt]);
  if (!mounts.length)
    return (
      <p className="hint">
        Configure kv-v2 entries in openbao.secret-mounts to browse KV paths. You
        can add paths below.
      </p>
    );
  const current =
    listing?.mount === mount && listing.prefix === prefix ? listing : undefined;
  return (
    <fieldset className="flex flex-col gap-3 rounded-md border border-border p-4">
      <legend>Browse KV paths</legend>
      <p className="hint">
        Names only. Selecting a secret adds its data path; no secret values are
        read.
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor="kv-mount">KV mount</label>
        <select
          id="kv-mount"
          value={mount}
          onChange={(event) => {
            setMount(event.target.value);
            setPrefix("");
          }}
        >
          {mounts.map((name) => (
            <option key={name}>{name}</option>
          ))}
        </select>
        <Button
          type="button"
          variant="outline"
          disabled={!prefix}
          onClick={() => setPrefix(prefix.replace(/[^/]+\/$/, ""))}
        >
          Up one level
        </Button>
        <Button
          type="button"
          variant="outline"
          onClick={() => {
            setListing(undefined);
            setAttempt(attempt + 1);
          }}
        >
          Refresh paths
        </Button>
      </div>
      <p className="mono break-all">
        {mount}/{prefix}
      </p>
      {!current ? (
        <p role="status">Loading KV paths…</p>
      ) : current.problem ? (
        <p className="caution" role="alert">
          {current.problem}
        </p>
      ) : current.paths.length ? (
        <ul className="flex flex-col gap-2">
          {current.paths.map((name) => (
            <li
              key={name}
              className="flex flex-wrap items-center justify-between gap-2"
            >
              {name.endsWith("/") ? (
                <button
                  type="button"
                  className="mono underline"
                  onClick={() => setPrefix(prefix + name)}
                  aria-label={`Open ${name}`}
                >
                  {name}
                </button>
              ) : (
                <span className="mono break-all">{name}</span>
              )}
              <Button
                type="button"
                variant="outline"
                onClick={() =>
                  add(
                    `${mount}/data/${prefix}${name}${name.endsWith("/") ? "*" : ""}`,
                    ["read"],
                  )
                }
                disabled={!isLiteralACLPath(`${mount}/${prefix}${name}`)}
                aria-label={`Add ${name}`}
              >
                {name.endsWith("/") ? "Add subtree" : "Add read path"}
              </Button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="hint">No paths in this directory.</p>
      )}
      {(!isLiteralACLPath(`${mount}/${prefix}`) ||
        current?.paths.some(
          (name) => !isLiteralACLPath(`${mount}/${prefix}${name}`),
        )) && (
        <p className="caution">
          Names with ACL wildcards, ACL templating, or HCL template syntax
          cannot be added as literal paths. Use raw HCL to choose their grant.
        </p>
      )}
      <Button
        type="button"
        variant="outline"
        disabled={!isLiteralACLPath(`${mount}/${prefix}`)}
        onClick={() => add(`${mount}/metadata/${prefix}*`, ["list"])}
      >
        Add LIST path for this directory
      </Button>
    </fieldset>
  );
}
