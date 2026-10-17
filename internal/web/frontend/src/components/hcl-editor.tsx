// ---
// relationships:
//   implements: web-interface
// ---
import { useState } from "react";
import { Button, Input, Textarea } from "@/components/shared";
import { KVBrowser } from "@/components/kv-browser";
import {
  addSelfOperations,
  appendRule,
  capabilities,
  graphicalRules,
  hasPathTemplate,
  replaceSpan,
} from "@/lib/policy-hcl";

export function HCLEditor({
  value,
  mounts,
  onChange,
  onCheck,
}: {
  value: string;
  mounts: string[];
  onChange?: (hcl: string) => void;
  onCheck?: (hcl: string) => void;
}) {
  const [source, setSource] = useState(value);
  const [raw, setRaw] = useState(false);
  const [newPath, setNewPath] = useState("");
  const [pathProblem, setPathProblem] = useState("");
  const rules = graphicalRules(source);
  const showRaw = raw || !rules;
  const changeSource = (next: string, check = false) => {
    setSource(next);
    onChange?.(next);
    if (check) onCheck?.(next);
  };
  const add = (path: string, caps: string[]) =>
    changeSource(appendRule(source, path, caps), true);
  return (
    <div className="flex flex-col gap-4">
      <input type="hidden" name="hcl" value={source} />
      <div
        className="flex flex-wrap gap-2"
        role="group"
        aria-label="Policy editor view"
      >
        <Button
          type="button"
          variant="outline"
          aria-pressed={!showRaw}
          disabled={!rules}
          onClick={() => setRaw(false)}
        >
          Graphical paths
        </Button>
        <Button
          type="button"
          variant="outline"
          aria-pressed={showRaw}
          onClick={() => setRaw(true)}
        >
          Raw HCL
        </Button>
      </div>
      {!rules && (
        <p className="caution">
          This HCL uses constructs the graphical editor cannot represent. Edit
          it as raw HCL; the complete text is retained.
        </p>
      )}
      <p className="hint">
        Binding tokens have no OpenBao default policy. Include
        auth/token/lookup-self (read), auth/token/renew-self (update), and
        auth/token/revoke-self (update). TTL, access group, and enforcement are
        set on each binding.
      </p>
      <Button
        type="button"
        variant="outline"
        disabled={!rules}
        onClick={() => changeSource(addSelfOperations(source), true)}
      >
        Add token self-operation preset
      </Button>
      {pathProblem && <p className="caution">{pathProblem}</p>}
      {showRaw ? (
        <div className="field">
          <label htmlFor="hcl">OpenBao policy HCL</label>
          <Textarea
            id="hcl"
            className="hcl"
            spellCheck={false}
            value={source}
            onChange={(event) => changeSource(event.target.value)}
            onBlur={() => onCheck?.(source)}
          />
        </div>
      ) : (
        <>
          <div className="flex flex-col gap-3" aria-label="Policy paths">
            {rules.map((rule, index) => (
              <fieldset
                key={index}
                className="flex min-w-0 flex-col gap-3 rounded-md border border-border p-4"
              >
                <legend>Path {index + 1}</legend>
                <label htmlFor={`path-${index}`} className="visually-hidden">
                  Path {index + 1}
                </label>
                <Input
                  id={`path-${index}`}
                  className="mono"
                  value={rule.path}
                  onBlur={() => onCheck?.(source)}
                  onChange={(event) => {
                    if (hasPathTemplate(event.target.value)) {
                      setPathProblem(
                        "Use Raw HCL for path template syntax. The graphical path is unchanged.",
                      );
                      return;
                    }
                    setPathProblem("");
                    changeSource(
                      replaceSpan(
                        source,
                        rule.pathStart,
                        rule.pathEnd,
                        JSON.stringify(event.target.value),
                      ),
                    );
                  }}
                />
                <div className="flex flex-wrap gap-x-4 gap-y-2">
                  {capabilities.map((cap) => (
                    <label key={cap} className="editor-choice">
                      <input
                        type="checkbox"
                        checked={rule.capabilities.includes(cap)}
                        onChange={(event) => {
                          const selected = event.target.checked
                            ? [...rule.capabilities, cap]
                            : rule.capabilities.filter(
                                (value) => value !== cap,
                              );
                          changeSource(
                            replaceSpan(
                              source,
                              rule.capsStart,
                              rule.capsEnd,
                              JSON.stringify(selected),
                            ),
                            true,
                          );
                        }}
                      />
                      {cap}
                    </label>
                  ))}
                </div>
                <Button
                  type="button"
                  variant="outline"
                  aria-label={`Remove path ${index + 1}`}
                  onClick={() =>
                    changeSource(
                      replaceSpan(source, rule.start, rule.end, ""),
                      true,
                    )
                  }
                >
                  Remove path
                </Button>
              </fieldset>
            ))}
            {!rules.length && (
              <p className="hint">
                No paths. Add a path or the token self-operation preset.
              </p>
            )}
          </div>
          <KVBrowser mounts={mounts} add={add} />
          <fieldset className="flex flex-col gap-2">
            <legend>Add a path</legend>
            <p className="hint">
              Paths are relative to the namespace. Wildcards and paths outside
              the browsed mounts can be entered here. OpenBao ACL templates (
              <code>{"{{...}}"}</code>) are evaluated for each token.
            </p>
            <label htmlFor="new-path" className="visually-hidden">
              New path
            </label>
            <Input
              id="new-path"
              className="mono"
              value={newPath}
              onChange={(event) => setNewPath(event.target.value)}
              placeholder="kv/data/example/*"
            />
            {hasPathTemplate(newPath) && (
              <p className="caution">Use Raw HCL for path template syntax.</p>
            )}
            <Button
              type="button"
              variant="outline"
              disabled={!newPath.trim() || hasPathTemplate(newPath)}
              onClick={() => {
                add(newPath.trim(), ["read"]);
                setNewPath("");
              }}
            >
              Add path
            </Button>
          </fieldset>
        </>
      )}
    </div>
  );
}
