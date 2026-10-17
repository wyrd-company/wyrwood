// ---
// relationships:
//   implements: web-interface
// ---
import { useState, useId } from "react";
import { Button, Input } from "@/components/shared";

function lines(value: string) {
  return value
    .split(/\r?\n/)
    .map((name) => name.trim())
    .filter(Boolean);
}
export function IdentityPicker({
  title,
  name,
  available,
  selected,
  restricted,
}: {
  title: string;
  name: string;
  available: string[];
  selected: string;
  restricted: string;
}) {
  const id = useId();
  const [manual, setManual] = useState<string[]>([]);
  const [candidate, setCandidate] = useState("");
  const [offered, setOffered] = useState(lines(selected));
  const [blocked, setBlocked] = useState(lines(restricted));
  const names = [
    ...new Set([
      ...available,
      ...lines(selected),
      ...lines(restricted),
      ...offered,
      ...blocked,
      ...manual,
    ]),
  ].sort();
  return (
    <fieldset className="flex min-w-0 flex-col gap-3">
      <legend>{title}</legend>
      <input type="hidden" name={name} value={offered.join("\n")} />
      <input
        type="hidden"
        name={`not-forwardable-${name}`}
        value={blocked.join("\n")}
      />
      {!names.length && <p className="hint">No available items.</p>}
      {names.map((identity) => (
        <div
          key={identity}
          className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-border p-3"
        >
          <label className="editor-choice min-w-0">
            <input
              type="checkbox"
              checked={offered.includes(identity)}
              onChange={(event) => {
                setOffered(
                  event.target.checked
                    ? [...offered, identity]
                    : offered.filter((name) => name !== identity),
                );
              }}
            />
            <span className="mono break-all">{identity}</span>
            {!available.includes(identity) && (
              <span className="hint">not listed</span>
            )}
          </label>
          <label className="editor-choice">
            <input
              type="checkbox"
              aria-label={`Not forwardable ${identity}`}
              checked={blocked.includes(identity)}
              onChange={(event) => {
                setBlocked(
                  event.target.checked
                    ? [...blocked, identity]
                    : blocked.filter((name) => name !== identity),
                );
              }}
            />
            Not forwardable
          </label>
        </div>
      ))}
      <div className="flex flex-col gap-2">
        <label htmlFor={id}>Additional {title.toLowerCase()} name</label>
        <Input
          id={id}
          value={candidate}
          onChange={(event) => setCandidate(event.target.value)}
        />
        <Button
          type="button"
          variant="outline"
          disabled={!candidate.trim()}
          onClick={() => {
            setManual([...manual, candidate.trim()]);
            setCandidate("");
          }}
        >
          Add identity name
        </Button>
        <p className="hint">
          An offered identity must exist in OpenBao. A not-forwardable selector
          can name an identity offered by another policy in the binding.
        </p>
      </div>
    </fieldset>
  );
}
