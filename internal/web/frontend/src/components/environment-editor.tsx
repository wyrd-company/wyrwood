// ---
// relationships:
//   implements: container-contract
// ---
import { useState } from "react";
import { Button, Input } from "@/components/shared";

export function EnvironmentEditor({ value }: { value: string }) {
  const [source, setSource] = useState(value);
  const [rows, setRows] = useState(() =>
    value
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line, id) => {
        const split = line.indexOf("=");
        return {
          id,
          name: split < 0 ? line : line.slice(0, split),
          value: split < 0 ? "" : line.slice(split + 1),
          valid: split >= 0,
        };
      }),
  );
  const [nextID, setNextID] = useState(rows.length);
  const update = (next: typeof rows) => {
    setRows(next);
    setSource(
      next
        .map((row) => (row.valid ? `${row.name}=${row.value}` : row.name))
        .join("\n"),
    );
  };
  return (
    <fieldset className="flex flex-col gap-3">
      <legend>Environment</legend>
      <input type="hidden" name="env" value={source} />
      <p className="hint">
        <code>{"{mount-target}"}</code> is replaced by the mount target.
      </p>
      {rows.map((row, index) => (
        <div
          key={row.id}
          className="flex flex-col gap-2 rounded-md border border-border p-3"
        >
          <label htmlFor={`env-name-${row.id}`}>
            Variable {index + 1} name
          </label>
          <Input
            id={`env-name-${row.id}`}
            value={row.name}
            onChange={(event) =>
              update(
                rows.map((entry) =>
                  entry.id === row.id
                    ? { ...entry, name: event.target.value, valid: true }
                    : entry,
                ),
              )
            }
          />
          <label htmlFor={`env-value-${row.id}`}>
            Variable {index + 1} value
          </label>
          <Input
            id={`env-value-${row.id}`}
            value={row.value}
            onChange={(event) =>
              update(
                rows.map((entry) =>
                  entry.id === row.id
                    ? { ...entry, value: event.target.value, valid: true }
                    : entry,
                ),
              )
            }
          />
          {!row.valid && (
            <p className="caution">This entry needs a value separated by =.</p>
          )}
          <Button
            type="button"
            variant="outline"
            aria-label={`Remove variable ${index + 1}`}
            onClick={() => update(rows.filter((entry) => entry.id !== row.id))}
          >
            Remove variable
          </Button>
        </div>
      ))}
      <Button
        type="button"
        variant="outline"
        onClick={() => {
          update([...rows, { id: nextID, name: "", value: "", valid: true }]);
          setNextID(nextID + 1);
        }}
      >
        Add variable
      </Button>
    </fieldset>
  );
}
