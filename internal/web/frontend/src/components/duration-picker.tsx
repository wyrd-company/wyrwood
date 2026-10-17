// ---
// relationships:
//   implements: web-interface
// ---
import { useState } from "react";
import { Input } from "@/components/shared";

export function DurationPicker({
  id,
  name,
  value,
  binding = false,
}: {
  id: string;
  name: string;
  value: string;
  binding?: boolean;
}) {
  const units = binding ? ["m", "h"] : ["s", "m", "h"];
  const parsed = /^(\d+)([smh])$/.exec(value);
  const simple = parsed && units.includes(parsed[2]);
  const [amount, setAmount] = useState(simple ? parsed[1] : "");
  const [unit, setUnit] = useState(simple ? parsed[2] : "h");
  const [duration, setDuration] = useState(value);
  // Preserve an invalid server-echoed value so the operator can correct it.
  const [custom] = useState(!simple);
  return (
    <div className="flex flex-wrap items-center gap-2">
      <input type="hidden" name={name} value={duration} />
      {custom ? (
        <Input
          id={id}
          value={duration}
          onChange={(event) => setDuration(event.target.value)}
          required
        />
      ) : (
        <>
          <Input
            id={id}
            className="w-28"
            type="number"
            min={binding ? "1" : "0"}
            step="1"
            value={amount}
            required
            onChange={(event) => {
              setAmount(event.target.value);
              setDuration(event.target.value ? event.target.value + unit : "");
            }}
          />
          <select
            aria-label={`${name} unit`}
            value={unit}
            onChange={(event) => {
              setUnit(event.target.value);
              setDuration(amount ? amount + event.target.value : "");
            }}
          >
            {units.map((unit) => (
              <option key={unit} value={unit}>
                {{ s: "Seconds", m: "Minutes", h: "Hours" }[unit]}
              </option>
            ))}
          </select>
        </>
      )}
    </div>
  );
}
