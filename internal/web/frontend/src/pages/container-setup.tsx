// ---
// relationships:
//   implements: web-interface
// ---
import { useState } from "react";
import { Button } from "@/components/shared";
import type { ContainerRow } from "@/types";

export function ContainerSetup({ setup }: { setup: ContainerRow["Setup"] }) {
  return (
    <section aria-labelledby="h-setup" className="flex flex-col gap-3">
      <h3 id="h-setup">Container setup</h3>
      {setup ? (
        <>
          <p className="hint">
            Run on this container’s agent host. The source directory is
            agent-managed; let the agent create it. Add these settings when
            creating the container and retain your application’s other options.
          </p>
          <SetupValue label="Host source" value={setup.Source} />
          <SetupValue label="Container target" value={setup.Target} />
          <SetupValue label="Docker Compose" value={setup.Compose} />
          <SetupValue label="docker run" value={setup.DockerRun} />
        </>
      ) : (
        <p className="hint">
          Setup examples are unavailable until the agent reports the consumer
          directory and container image. Update the agent if its report omits
          the directory.
        </p>
      )}
    </section>
  );
}

function SetupValue({ label, value }: { label: string; value: string }) {
  const [message, setMessage] = useState("");
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center justify-between gap-2">
        <h4>{label}</h4>
        <Button
          type="button"
          variant="outline"
          className="small"
          aria-label={`Copy ${label}`}
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(value);
              setMessage(`${label} copied.`);
            } catch {
              setMessage(`Select and copy the ${label} text below.`);
            }
          }}
        >
          Copy
        </Button>
      </div>
      <pre className="overflow-x-auto whitespace-pre-wrap break-all text-xs">
        <code>{value}</code>
      </pre>
      {message && (
        <p className="hint" role="status">
          {message}
        </p>
      )}
    </div>
  );
}
