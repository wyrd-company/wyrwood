// ---
// relationships:
//   implements: web-interface
// ---
import { Panel } from "@/components/shared";
import type { SettingsData } from "@/types";

export function Settings({ data }: { data: SettingsData }) {
  return (
    <main>
      <p className="hint">
        Effective controller settings loaded at startup. To change them, edit
        the controller configuration and restart the controller. This view is
        read-only. Credentials and credential-file paths are omitted. Endpoint
        origins show only the scheme and host.
      </p>
      {data.Sections.map((section, index) => (
        <Panel key={section.Title} aria-labelledby={`settings-${index}`}>
          <h2 id={`settings-${index}`}>{section.Title}</h2>
          <dl className="facts">
            {section.Settings.map((setting) => (
              <div key={setting.Label}>
                <dt>{setting.Label}</dt>
                <dd className="mono">{setting.Value || "Not configured"}</dd>
              </div>
            ))}
          </dl>
        </Panel>
      ))}
    </main>
  );
}
