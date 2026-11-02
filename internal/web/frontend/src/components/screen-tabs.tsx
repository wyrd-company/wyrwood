// ---
// relationships:
//   implements: web-interface
// ---
import * as Tabs from "@radix-ui/react-tabs";
import {
  useCallback,
  useEffect,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import { flushSync } from "react-dom";

export interface ScreenTab {
  id: string;
  label: string;
  // Text in the tab's name, for hidden content that needs attention.
  attention?: boolean;
  content: ReactNode;
}

function focusPanel(id: string) {
  document
    .querySelector<HTMLElement>(`[role="tabpanel"][data-tab="${id}"]`)
    ?.focus();
}

// useScreenTabs owns the selected tab. The tab that owns a refused submission's
// problem comes first, then the tab the request names, then the first tab. A
// value the screen does not have is ignored. A fragment that names content in a
// tab selects that tab and moves focus to its panel.
export function useScreenTabs(
  ids: string[],
  data: { Tab?: string; ProblemTab?: string },
  fragments: Record<string, string> = {},
) {
  const [tab, setTab] = useState(
    () =>
      [data.ProblemTab, data.Tab].find((id) => id && ids.includes(id)) ??
      ids[0],
  );
  const [focusing, setFocusing] = useState("");
  useEffect(() => {
    if (focusing) {
      focusPanel(focusing);
      setFocusing("");
    }
  }, [focusing]);
  const reveal = useCallback(
    (fragment: string) => {
      const id = fragments[fragment];
      if (id && ids.includes(id)) {
        setTab(id);
        setFocusing(id);
      }
    },
    [ids.join(), JSON.stringify(fragments)],
  );
  useEffect(() => {
    const follow = () => reveal(window.location.hash);
    if (!data.ProblemTab) follow();
    window.addEventListener("hashchange", follow);
    return () => window.removeEventListener("hashchange", follow);
  }, [reveal, data.ProblemTab]);
  // A browser cannot focus a required control in a hidden panel, so it would
  // refuse the submission and show nothing. The first invalid control's panel is
  // shown before the browser reports it, so the browser focuses the control and
  // shows its own message.
  const onInvalidCapture = (event: FormEvent<HTMLFormElement>) => {
    const control = event.target as HTMLElement;
    const first = event.currentTarget.querySelector(
      "input:invalid, select:invalid, textarea:invalid",
    );
    const id = control.closest("[role=tabpanel]")?.getAttribute("data-tab");
    if (control === first && id) flushSync(() => setTab(id));
  };
  // The selected tab travels in a form's action and in links, not in a form field,
  // so the fields a form posts do not change. The first tab needs no value.
  const withTab = (url: string) =>
    tab === ids[0]
      ? url
      : `${url}${url.includes("?") ? "&" : "?"}tab=${encodeURIComponent(tab)}`;
  return { tab, setTab, reveal, onInvalidCapture, withTab };
}

export function ScreenTabs({
  label,
  tabs,
  value,
  onValueChange,
}: {
  label: string;
  tabs: ScreenTab[];
  value: string;
  onValueChange: (id: string) => void;
}) {
  return (
    <Tabs.Root value={value} onValueChange={onValueChange}>
      <Tabs.List aria-label={label} className="screen-tabs">
        {tabs.map((tab) => (
          <Tabs.Trigger key={tab.id} value={tab.id} className="screen-tab">
            {tab.label}
            {tab.attention && (
              <span className="tab-attention"> · Needs attention</span>
            )}
          </Tabs.Trigger>
        ))}
      </Tabs.List>
      {tabs.map((tab) => (
        // forceMount alone leaves the panel visible. The panel keeps its fields
        // in the form, and hidden removes it from sight and the accessibility tree.
        <Tabs.Content
          key={tab.id}
          value={tab.id}
          forceMount
          hidden={tab.id !== value}
          data-tab={tab.id}
          className="screen-panel"
        >
          {tab.content}
        </Tabs.Content>
      ))}
    </Tabs.Root>
  );
}
