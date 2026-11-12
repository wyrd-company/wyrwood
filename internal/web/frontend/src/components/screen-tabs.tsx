// ---
// relationships:
//   implements: web-interface
// ---
import * as Tabs from "@radix-ui/react-tabs";
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
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
  useLayoutEffect(() => {
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

// keepInView scrolls the tab list sideways so that the tab is inside the
// list's scroll padding, clear of a faded edge. It moves only the list, never
// the page.
function keepInView(list: HTMLElement, tab: HTMLElement) {
  const pad = parseFloat(getComputedStyle(list).scrollPaddingLeft) || 0;
  const box = list.getBoundingClientRect();
  const edges = tab.getBoundingClientRect();
  if (edges.left < box.left + pad) {
    list.scrollLeft -= box.left + pad - edges.left;
  } else if (edges.right > box.right - pad) {
    list.scrollLeft += edges.right - (box.right - pad);
  }
}

// markMore marks each side of the tab list that has tabs out of sight, so that
// the stylesheet fades that edge.
function markMore(list: HTMLElement) {
  const rest = list.scrollWidth - list.clientWidth - list.scrollLeft;
  list.toggleAttribute("data-more-start", list.scrollLeft > 1);
  list.toggleAttribute("data-more-end", rest > 1);
}

// At phone width the tab list is one row that scrolls sideways. A tab that
// takes focus or becomes selected scrolls into view.
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
  const list = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    const element = list.current;
    const selected = element?.querySelector<HTMLElement>(
      '[role="tab"][data-state="active"]',
    );
    if (element && selected) keepInView(element, selected);
    if (element) markMore(element);
  }, [value]);
  useEffect(() => {
    const element = list.current;
    if (!element || typeof ResizeObserver === "undefined") return;
    // The tabs change width when the web font loads, and the list when the
    // page does.
    const observer = new ResizeObserver(() => markMore(element));
    observer.observe(element);
    for (const tab of element.children) observer.observe(tab);
    return () => observer.disconnect();
  }, [tabs.map((tab) => tab.id).join()]);
  return (
    <Tabs.Root value={value} onValueChange={onValueChange}>
      <Tabs.List
        ref={list}
        aria-label={label}
        className="screen-tabs"
        onFocus={(event) => {
          if (event.target.getAttribute("role") === "tab") {
            keepInView(event.currentTarget, event.target);
          }
        }}
        onScroll={(event) => markMore(event.currentTarget)}
      >
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
