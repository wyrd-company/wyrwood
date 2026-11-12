// ---
// relationships:
//   verifies: web-interface
// ---
import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it } from "vitest";
import { ScreenTabs } from "./screen-tabs";

// jsdom has no layout. lay() gives the tab list a 250 px box that scrolls over
// tabs 100 px wide, so the list holds two and a half tabs.
const width = 250;
const tabWidth = 100;

function lay(list: HTMLElement) {
  let left = 0;
  const tabs = [...list.querySelectorAll<HTMLElement>("[role=tab]")];
  const max = tabs.length * tabWidth - width;
  Object.defineProperty(list, "scrollLeft", {
    configurable: true,
    get: () => left,
    set: (value: number) => {
      left = Math.min(max, Math.max(0, value));
    },
  });
  Object.defineProperty(list, "clientWidth", {
    configurable: true,
    value: width,
  });
  Object.defineProperty(list, "scrollWidth", {
    configurable: true,
    value: tabs.length * tabWidth,
  });
  list.getBoundingClientRect = () => new DOMRect(0, 0, width, 44);
  tabs.forEach((tab, index) => {
    tab.getBoundingClientRect = () =>
      new DOMRect(index * tabWidth - left, 0, tabWidth, 44);
  });
}

const ids = ["first", "second", "third", "fourth", "fifth"];

function Row({ start = "first" }: { start?: string }) {
  const [value, setValue] = useState(start);
  return (
    <>
      <ScreenTabs
        label="Sections"
        value={value}
        onValueChange={setValue}
        tabs={ids.map((id) => ({ id, label: id, content: <p>{id}</p> }))}
      />
      <button type="button" onClick={() => setValue("fifth")}>
        Select fifth
      </button>
    </>
  );
}

function setup() {
  const view = render(<Row />);
  const list = screen.getByRole("tablist");
  lay(list);
  return { ...view, list };
}

describe("tab row", () => {
  it("scrolls the selected tab back into view when it takes focus", () => {
    const { list } = setup();
    // The operator swipes the selected first tab out of sight, then Tab
    // moves focus to it. Focus does not change the selection.
    list.scrollLeft = 250;
    act(() => screen.getByRole("tab", { name: "first" }).focus());
    expect(screen.getByRole("tab", { name: "first" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(list.scrollLeft).toBe(0);
  });

  it("scrolls each tab into view as the arrow keys move focus", async () => {
    const user = userEvent.setup();
    const { list } = setup();
    act(() => screen.getByRole("tab", { name: "first" }).focus());
    for (const [index, id] of ids.slice(1).entries()) {
      await user.keyboard("{ArrowRight}");
      const tab = screen.getByRole("tab", { name: id });
      expect(tab).toHaveFocus();
      const edges = tab.getBoundingClientRect();
      expect([index, edges.left >= 0, edges.right <= width]).toEqual([
        index,
        true,
        true,
      ]);
    }
    expect(list.scrollLeft).toBe(250);
  });

  it("scrolls a tab that becomes selected without focus into view", async () => {
    const user = userEvent.setup();
    const { list } = setup();
    await user.click(screen.getByRole("button", { name: "Select fifth" }));
    expect(screen.getByRole("tab", { name: "fifth" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(screen.getByRole("button", { name: "Select fifth" })).toHaveFocus();
    expect(list.scrollLeft).toBe(250);
  });

  it("marks each side that has tabs out of sight", () => {
    const { list } = setup();
    fireEvent.scroll(list);
    expect(list).not.toHaveAttribute("data-more-start");
    expect(list).toHaveAttribute("data-more-end");
    list.scrollLeft = 100;
    fireEvent.scroll(list);
    expect(list).toHaveAttribute("data-more-start");
    expect(list).toHaveAttribute("data-more-end");
    list.scrollLeft = 250;
    fireEvent.scroll(list);
    expect(list).toHaveAttribute("data-more-start");
    expect(list).not.toHaveAttribute("data-more-end");
  });

  it("marks no side when every tab is in sight", () => {
    const { list } = setup();
    Object.defineProperty(list, "scrollWidth", { value: width });
    fireEvent.scroll(list);
    expect(list).not.toHaveAttribute("data-more-start");
    expect(list).not.toHaveAttribute("data-more-end");
  });
});
