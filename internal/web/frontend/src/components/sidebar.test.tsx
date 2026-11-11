// ---
// relationships:
//   verifies: web-interface
// ---
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { Layout } from "@/types";
import { Sidebar } from "./sidebar";

const layout: Layout = {
  Title: "Sample",
  Current: "agents",
  CSRF: "sample-csrf",
  Operator: "operator@example.com",
  Pending: 2,
  PendingOperatorKeys: 1,
  OpenBaoOK: true,
  OpenBaoURL: "",
  Controller: "controller.example.com",
  Notice: "",
  Problem: "",
};

// jsdom applies no style sheet, so the panel's visibility is the browser
// test's work (docs/demo/phone.sh). These tests cover the control's state.
function draw() {
  render(<Sidebar data={layout} />);
  const nav = screen.getByRole("navigation", { name: "Primary" });
  const control = within(nav).getByRole("button", { name: "Menu" });
  const panel = document.getElementById(control.getAttribute("aria-controls")!);
  return { nav, control, panel: panel! };
}

describe("navigation menu control", () => {
  it("is a closed button that names a panel holding every destination", () => {
    const { nav, control, panel } = draw();
    expect(control.tagName).toBe("BUTTON");
    expect(control).toHaveAttribute("type", "button");
    expect(control).toHaveAttribute("aria-expanded", "false");
    expect(nav).toContainElement(panel);
    expect(panel).not.toHaveAttribute("data-open");
    for (const name of [
      "Agents",
      "Bindings",
      "Policies",
      "OpenBao keys",
      "Operator keys",
      "Events",
      "Settings",
    ])
      expect(
        within(panel).getByRole("link", { name: new RegExp(`^${name}`) }),
      ).toBeInTheDocument();
    expect(within(panel).getByLabelText("2 pending")).toBeInTheDocument();
    expect(within(panel).getByLabelText("1 pending")).toBeInTheDocument();
    expect(within(panel).getByText("OpenBao reachable")).toBeInTheDocument();
    expect(
      within(panel).getByRole("link", { name: /Report an issue/ }),
    ).toBeInTheDocument();
    expect(
      within(panel).getByRole("button", { name: /Account/ }),
    ).toBeInTheDocument();
  });

  it("opens and closes with pointer, Enter and Space", async () => {
    const user = userEvent.setup();
    const { control, panel } = draw();
    await user.click(control);
    expect(control).toHaveAttribute("aria-expanded", "true");
    expect(panel).toHaveAttribute("data-open");
    await user.click(control);
    expect(control).toHaveAttribute("aria-expanded", "false");
    expect(panel).not.toHaveAttribute("data-open");
    control.focus();
    await user.keyboard("{Enter}");
    expect(control).toHaveAttribute("aria-expanded", "true");
    await user.keyboard(" ");
    expect(control).toHaveAttribute("aria-expanded", "false");
  });

  it("closes on Escape from an item and returns focus to the control", async () => {
    const user = userEvent.setup();
    const { control, panel } = draw();
    await user.click(control);
    within(panel).getByRole("link", { name: "Events" }).focus();
    await user.keyboard("{Escape}");
    expect(control).toHaveAttribute("aria-expanded", "false");
    expect(control).toHaveFocus();
  });

  it("leaves focus in place on Escape while the menu is closed", async () => {
    const user = userEvent.setup();
    const { nav, control } = draw();
    const brand = within(nav).getByRole("link", { name: "Wyrwood" });
    brand.focus();
    await user.keyboard("{Escape}");
    expect(brand).toHaveFocus();
    expect(control).toHaveAttribute("aria-expanded", "false");
  });

  it("leaves the menu open when Escape closes the account menu", async () => {
    const user = userEvent.setup();
    const { control, panel } = draw();
    await user.click(control);
    const account = within(panel).getByRole("button", { name: /Account/ });
    account.focus();
    await user.keyboard("{Enter}");
    expect(screen.getByRole("menu")).toContainElement(
      document.activeElement as HTMLElement,
    );
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("menuitem")).not.toBeInTheDocument();
    expect(control).toHaveAttribute("aria-expanded", "true");
    expect(account).toHaveFocus();
  });
});
