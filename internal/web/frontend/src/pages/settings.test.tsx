// ---
// relationships:
//   verifies: web-interface
// ---
import { render, screen, within } from "@testing-library/react";
import { expect, it } from "vitest";
import { App } from "@/app";
import type { SettingsData } from "@/types";

it.each(["Enabled", "Disabled"])(
  "shows read-only settings with local agent %s",
  (localAgent) => {
    const data: SettingsData = {
      Title: "Settings",
      Current: "settings",
      CSRF: "sample-csrf",
      Operator: "operator@example.com",
      Pending: 0,
      OpenBaoOK: true,
      OpenBaoURL: "",
      Controller: "admin.example.com",
      Notice: "",
      Problem: "",
      Sections: [
        {
          Title: "Controller",
          Settings: [
            { Label: "HTTP listen address", Value: "127.0.0.1:8080" },
            { Label: "Local agent", Value: localAgent },
          ],
        },
        { Title: "OpenBao", Settings: [{ Label: "Namespace", Value: "" }] },
        {
          Title: "Update checks",
          Settings: [{ Label: "Release checks", Value: "Disabled" }],
        },
      ],
    };
    render(<App page={{ page: "settings", data }} />);
    expect(screen.getByRole("link", { name: "Settings" })).toHaveAttribute(
      "href",
      "/settings",
    );
    expect(screen.getByRole("link", { name: "Settings" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    const main = screen.getByRole("main");
    expect(within(main).getByText("127.0.0.1:8080")).toBeVisible();
    expect(
      within(main).getByText("Local agent").nextElementSibling,
    ).toHaveTextContent(localAgent);
    expect(within(main).getByText("Not configured")).toBeVisible();
    expect(within(main).getByText(/read-only/)).toBeVisible();
    expect(
      main.querySelector("form, input, textarea, select, button"),
    ).toBeNull();
  },
);
