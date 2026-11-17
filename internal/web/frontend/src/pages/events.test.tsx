// ---
// relationships:
//   verifies: web-interface
// ---
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { App } from "@/app";
import type { EventsData } from "@/types";

const data: EventsData = {
  Title: "Events",
  Current: "events",
  CSRF: "sample-csrf",
  Operator: "operator@example.com",
  Pending: 0,
  OpenBaoOK: true,
  OpenBaoURL: "",
  Controller: "controller.example.com",
  Notice: "",
  Problem: "",
  Outcome: "",
  Outcomes: ["ok", "denied", "failed", "timeout"],
  Events: [
    {
      Time: "2026-11-17T06:50:01.263Z",
      Operation: "operator-key-grant-changed",
      Outcome: "ok",
      Error: "",
      Class: "good",
      Subject: "key:menagerie",
      Operator: "operator@example.com",
      Latency: "0s",
      Grant: {
        Fingerprint: "SHA256:sample-operator-key",
        EditURL:
          "/operator-keys/grant?fingerprint=SHA256%3Asample-operator-key",
        Complete: true,
        Rows: [
          { Name: "Agents", Before: "tools", After: "tools", Changed: false },
          {
            Name: "Policies",
            Before: "shared-key",
            After: "bob-secrets, shared-key",
            Changed: true,
          },
          { Name: "Read", Before: "Allowed", After: "Allowed", Changed: false },
          { Name: "Bind", Before: "Allowed", After: "Allowed", Changed: false },
          {
            Name: "Policy write",
            Before: "Denied",
            After: "Denied",
            Changed: false,
          },
        ],
      },
    },
    {
      Time: "2026-11-17T06:49:00Z",
      Operation: "policy-saved",
      Outcome: "ok",
      Error: "",
      Class: "good",
      Subject: "bob-secrets",
      Operator: "operator@example.com",
      Latency: "3ms",
    },
  ],
};

it("shows a grant edit as one row with its old and new grant", async () => {
  const user = userEvent.setup();
  render(<App page={{ page: "events", data }} />);
  expect(screen.getAllByText("operator-key-grant-changed")).toHaveLength(1);
  await user.click(screen.getByText("Old and new grant"));
  const table = screen.getByRole("table", {
    name: "Old and new grant of key:menagerie",
  });
  const policies = within(table).getByRole("row", { name: /^Policies/ });
  expect(policies).toHaveTextContent(
    "Policiesshared-keybob-secrets, shared-key · Changed",
  );
  expect(
    within(table).getByRole("row", { name: /^Read/ }),
  ).not.toHaveTextContent("Changed");
  expect(
    screen.getByRole("link", { name: "View current key grant" }),
  ).toHaveAttribute(
    "href",
    "/operator-keys/grant?fingerprint=SHA256%3Asample-operator-key",
  );
  expect(screen.getByText("SHA256:sample-operator-key")).toBeVisible();
});

it("leaves other events as they were", () => {
  render(<App page={{ page: "events", data }} />);
  expect(screen.getAllByText("Old and new grant")).toHaveLength(1);
});

it("shows no grant for an edit the history no longer holds whole", async () => {
  const user = userEvent.setup();
  const first = data.Events![0];
  render(
    <App
      page={{
        page: "events",
        data: {
          ...data,
          Events: [
            {
              ...first,
              Grant: { ...first.Grant!, Complete: false, Rows: null },
            },
          ],
        },
      }}
    />,
  );
  await user.click(screen.getByText("Old and new grant"));
  expect(
    screen.getByText(
      "Part of this edit is no longer in the event history, so its old and new grant are not shown.",
    ),
  ).toBeVisible();
  expect(
    screen.queryByRole("table", { name: /Old and new grant of/ }),
  ).toBeNull();
});
