// ---
// relationships:
//   verifies: web-interface
// ---
import { render, screen, within } from "@testing-library/react";
import { expect, test } from "vitest";
import type { BindingRow, PolicyRenameData } from "@/types";
import { PolicyRename } from "./policy-rename";

const page: PolicyRenameData = {
  Title: "Rename policy",
  Current: "policies",
  CSRF: "token",
  Operator: "operator@example.com",
  Pending: 0,
  OpenBaoOK: true,
  OpenBaoURL: "",
  Controller: "controller.example.com",
  Notice: "",
  Name: "sample",
  NewName: "sample",
  Revision: 3,
  Generation: 2,
  Identity: "wyrwood-sample--2",
  Consequence: "No binding selects this policy.",
  Action: "/policies/rename?name=sample",
  Back: "/policies/edit?name=sample",
  Problem: "",
  Bindings: null,
};

const row: BindingRow = {
  ID: "b-one",
  Agent: "host-a",
  AgentNotApproved: false,
  Connected: true,
  LastReport: new Date().toISOString(),
  KeyKind: "name",
  KeyValue: "sample-container",
  Policies: ["sample"],
  Containers: null,
  Badge: "Not reported",
  BadgeClass: "neutral",
  Screen: "/bindings/b-one",
};

test("takes the new name and binds the request to what the page shows", () => {
  const { container } = render(<PolicyRename data={page} />);
  expect(
    screen.getByRole("heading", { name: "Rename policy sample" }),
  ).toBeVisible();
  const field = screen.getByLabelText("New name");
  expect(field).toHaveValue("sample");
  expect(field).toHaveAttribute("name", "new-name");
  expect(field).toBeRequired();
  const form = container.querySelector("form");
  expect(form).toHaveAttribute("action", "/policies/rename?name=sample");
  expect(form).toHaveAttribute("method", "post");
  expect(form?.querySelector('input[name="csrf"]')).toHaveValue("token");
  expect(form?.querySelector('input[name="revision"]')).toHaveValue("3");
  expect(form?.querySelector('input[name="generation"]')).toHaveValue("2");
  expect(screen.getByRole("button", { name: "Rename policy" })).toBeVisible();
  expect(screen.getByRole("link", { name: "Cancel" })).toHaveAttribute(
    "href",
    "/policies/edit?name=sample",
  );
  expect(screen.getByText("wyrwood-sample--2")).toBeVisible();
  expect(screen.queryByRole("alert")).toBeNull();
  expect(screen.queryByRole("heading", { name: "Bindings" })).toBeNull();
});

test("states the consequence and lists each affected binding", () => {
  render(
    <PolicyRename
      data={{
        ...page,
        Consequence:
          "1 binding selects this policy. It gets a fresh credential.",
        Bindings: [row],
      }}
    />,
  );
  expect(screen.getByText(/It gets a fresh credential/)).toBeVisible();
  const table = screen.getByRole("table");
  expect(
    within(table).getByRole("link", { name: /sample-container/ }),
  ).toBeVisible();
});

test("keeps the reason and what the operator typed", () => {
  render(
    <PolicyRename
      data={{
        ...page,
        Problem: "the name other is already in use",
        NewName: "other",
      }}
    />,
  );
  expect(screen.getByRole("alert")).toHaveTextContent("already in use");
  expect(screen.getByLabelText("New name")).toHaveValue("other");
});
