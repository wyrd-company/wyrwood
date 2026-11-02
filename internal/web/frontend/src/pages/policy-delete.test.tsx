// ---
// relationships:
//   verifies: web-interface
// ---
import { render, screen, within } from "@testing-library/react";
import { expect, it } from "vitest";
import type { BindingRow, PolicyDeleteData } from "@/types";
import { PolicyDelete } from "./policy-delete";

const confirm: PolicyDeleteData = {
  Title: "Delete policy",
  Current: "policies",
  CSRF: "sample-csrf",
  Operator: "operator@example.com",
  Pending: 0,
  OpenBaoOK: true,
  OpenBaoURL: "",
  Controller: "controller.example.com",
  Notice: "",
  Problem: "",
  Heading: "Delete policy sample?",
  Body: "This removes the policy sample and its OpenBao policy wyrwood-sample.",
  Action: "/policies/delete?name=sample",
  Button: "Delete policy",
  Danger: true,
  Back: "/policies/edit?name=sample",
  Blockers: null,
};

const notReported: BindingRow = {
  ID: "b-one",
  Agent: "host-a",
  AgentNotApproved: false,
  Connected: true,
  LastReport: new Date().toISOString(),
  KeyKind: "name",
  KeyValue: "absent-container",
  Policies: ["sample"],
  Containers: null,
  Badge: "Not reported",
  BadgeClass: "neutral",
  Screen: "/bindings/b-one",
};

const notApproved: BindingRow = {
  ...notReported,
  ID: "b-two",
  Agent: "host-b",
  AgentNotApproved: true,
  KeyValue: "pending-container",
  Screen: "/bindings/b-two",
};

const refusal: PolicyDeleteData = {
  ...confirm,
  Heading: "sample cannot be deleted",
  Body: "2 bindings select this policy.",
  Action: "",
  Button: "",
  Danger: false,
  Blockers: [notReported, notApproved],
};

it("posts the delete with the anti-forgery token and offers a way back", () => {
  render(<PolicyDelete data={confirm} />);
  expect(
    screen.getByRole("heading", { name: "Delete policy sample?" }),
  ).toBeInTheDocument();
  expect(screen.getByText(/wyrwood-sample/)).toBeInTheDocument();
  const button = screen.getByRole("button", { name: "Delete policy" });
  const form = button.closest("form") as HTMLFormElement;
  expect(form).toHaveAttribute("method", "post");
  expect(form).toHaveAttribute("action", "/policies/delete?name=sample");
  expect(new FormData(form).get("csrf")).toBe("sample-csrf");
  expect(screen.getByRole("link", { name: "Cancel" })).toHaveAttribute(
    "href",
    "/policies/edit?name=sample",
  );
  expect(screen.queryByRole("region", { name: "Bindings" })).toBeNull();
});

it("lists every blocking binding with its link and offers no delete", () => {
  render(<PolicyDelete data={refusal} />);
  expect(screen.queryByRole("button", { name: "Delete policy" })).toBeNull();
  const list = within(screen.getByRole("region", { name: "Bindings" }));
  expect(list.getAllByText("Not reported")).toHaveLength(2);
  expect(list.getByText("Agent not approved")).toBeInTheDocument();
  expect(list.getByRole("link", { name: /absent-container/ })).toHaveAttribute(
    "href",
    "/bindings/b-one",
  );
  expect(list.getByRole("link", { name: /pending-container/ })).toHaveAttribute(
    "href",
    "/bindings/b-two",
  );
  expect(screen.getByRole("link", { name: "Back" })).toHaveAttribute(
    "href",
    "/policies/edit?name=sample",
  );
});

it("shows a failure in place of the text and keeps the retry", () => {
  render(
    <PolicyDelete
      data={{ ...confirm, Problem: "OpenBao could not delete the policy" }}
    />,
  );
  expect(screen.getByRole("alert")).toHaveTextContent(
    "OpenBao could not delete the policy",
  );
  expect(
    screen.getByRole("button", { name: "Delete policy" }),
  ).toBeInTheDocument();
});
