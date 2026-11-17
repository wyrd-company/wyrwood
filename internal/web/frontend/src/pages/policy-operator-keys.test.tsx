// ---
// relationships:
//   verifies: web-interface
// ---
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { App } from "@/app";
import type { PolicyData } from "@/types";

const data: PolicyData = {
  AgentTokenRenewal: true,
  Title: "Policy editor",
  Current: "policies",
  CSRF: "sample-csrf",
  Operator: "operator@example.com",
  Pending: 0,
  OpenBaoOK: true,
  OpenBaoURL: "",
  Controller: "controller.example.com",
  Notice: "",
  Problem: "",
  New: false,
  Name: "bob-secrets",
  Revision: 1,
  BindingRows: [],
  Bindings: 0,
  Agents: 0,
  HCL: 'path "kv/data/operators/bob/*" { capabilities = ["read"] }',
  Warnings: [],
  KVMounts: [],
  AvailableTransitKeys: [],
  AvailableCARoles: [],
  IdentityProblems: [],
  TransitKeys: "",
  CARoles: "",
  NotForwardableTransitKeys: "",
  NotForwardableCARoles: "",
  MountTarget: "",
  Env: "",
  Unpermitted: [],
  PolicyPath: "sys/policies/acl/wyrwood-bob-secrets",
  OperatorKeys: [
    {
      Label: "menagerie",
      Fingerprint: "SHA256:menagerie",
      Actions: ["read", "bind"],
      AllPolicies: false,
      Held: true,
      Selected: true,
    },
    {
      Label: "inventory-reader",
      Fingerprint: "SHA256:reader",
      Actions: ["read"],
      AllPolicies: false,
      Held: false,
      Selected: false,
    },
    {
      Label: "fleet-admin",
      Fingerprint: "SHA256:admin",
      Actions: ["read", "bind", "policy-write"],
      AllPolicies: true,
      Held: false,
      Selected: true,
    },
  ],
};

function setup(page: PolicyData = data) {
  render(<App page={{ page: "policy", data: page }} />);
  const form = screen
    .getByRole("button", { name: "Save and validate" })
    .closest("form") as HTMLFormElement;
  return { form };
}

it("lists each approved key with its actions on its own tab", async () => {
  const user = userEvent.setup();
  setup();
  await user.click(screen.getByRole("tab", { name: "Operator keys" }));
  const panel = within(screen.getByRole("region", { name: "Operator keys" }));
  expect(panel.getByRole("checkbox", { name: /menagerie/ })).toBeChecked();
  expect(
    panel.getByRole("checkbox", { name: /inventory-reader/ }),
  ).not.toBeChecked();
  expect(panel.getByText("Read, Bind")).toBeVisible();
  expect(panel.getByText("Read")).toBeVisible();
  const admin = panel.getByRole("checkbox", { name: /fleet-admin/ });
  expect(admin).toBeChecked();
  expect(admin).toBeDisabled();
  expect(
    panel.getByText("Read, Bind, Policy write · All policies"),
  ).toBeVisible();
});

it("posts which keys it listed and held, and which are checked", async () => {
  const user = userEvent.setup();
  const { form } = setup();
  await user.click(screen.getByRole("tab", { name: "Operator keys" }));
  const panel = within(screen.getByRole("region", { name: "Operator keys" }));
  await user.click(panel.getByRole("checkbox", { name: /menagerie/ }));
  await user.click(panel.getByRole("checkbox", { name: /inventory-reader/ }));
  const posted = new FormData(form);
  expect(posted.getAll("operator-keys-listed")).toEqual([
    "SHA256:menagerie",
    "SHA256:reader",
  ]);
  expect(posted.getAll("operator-keys-held")).toEqual(["SHA256:menagerie"]);
  expect(posted.getAll("operator-keys")).toEqual(["SHA256:reader"]);
});

it("offers the keys when a policy is created", async () => {
  const user = userEvent.setup();
  setup({
    ...data,
    New: true,
    Name: "",
    BindingRows: null,
    OperatorKeys: data.OperatorKeys!.map((key) => ({
      ...key,
      Held: false,
      Selected: key.AllPolicies,
    })),
  });
  expect(screen.queryByRole("tab", { name: "Bindings" })).toBeNull();
  await user.click(screen.getByRole("tab", { name: "Operator keys" }));
  expect(screen.getByRole("checkbox", { name: /menagerie/ })).not.toBeChecked();
});

it("says when no operator key is approved", async () => {
  const user = userEvent.setup();
  setup({ ...data, OperatorKeys: [] });
  await user.click(screen.getByRole("tab", { name: "Operator keys" }));
  expect(screen.getByText("No operator key is approved.")).toBeVisible();
});
