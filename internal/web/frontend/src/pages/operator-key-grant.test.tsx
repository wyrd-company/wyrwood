// ---
// relationships:
//   verifies: web-interface
// ---
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { App } from "@/app";
import type { OperatorKeyGrantData } from "@/types";

const data: OperatorKeyGrantData = {
  Title: "Operator keys",
  Current: "operator-keys",
  CSRF: "sample-csrf",
  Operator: "operator@example.com",
  Pending: 0,
  OpenBaoOK: true,
  OpenBaoURL: "",
  Controller: "controller.example.com",
  Notice: "",
  Problem: "",
  Label: "menagerie",
  Fingerprint: "SHA256:sample-operator-key",
  Grant: {
    agents: ["tools"],
    policies: ["shared-key", "later-policy"],
    actions: ["read", "bind"],
  },
  Previous:
    '{"agents":["tools"],"policies":["shared-key","later-policy"],"actions":["read","bind"]}',
  GrantAgents: ["build-host", "tools"],
  GrantPolicies: ["bob-secrets", "shared-key", "teal"],
};

function setup(page: OperatorKeyGrantData = data) {
  render(<App page={{ page: "operator-key-grant", data: page }} />);
  const form = screen
    .getByRole("button", { name: "Save" })
    .closest("form") as HTMLFormElement;
  const agents = within(screen.getByRole("group", { name: "Agents" }));
  const policies = within(screen.getByRole("group", { name: "Policies" }));
  const actions = within(screen.getByRole("group", { name: "Actions" }));
  const summary = screen.getByRole("region", { name: "What this key can do" });
  return { form, agents, policies, actions, summary };
}

it("shows the key and starts from the grant it holds", () => {
  const { form, agents, policies, actions } = setup();
  expect(screen.getByRole("heading", { name: "menagerie" })).toBeVisible();
  expect(screen.getByText("Approved")).toBeVisible();
  expect(screen.getByText("SHA256:sample-operator-key")).toBeVisible();
  expect(screen.getByRole("link", { name: "← Operator keys" })).toHaveAttribute(
    "href",
    "/operator-keys",
  );
  expect(agents.getByRole("checkbox", { name: "tools" })).toBeChecked();
  expect(
    agents.getByRole("checkbox", { name: "build-host" }),
  ).not.toBeChecked();
  expect(policies.getByRole("checkbox", { name: "shared-key" })).toBeChecked();
  expect(policies.getByRole("checkbox", { name: "teal" })).not.toBeChecked();
  expect(
    policies.getByRole("textbox", { name: "Other policy names" }),
  ).toHaveValue("later-policy");
  expect(actions.getByRole("checkbox", { name: "Read" })).toBeChecked();
  expect(actions.getByRole("checkbox", { name: "Bind" })).toBeChecked();
  expect(
    actions.getByRole("checkbox", { name: "Policy write" }),
  ).not.toBeChecked();
  const posted = new FormData(form);
  expect(posted.get("fingerprint")).toBe("SHA256:sample-operator-key");
  expect(posted.get("previous")).toBe(data.Previous);
  expect(posted.get("csrf")).toBe("sample-csrf");
  expect(posted.getAll("policies")).toEqual(["shared-key", "later-policy"]);
  expect(posted.getAll("actions")).toEqual(["read", "bind"]);
  expect(
    screen.getAllByRole("button").map((button) => button.textContent),
  ).toEqual(expect.arrayContaining(["Validate", "Save"]));
  expect(screen.queryByRole("button", { name: /review|cancel/i })).toBeNull();
});

it("updates what the key can do on each change and posts the edit", async () => {
  const user = userEvent.setup();
  const { form, policies, actions, summary } = setup();
  await user.click(policies.getByRole("checkbox", { name: "bob-secrets" }));
  await user.click(actions.getByRole("checkbox", { name: "Policy write" }));
  expect(summary).toHaveTextContent(
    "Can read bob-secrets, shared-key, and later-policy, and bindings on tools that hold no policy other than bob-secrets, shared-key, and later-policy.",
  );
  expect(summary).toHaveTextContent("Can create and change bob-secrets");
  const posted = new FormData(form);
  expect(posted.getAll("policies")).toEqual([
    "bob-secrets",
    "shared-key",
    "later-policy",
  ]);
  expect(posted.getAll("actions")).toEqual(["read", "bind", "policy-write"]);
});

it("starts with all policies selected for a key that holds them all", () => {
  const { form, policies } = setup({
    ...data,
    Grant: { agents: ["*"], policies: ["*"], actions: ["read"] },
  });
  expect(
    policies.getByRole("checkbox", {
      name: "All policies, including policies created later",
    }),
  ).toBeChecked();
  expect(policies.getByRole("checkbox", { name: "teal" })).toBeDisabled();
  const posted = new FormData(form);
  expect(posted.getAll("agents")).toEqual(["*"]);
  expect(posted.getAll("policies")).toEqual(["*"]);
});

it("validates without saving", async () => {
  const user = userEvent.setup();
  const { actions } = setup();
  let submitted = false;
  screen
    .getByRole("button", { name: "Save" })
    .closest("form")
    ?.addEventListener("submit", (event) => {
      submitted = true;
      event.preventDefault();
    });
  await user.click(screen.getByRole("button", { name: "Validate" }));
  expect(screen.getByRole("status")).toHaveTextContent("Valid grant.");

  await user.click(actions.getByRole("checkbox", { name: "Read" }));
  expect(screen.queryByText("Valid grant.")).toBeNull();
  await user.click(actions.getByRole("checkbox", { name: "Bind" }));
  await user.click(screen.getByRole("button", { name: "Validate" }));
  expect(screen.getByRole("alert")).toHaveTextContent(
    "Not valid: select at least one action.",
  );
  expect(submitted).toBe(false);
});

it("shows a refused save with the edit kept", () => {
  setup({
    ...data,
    Problem:
      "this key's grant changed after you opened it. Reload to see the grant it holds now",
    Grant: { agents: ["tools"], policies: ["teal"], actions: ["read"] },
  });
  expect(screen.getByRole("alert")).toHaveTextContent(
    "this key's grant changed after you opened it",
  );
  expect(
    within(screen.getByRole("group", { name: "Policies" })).getByRole(
      "checkbox",
      { name: "teal" },
    ),
  ).toBeChecked();
});
