// ---
// relationships:
//   verifies: web-interface
// ---
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { App } from "@/app";
import type { OperatorKeysData } from "@/types";

const data: OperatorKeysData = {
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
  HostKey: "SHA256:sample-host-key",
  PendingKeys: [
    {
      Label: "sample-script",
      Fingerprint: "SHA256:sample-operator-key",
      FirstSeen: new Date().toISOString(),
    },
  ],
  Approved: null,
  Ended: null,
  GrantAgents: ["agent-a", "agent-b"],
  GrantPolicies: ["policy-x", "policy-y"],
};

function setup() {
  render(<App page={{ page: "operator-keys", data }} />);
  const form = screen
    .getByRole("button", { name: "Approve key" })
    .closest("form") as HTMLFormElement;
  const agents = within(screen.getByRole("group", { name: "Agents" }));
  const policies = within(screen.getByRole("group", { name: "Policies" }));
  const actions = within(screen.getByRole("group", { name: "Actions" }));
  const summary = screen.getByRole("region", { name: "What this key can do" });
  const lines = () =>
    within(summary)
      .getAllByRole("listitem")
      .map((item) => item.querySelector(".grant-line")?.textContent);
  return { form, agents, policies, actions, summary, lines };
}

it("offers the approved agents and stored policies as choices", () => {
  const { agents, policies } = setup();
  for (const name of [
    "All agents, including agents approved later",
    "agent-a",
    "agent-b",
  ])
    expect(agents.getByRole("checkbox", { name })).not.toBeChecked();
  for (const name of [
    "All policies, including policies created later",
    "policy-x",
    "policy-y",
  ])
    expect(policies.getByRole("checkbox", { name })).not.toBeChecked();
  expect(
    agents.getByRole("textbox", { name: "Other agent names" }),
  ).toHaveValue("");
  expect(
    policies.getByRole("textbox", { name: "Other policy names" }),
  ).toHaveValue("");
});

it("posts the chosen names and updates the summary on each change", async () => {
  const user = userEvent.setup();
  const { form, agents, policies, actions, summary, lines } = setup();
  expect(summary).toHaveAttribute("aria-live", "polite");
  expect(lines()).toEqual([
    "Cannot read policies or bindings: no policy is selected.",
    "Cannot bind or unbind.",
    "Cannot change policies.",
  ]);

  await user.click(agents.getByRole("checkbox", { name: "agent-a" }));
  await user.click(policies.getByRole("checkbox", { name: "policy-x" }));
  expect(lines()).toEqual([
    "Can read policy-x, and bindings on agent-a that hold no policy other than policy-x.",
    "Cannot bind or unbind.",
    "Cannot change policies.",
  ]);

  await user.click(
    actions.getByRole("checkbox", { name: "Create and remove bindings" }),
  );
  await user.type(
    policies.getByRole("textbox", { name: "Other policy names" }),
    "future-policy",
  );
  expect(lines()[1]).toBe(
    "Can create and remove bindings on agent-a that hold no policy other than policy-x and future-policy.",
  );
  expect(summary).toHaveTextContent(
    "A grant cannot be changed after approval.",
  );
  const posted = new FormData(form);
  expect(posted.getAll("agents")).toEqual(["agent-a", ""]);
  expect(posted.getAll("policies")).toEqual(["policy-x", "future-policy"]);
  expect(posted.getAll("actions")).toEqual(["read", "bind"]);
  expect(posted.get("csrf")).toBe("sample-csrf");
  expect(posted.get("fingerprint")).toBe("SHA256:sample-operator-key");
});

it("posts * alone when all names are selected", async () => {
  const user = userEvent.setup();
  const { form, agents, policies, lines } = setup();
  await user.click(agents.getByRole("checkbox", { name: "agent-b" }));
  await user.type(
    agents.getByRole("textbox", { name: "Other agent names" }),
    "later-agent",
  );
  await user.click(
    agents.getByRole("checkbox", {
      name: "All agents, including agents approved later",
    }),
  );
  expect(agents.getByRole("checkbox", { name: "agent-b" })).toBeDisabled();
  expect(
    agents.getByRole("textbox", { name: "Other agent names" }),
  ).toBeDisabled();
  expect(new FormData(form).getAll("agents")).toEqual(["*"]);
  expect(lines()[0]).toBe(
    "Cannot read policies or bindings: no policy is selected.",
  );
  await user.click(policies.getByRole("checkbox", { name: "policy-y" }));
  expect(lines()[0]).toBe(
    "Can read policy-y, and bindings on every agent that hold no policy other than policy-y.",
  );
  await user.click(policies.getByRole("checkbox", { name: "policy-y" }));

  await user.click(
    agents.getByRole("checkbox", {
      name: "All agents, including agents approved later",
    }),
  );
  expect(agents.getByRole("checkbox", { name: "agent-b" })).toBeChecked();
  expect(new FormData(form).getAll("agents")).toEqual([
    "agent-b",
    "later-agent",
  ]);
});

it("states the refusal when no action is selected", async () => {
  const user = userEvent.setup();
  const { actions, lines } = setup();
  await user.click(
    actions.getByRole("checkbox", { name: "Read policies and bindings" }),
  );
  expect(lines()[0]).toBe("Approval is refused: select at least one action.");
});

it("says when no agent or policy can be offered", () => {
  render(
    <App
      page={{
        page: "operator-keys",
        data: { ...data, GrantAgents: null, GrantPolicies: null },
      }}
    />,
  );
  expect(screen.getByText("No agent is approved yet.")).toBeInTheDocument();
  expect(screen.getByText("No policy exists yet.")).toBeInTheDocument();
});
