// ---
// relationships:
//   verifies: web-interface
// ---
import { render, screen, within } from "@testing-library/react";
import { expect, it } from "vitest";
import type { BindingRow, PolicyData } from "@/types";
import { PolicyEditor } from "./policy-editor";

const saved: PolicyData = {
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
  Name: "sample",
  Revision: 3,
  BindingRows: [],
  Bindings: 0,
  Agents: 0,
  HCL: 'path "sample-data/*" { capabilities = ["read"] }',
  Warnings: [],
  KVMounts: [],
  AvailableTransitKeys: [],
  AvailableCARoles: [],
  IdentityProblems: [],
  TransitKeys: "",
  CARoles: "",
  NotForwardableTransitKeys: "",
  NotForwardableCARoles: "",
  MountTarget: "/run/sample",
  Env: "",
  Unpermitted: [],
  PolicyPath: "",
};

const row: BindingRow = {
  ID: "b-one",
  Agent: "host-a",
  AgentNotApproved: false,
  Connected: true,
  LastReport: new Date().toISOString(),
  KeyKind: "name",
  KeyValue: "sample",
  Policies: ["sample"],
  Containers: [
    {
      ID: "sample-id",
      Name: "sample-container",
      Image: "busybox:latest",
      State: "running",
      Screen: "/bindings/b-one?container=sample-id",
    },
  ],
  Badge: "Conforms",
  BadgeClass: "good",
  Screen: "/bindings/b-one",
};

const section = () => screen.getByRole("region", { name: "Bindings" });

it("lists a reported binding with its container, agent, key, state and link", () => {
  render(
    <PolicyEditor
      data={{ ...saved, BindingRows: [row], Bindings: 1, Agents: 1 }}
    />,
  );
  const list = within(section());
  expect(list.getByRole("link", { name: /sample-container/ })).toHaveAttribute(
    "href",
    "/bindings/b-one?container=sample-id",
  );
  expect(list.getByText("busybox:latest")).toBeInTheDocument();
  expect(list.getByText("host-a")).toBeInTheDocument();
  expect(list.getByText("Connected")).toBeInTheDocument();
  expect(list.getByText("name")).toBeInTheDocument();
  expect(list.getByText("sample")).toBeInTheDocument();
  expect(list.getByText("Conforms")).toBeInTheDocument();
});

it("marks a binding with no reported container and its disconnected agent", () => {
  render(
    <PolicyEditor
      data={{
        ...saved,
        BindingRows: [
          {
            ...row,
            Connected: false,
            Containers: null,
            Badge: "Not reported",
            BadgeClass: "neutral",
          },
        ],
        Bindings: 1,
        Agents: 1,
      }}
    />,
  );
  const list = within(section());
  expect(list.getByText("Not reported")).toBeInTheDocument();
  expect(list.getByRole("link", { name: /sample/ })).toHaveAttribute(
    "href",
    "/bindings/b-one",
  );
  expect(list.getByText(/Disconnected/)).toBeInTheDocument();
  expect(list.getByText(/Last report/)).toBeInTheDocument();
});

it("says that an agent is not approved instead of its last report", () => {
  render(
    <PolicyEditor
      data={{
        ...saved,
        BindingRows: [
          {
            ...row,
            AgentNotApproved: true,
            Connected: false,
            Containers: null,
            Badge: "Not reported",
            BadgeClass: "neutral",
          },
        ],
        Bindings: 1,
        Agents: 1,
      }}
    />,
  );
  const list = within(section());
  expect(list.getByText("Agent not approved")).toBeInTheDocument();
  expect(list.queryByText(/Last report/)).not.toBeInTheDocument();
});

it("says that no binding selects the policy", () => {
  render(<PolicyEditor data={saved} />);
  expect(
    within(section()).getByText("No binding selects this policy."),
  ).toBeInTheDocument();
});

it("shows no section for a new policy", () => {
  render(<PolicyEditor data={{ ...saved, New: true, BindingRows: null }} />);
  expect(screen.queryByRole("region", { name: "Bindings" })).toBeNull();
});

it("links the counts in the header to the list, with singular and plural", () => {
  const { unmount } = render(
    <PolicyEditor
      data={{ ...saved, BindingRows: [row], Bindings: 1, Agents: 1 }}
    />,
  );
  expect(
    screen.getByRole("link", { name: "1 binding on 1 agent" }),
  ).toHaveAttribute("href", "#h-bindings");
  unmount();
  render(<PolicyEditor data={{ ...saved, Bindings: 2, Agents: 2 }} />);
  expect(
    screen.getByRole("link", { name: "2 bindings on 2 agents" }),
  ).toBeInTheDocument();
});

it("keeps Save in the header, ahead of a list of 50 bindings", () => {
  const rows = Array.from({ length: 50 }, (_, index) => ({
    ...row,
    ID: `b-${index}`,
  }));
  render(
    <PolicyEditor
      data={{ ...saved, BindingRows: rows, Bindings: 50, Agents: 1 }}
    />,
  );
  const save = screen.getByRole("button", { name: "Save and validate" });
  expect(save.closest(".section-head")).not.toBeNull();
  const list = section();
  expect(save.closest("form")?.contains(list)).toBe(false);
  expect(
    save.compareDocumentPosition(list) & Node.DOCUMENT_POSITION_FOLLOWING,
  ).toBeTruthy();
  expect(within(list).getAllByRole("row")).toHaveLength(51);
});
