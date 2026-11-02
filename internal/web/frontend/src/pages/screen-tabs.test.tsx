// ---
// relationships:
//   verifies: web-interface
// ---
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AddBinding } from "./add-binding";
import { Binding } from "./binding";
import { Bindings } from "./bindings";
import { PolicyBindings } from "./policy-bindings";
import { PolicyEditor } from "./policy-editor";
import { ScreenTabs, useScreenTabs } from "@/components/screen-tabs";
import type {
  AddBindingData,
  BindingData,
  BindingRow,
  BindingsData,
  ContainerRow,
  Layout,
  PolicyData,
} from "@/types";

const layout: Layout = {
  Title: "Sample",
  Current: "bindings",
  CSRF: "sample-csrf",
  Operator: "operator@example.com",
  Pending: 0,
  OpenBaoOK: true,
  OpenBaoURL: "",
  Controller: "controller.example.com",
  Notice: "",
  Problem: "",
};
const container: ContainerRow = {
  Screen: "/bindings/new?agent=sample-host&container=sample-id&q=kept",
  Agent: "sample-host",
  Connected: true,
  LastReport: "2026-01-01T00:00:00Z",
  ID: "sample-id",
  Name: "sample-container",
  Image: "alpine:latest",
  State: "running",
  KeyKind: "name",
  KeyValue: "sample-container",
  Policies: ["first"],
  Revision: 3,
  Applied: true,
  Warnings: [],
  Settings: { "token-ttl": "1h", "token-max-ttl": "8h", enforcement: "report" },
  Effective: {
    sources: [{ name: "first", revision: 1, hcl: "sample HCL" }],
    openbao: { policy: "saved combined HCL" },
    contract: { "mount-target": "/run/sample", enforcement: "report" },
    settings: {
      "token-ttl": "1h",
      "token-max-ttl": "8h",
      enforcement: "report",
    },
  },
  Badge: "Conforms",
  BadgeClass: "good",
  Bound: true,
  BindingID: "sample-binding",
  Token: "sample token state",
  Checks: [{ Label: "sample check", Mark: "OK", Status: "good" }],
  Candidates: [
    {
      Kind: "name",
      Value: "sample-container",
      Encoded: "name:sample-container",
      Note: "less stable",
    },
    {
      Kind: "compose",
      Value: "sample/service",
      Encoded: "compose:sample/service",
      Note: "most stable",
    },
  ],
  AssignableGroups: {
    any: true,
    groups: [{ gid: 100, name: "sample-group" }],
  },
  Setup: {
    Source: "/sample/source",
    Target: "/run/sample",
    Compose: "sample compose",
    DockerRun: "sample run",
  },
} as ContainerRow;

function binding(bound: boolean, overrides: Partial<BindingData> = {}) {
  return {
    ...layout,
    Row: { ...container, Bound: bound },
    Reported: true,
    Policies: [
      { Name: "first", Selected: bound },
      { Name: "second", Selected: false },
    ],
    Form: {
      Key: bound ? "" : "name:sample-container",
      Revision: 3,
      Understood: false,
      Settings: {
        "token-ttl": "1h",
        "token-max-ttl": "8h",
        "access-group": "",
        enforcement: "report",
      },
    },
    Screen: "/bindings/sample-binding?q=kept",
    Action: bound
      ? "/bindings/sample-binding/policy?q=kept"
      : "/bindings?q=kept",
    Recreate: "/bindings/sample-binding/recreate?q=kept",
    Unbind: "/bindings/sample-binding/unbind?q=kept",
    Back: "/bindings?q=kept",
    ...overrides,
  } as BindingData;
}
const row: BindingRow = {
  ID: "sample-binding",
  Agent: "sample-host",
  AgentNotApproved: false,
  Connected: true,
  LastReport: "2026-01-01T00:00:00Z",
  KeyKind: "compose",
  KeyValue: "sample/service",
  Policies: ["first"],
  Containers: [
    {
      ID: "sample-id",
      Name: "sample-container",
      Image: "alpine:latest",
      State: "running",
      Screen: "/bindings/sample-binding?container=sample-id&q=kept",
    },
  ],
  Badge: "Conforms",
  BadgeClass: "good",
  Screen: "/bindings/sample-binding?q=kept",
};
const policy: PolicyData = {
  ...layout,
  Current: "policies",
  AgentTokenRenewal: true,
  KVMounts: ["sample-kv"],
  AvailableTransitKeys: ["sample-key"],
  AvailableCARoles: ["sample-role"],
  IdentityProblems: [],
  Warnings: [],
  New: false,
  Name: "sample",
  Revision: 2,
  BindingRows: [row],
  Bindings: 1,
  Agents: 1,
  HCL: 'path "sample/*" {\n  capabilities = ["read"]\n}\n',
  TransitKeys: "",
  CARoles: "",
  NotForwardableTransitKeys: "",
  NotForwardableCARoles: "",
  MountTarget: "/run/sample",
  Env: "SAMPLE=value",
  Unpermitted: [],
  PolicyPath: "sys/policies/acl/sample",
};
function list() {
  return {
    ...layout,
    Agents: [{ Name: "sample-host", Count: 1, Selected: false }],
    FilterAgent: "",
    Query: "",
    Sort: "name",
    Order: "asc",
  };
}

const tabNames = () => screen.getAllByRole("tab").map((tab) => tab.textContent);
const selected = () => screen.getByRole("tab", { selected: true }).textContent;
const tab = (name: RegExp | string) => screen.getByRole("tab", { name });
const fieldNames = (form: HTMLFormElement) =>
  [...new Set(new FormData(form).keys())].sort();
const formOf = (name: string) =>
  screen.getByRole("button", { name }).closest("form")!;

afterEach(() => {
  window.location.hash = "";
  vi.unstubAllGlobals();
});

describe("row actions", () => {
  const states: [string, BindingRow, string][] = [
    [
      "one reported container",
      row,
      "Edit binding for sample-container on sample-host",
    ],
    [
      "several reported containers",
      {
        ...row,
        Containers: [
          row.Containers![0],
          { ...row.Containers![0], ID: "other-id", Name: "other-container" },
        ],
      },
      "Edit binding sample/service on sample-host",
    ],
    [
      "no reported container",
      { ...row, Containers: null },
      "Edit binding sample/service on sample-host",
    ],
    [
      "a disconnected agent",
      { ...row, Connected: false },
      "Edit binding for sample-container on sample-host",
    ],
    [
      "an agent that is not approved",
      { ...row, AgentNotApproved: true, Connected: false },
      "Edit binding for sample-container on sample-host",
    ],
  ];
  it.each(states)("offers Edit on a row with %s", (_, state, name) => {
    const data = {
      ...list(),
      Add: "/bindings/add",
      Rows: [state],
    } as BindingsData;
    render(<Bindings data={data} />);
    expect(
      screen.getByRole("columnheader", { name: "Actions" }),
    ).toBeInTheDocument();
    const action = screen.getByRole("link", { name });
    expect(action).toHaveAttribute("href", state.Screen);
    expect(action).toHaveTextContent(/^Edit$/);
    expect(action.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
  });

  it.each(states)(
    "offers Edit on a policy page row with %s",
    (_, state, name) => {
      render(
        <PolicyEditor
          data={{ ...policy, Tab: "bindings", BindingRows: [state] }}
        />,
      );
      expect(screen.getByRole("link", { name })).toHaveAttribute(
        "href",
        state.Screen,
      );
    },
  );

  it("gives two rows in one table different names and keeps the container links", () => {
    const other = {
      ...row,
      ID: "other-binding",
      Screen: "/bindings/other-binding",
      Containers: [
        {
          ...row.Containers![0],
          Name: "other-container",
          Screen: "/bindings/other-binding?container=sample-id",
        },
      ],
    };
    const data = {
      ...list(),
      Add: "/bindings/add",
      Rows: [row, other],
    } as BindingsData;
    render(<Bindings data={data} />);
    const actions = screen.getAllByRole("link", { name: /^Edit binding/ });
    expect(new Set(actions.map((a) => a.getAttribute("aria-label"))).size).toBe(
      2,
    );
    expect(
      screen.getByRole("link", { name: /^sample-container/ }),
    ).toHaveAttribute("href", row.Containers![0].Screen);
  });

  it("keeps one container link per container on a row with several", () => {
    const several = {
      ...row,
      Containers: [
        row.Containers![0],
        {
          ...row.Containers![0],
          ID: "other-id",
          Name: "other-container",
          Screen: "/bindings/sample-binding?container=other-id",
        },
      ],
    };
    render(
      <Bindings
        data={{ ...list(), Add: "/a", Rows: [several] } as BindingsData}
      />,
    );
    expect(
      screen.getByRole("link", { name: /^other-container/ }),
    ).toHaveAttribute("href", "/bindings/sample-binding?container=other-id");
    expect(
      screen.getByRole("link", { name: /^sample-container/ }),
    ).toHaveAttribute("href", row.Containers![0].Screen);
  });

  it.each([
    ["a connected agent", { Connected: true }],
    ["a disconnected agent", { Connected: false }],
  ])("offers Add binding on an inventory row with %s", (_, state) => {
    const data = {
      ...list(),
      Back: "/bindings",
      Rows: [{ ...container, Bound: false, ...state }],
    } as AddBindingData;
    render(<AddBinding data={data} />);
    const action = screen.getByRole("link", {
      name: "Add binding for sample-container on sample-host",
    });
    expect(action).toHaveAttribute("href", container.Screen);
    expect(action).toHaveTextContent(/^Add binding$/);
    expect(action.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
  });

  it("adds no action to the rename and delete screens' rows", () => {
    render(<PolicyBindings rows={[row]} hint="sample" />);
    expect(screen.queryByRole("columnheader", { name: "Actions" })).toBeNull();
    expect(document.querySelector(".row-action")).toBeNull();
  });

  it("reaches the action with Tab", async () => {
    const data = {
      ...list(),
      Add: "/bindings/add",
      Rows: [row],
    } as BindingsData;
    render(<Bindings data={data} />);
    const user = userEvent.setup();
    const action = screen.getByRole("link", { name: /^Edit binding/ });
    for (let step = 0; step < 20 && document.activeElement !== action; step++)
      await user.tab();
    expect(action).toHaveFocus();
  });
});

describe("tab structure", () => {
  it("has the required tabs on each screen", () => {
    const first = render(<PolicyEditor data={{ ...policy, New: true }} />);
    expect(tabNames()).toEqual([
      "OpenBao policy",
      "SSH identities",
      "Container contract",
    ]);
    first.unmount();
    const second = render(<PolicyEditor data={policy} />);
    expect(tabNames()).toEqual([
      "OpenBao policy",
      "SSH identities",
      "Container contract",
      "Bindings",
    ]);
    second.unmount();
    const third = render(<Binding data={binding(false)} />);
    expect(tabNames()).toEqual([
      "Key and policies",
      "Settings",
      "Effective policy",
    ]);
    third.unmount();
    const fourth = render(<Binding data={binding(true)} />);
    expect(tabNames()).toEqual([
      "Status",
      "Policies",
      "Settings",
      "Effective policy",
      "Container setup",
    ]);
    fourth.unmount();
    render(<Binding data={binding(true, { Reported: false })} />);
    expect(tabNames()).toEqual([
      "Status",
      "Policies",
      "Settings",
      "Effective policy",
    ]);
    expect(screen.queryByText("Contract check")).toBeNull();
  });

  it("has no tabs when no policy exists to bind", () => {
    render(<Binding data={binding(false, { Policies: [] })} />);
    expect(screen.queryByRole("tablist")).toBeNull();
    expect(
      screen.getByRole("link", { name: "New policy" }),
    ).toBeInTheDocument();
  });

  it("keeps inactive panels mounted and hidden", () => {
    render(<PolicyEditor data={policy} />);
    const panels = document.querySelectorAll<HTMLElement>("[role=tabpanel]");
    expect(panels).toHaveLength(4);
    expect([...panels].map((panel) => panel.hidden)).toEqual([
      false,
      true,
      true,
      true,
    ]);
    expect(screen.getAllByRole("tabpanel")).toHaveLength(1);
    expect(document.querySelector("input[name=mount-target]")).not.toBeNull();
    expect(
      document.querySelector("input[name=mount-target]"),
    ).not.toBeVisible();
  });

  it("follows the tabs pattern with the keyboard", async () => {
    const user = userEvent.setup();
    render(<Binding data={binding(true)} />);
    const status = tab("Status");
    const list = screen.getByRole("tablist");
    expect(status).toHaveAttribute("aria-selected", "true");
    const panel = document.getElementById(
      status.getAttribute("aria-controls")!,
    )!;
    expect(panel).toHaveAttribute("role", "tabpanel");
    expect(panel).toHaveAttribute("aria-labelledby", status.id);
    expect(list).toHaveAttribute("aria-label", "Binding sections");
    status.focus();
    await user.keyboard("{ArrowRight}");
    expect(tab("Policies")).toHaveFocus();
    expect(selected()).toBe("Policies");
    expect(tab("Policies")).toHaveAttribute("tabindex", "0");
    expect(tab("Status")).toHaveAttribute("tabindex", "-1");
    await user.keyboard("{End}");
    expect(tab("Container setup")).toHaveFocus();
    expect(selected()).toBe("Container setup");
    await user.keyboard("{ArrowRight}");
    expect(tab("Status")).toHaveFocus();
    await user.keyboard("{ArrowLeft}");
    expect(tab("Container setup")).toHaveFocus();
    await user.keyboard("{Home}");
    expect(tab("Status")).toHaveFocus();
    expect(selected()).toBe("Status");
  });

  it.each([
    ["New policy", { ...policy, New: true }, "Save and validate"],
    ["Saved policy", policy, "Save and validate"],
  ])("posts the base fields of %s from every tab", async (_, data, button) => {
    const user = userEvent.setup();
    render(<PolicyEditor data={data as PolicyData} />);
    const expected = data.New
      ? [
          "agent-token-renewal",
          "ca-roles",
          "csrf",
          "env",
          "hcl",
          "mount-target",
          "name",
          "new",
          "not-forwardable-ca-roles",
          "not-forwardable-transit-keys",
          "transit-keys",
        ]
      : [
          "agent-token-renewal",
          "ca-roles",
          "csrf",
          "env",
          "hcl",
          "mount-target",
          "name",
          "not-forwardable-ca-roles",
          "not-forwardable-transit-keys",
          "transit-keys",
        ];
    for (const item of screen.getAllByRole("tab")) {
      await user.click(item);
      expect(fieldNames(formOf(button))).toEqual(expected);
    }
  });

  it.each([
    [
      "POST /bindings",
      false,
      "Bind policies",
      [
        "access-group",
        "agent",
        "container",
        "csrf",
        "enforcement",
        "key",
        "revision",
        "token-max-ttl",
        "token-ttl",
      ],
    ],
    [
      "POST /bindings/{id}/policy",
      true,
      "Save binding",
      [
        "access-group",
        "agent",
        "container",
        "csrf",
        "enforcement",
        "policies",
        "revision",
        "token-max-ttl",
        "token-ttl",
      ],
    ],
  ])(
    "posts the base fields of %s from every tab",
    async (_, bound, button, expected) => {
      const user = userEvent.setup();
      render(<Binding data={binding(bound)} />);
      for (const item of screen.getAllByRole("tab")) {
        await user.click(item);
        expect(fieldNames(formOf(button))).toEqual(expected);
      }
    },
  );

  it("sends the same fields to the preview from a hidden settings tab", async () => {
    const fetcher = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ effective: container.Effective, warnings: [] }),
    });
    vi.stubGlobal("fetch", fetcher);
    const user = userEvent.setup();
    render(<Binding data={binding(false)} />);
    await user.click(
      screen.getByRole("button", { name: "Preview effective policy" }),
    );
    const body: URLSearchParams = fetcher.mock.calls[0][1].body;
    expect([...new Set(body.keys())].sort()).toEqual(
      fieldNames(formOf("Bind policies")),
    );
    expect(body.get("token-ttl")).toBe("1h");
    expect(await screen.findByText("saved combined HCL")).toBeInTheDocument();
    expect(selected()).toBe("Effective policy");
  });

  it("shows a preview failure on the effective policy tab", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        json: async () => ({ error: "sample preview refusal" }),
      }),
    );
    const user = userEvent.setup();
    render(<Binding data={binding(false)} />);
    await user.click(
      screen.getByRole("button", { name: "Preview effective policy" }),
    );
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("sample preview refusal");
    expect(alert).toBeVisible();
    expect(selected()).toBe("Effective policy");
  });
});

describe("values across tabs", () => {
  it("keeps raw HCL, graphical HCL, environment rows and KV browser state", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ warnings: [], Paths: ["sample-folder/"] }),
      }),
    );
    const user = userEvent.setup();
    render(<PolicyEditor data={policy} />);
    const save = () => formOf("Save and validate");
    await user.click(screen.getByRole("button", { name: "Raw HCL" }));
    const raw = screen.getByLabelText("OpenBao policy HCL");
    await user.clear(raw);
    await user.type(raw, "raw sample");
    await user.click(tab("Bindings"));
    await user.click(tab("OpenBao policy"));
    expect(screen.getByLabelText("OpenBao policy HCL")).toHaveValue(
      "raw sample",
    );
    expect(new FormData(save()).get("hcl")).toBe("raw sample");
    await user.click(tab("Container contract"));
    await user.clear(screen.getByLabelText("Mount target"));
    await user.type(screen.getByLabelText("Mount target"), "/run/other");
    await user.click(tab("SSH identities"));
    await user.click(tab("Container contract"));
    expect(screen.getByLabelText("Mount target")).toHaveValue("/run/other");
    expect(new FormData(save()).get("env")).toBe("SAMPLE=value");
    expect(new FormData(save()).get("mount-target")).toBe("/run/other");
  });

  it("keeps graphical HCL edits and the KV browser's place", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ warnings: [], Paths: ["sample-folder/"] }),
      }),
    );
    const user = userEvent.setup();
    render(<PolicyEditor data={policy} />);
    const save = () => formOf("Save and validate");
    await user.click(screen.getByRole("checkbox", { name: /update/ }));
    const edited = new FormData(save()).get("hcl");
    expect(edited).toContain("update");
    const folder = await screen.findByRole("button", {
      name: "Open sample-folder/",
    });
    await user.click(folder);
    const place = "sample-kv/sample-folder/";
    expect(screen.getByText(place)).toBeVisible();
    await user.click(tab("SSH identities"));
    await user.click(tab(/^OpenBao policy/));
    expect(new FormData(save()).get("hcl")).toBe(edited);
    expect(screen.getByText(place)).toBeVisible();
  });

  it("keeps environment rows added on the contract tab", async () => {
    const user = userEvent.setup();
    render(<PolicyEditor data={policy} />);
    await user.click(tab("Container contract"));
    await user.click(screen.getByRole("button", { name: "Add variable" }));
    await user.click(tab("Bindings"));
    await user.click(tab("Container contract"));
    expect(
      screen.getByRole("button", { name: "Remove variable 2" }),
    ).toBeVisible();
  });

  it("keeps durations, a custom numeric group and selections", async () => {
    const user = userEvent.setup();
    render(<Binding data={binding(true)} />);
    const save = () => formOf("Save binding");
    await user.click(tab("Settings"));
    const ttl = screen.getByLabelText("Token time-to-live");
    await user.clear(ttl);
    await user.type(ttl, "20");
    await user.selectOptions(screen.getByLabelText("token-ttl unit"), "m");
    await user.selectOptions(screen.getByLabelText("Access group"), "custom");
    await user.type(screen.getByLabelText("Numeric access group"), "4321");
    await user.click(tab("Policies"));
    await user.click(screen.getByRole("checkbox", { name: "second" }));
    await user.click(tab("Status"));
    await user.click(tab("Settings"));
    expect(screen.getByLabelText("Token time-to-live")).toHaveValue(20);
    expect(screen.getByLabelText("Numeric access group")).toHaveValue("4321");
    const values = new FormData(save());
    expect(values.get("token-ttl")).toBe("20m");
    expect(values.get("access-group")).toBe("4321");
    expect(values.getAll("policies")).toEqual(["first", "second"]);
  });
});

describe("selected tab", () => {
  it("names a tab in the form action only when it is not the first", async () => {
    const user = userEvent.setup();
    render(<Binding data={binding(true)} />);
    expect(formOf("Save binding")).toHaveAttribute(
      "action",
      "/bindings/sample-binding/policy?q=kept",
    );
    await user.click(tab("Settings"));
    expect(formOf("Save binding")).toHaveAttribute(
      "action",
      "/bindings/sample-binding/policy?q=kept&tab=settings",
    );
    expect(
      screen.getByRole("link", { name: "Request recreate" }),
    ).toHaveAttribute(
      "href",
      "/bindings/sample-binding/recreate?q=kept&tab=settings",
    );
    expect(
      screen.getByRole("link", { name: "Unbind and revoke AppRole" }),
    ).toHaveAttribute(
      "href",
      "/bindings/sample-binding/unbind?q=kept&tab=settings",
    );
  });

  it("names the tab in the policy form action", async () => {
    const user = userEvent.setup();
    render(<PolicyEditor data={policy} />);
    expect(formOf("Save and validate")).toHaveAttribute("action", "/policies");
    await user.click(tab("Container contract"));
    expect(formOf("Save and validate")).toHaveAttribute(
      "action",
      "/policies?tab=container-contract",
    );
  });

  it("selects the tab the page names", () => {
    render(<Binding data={binding(true, { Tab: "container-setup" })} />);
    expect(selected()).toBe("Container setup");
  });

  it.each([
    ["a value no screen has", binding(true, { Tab: "other" })],
    ["a value of another screen", binding(true, { Tab: "key-and-policies" })],
    [
      "setup when the container is not reported",
      binding(true, { Tab: "container-setup", Reported: false }),
    ],
  ])("falls back to the first tab on %s", (_, data) => {
    render(<Binding data={data} />);
    expect(selected()).toBe("Status");
  });

  it("prefers the tab that owns a problem to the submitted tab", () => {
    render(
      <Binding
        data={binding(true, {
          Problem: "sample settings refusal",
          Tab: "policies",
          ProblemTab: "settings",
        })}
      />,
    );
    expect(selected()).toBe("Settings");
    expect(screen.getByRole("alert")).toHaveTextContent(
      "sample settings refusal",
    );
    expect(screen.getByRole("alert").closest("[role=tabpanel]")).toBeNull();
  });

  it("keeps the submitted tab for a problem with no owner", () => {
    render(
      <Binding
        data={binding(true, { Problem: "sample conflict", Tab: "settings" })}
      />,
    );
    expect(selected()).toBe("Settings");
    expect(
      screen.getByRole("link", { name: "Reload saved values" }),
    ).toHaveAttribute("href", "/bindings/sample-binding?q=kept&tab=settings");
  });

  it("opens the bindings tab and focuses its panel from the count link", async () => {
    const user = userEvent.setup();
    render(<PolicyEditor data={policy} />);
    await user.click(
      screen.getByRole("link", { name: "1 binding on 1 agent" }),
    );
    expect(selected()).toBe("Bindings");
    expect(document.activeElement).toHaveAttribute("role", "tabpanel");
    expect(document.activeElement).toContainElement(
      document.getElementById("h-bindings"),
    );
  });

  it("keeps the count link from jumping, which would clear the focus", () => {
    render(<PolicyEditor data={policy} />);
    const link = screen.getByRole("link", { name: "1 binding on 1 agent" });
    expect(fireEvent.click(link)).toBe(false);
    expect(window.location.hash).toBe("#h-bindings");
  });

  it("selects the owner of a problem over a fragment in the address", () => {
    window.location.hash = "#h-bindings";
    render(
      <PolicyEditor
        data={{ ...policy, Problem: "sample", ProblemTab: "ssh-identities" }}
      />,
    );
    expect(selected()).toMatch(/^SSH identities/);
  });

  it("opens the bindings tab from the fragment in the address", async () => {
    window.location.hash = "#h-bindings";
    render(<PolicyEditor data={policy} />);
    expect(selected()).toBe("Bindings");
    expect(document.activeElement).toHaveAttribute("role", "tabpanel");
  });

  it("follows a fragment that changes on the page", async () => {
    render(<PolicyEditor data={policy} />);
    expect(selected()).toBe("OpenBao policy");
    await act(async () => {
      window.location.hash = "#h-bindings";
      window.dispatchEvent(new HashChangeEvent("hashchange"));
    });
    expect(selected()).toBe("Bindings");
  });
});

describe("hidden state", () => {
  it("shows the bind screen's decisions and follows each change", async () => {
    const user = userEvent.setup();
    render(<Binding data={binding(false)} />);
    const summary = within(
      document.querySelector<HTMLElement>(".decision-summary")!,
    );
    const value = (term: string) =>
      summary.getByText(term).parentElement!.querySelector("dd")!.textContent;
    expect(value("Key")).toBe("name · sample-container");
    expect(value("Policies")).toBe("Not set");
    expect(value("Token time-to-live")).toBe("1h");
    expect(value("Token maximum lifetime")).toBe("8h");
    expect(value("Access group")).toBe("Owner-only");
    expect(value("Enforcement")).toBe("Report conformance");
    await user.click(screen.getByRole("radio", { name: /sample\/service/ }));
    expect(value("Key")).toBe("compose · sample/service");
    await user.click(screen.getByRole("checkbox", { name: "second" }));
    expect(value("Policies")).toBe("second");
    await user.click(tab("Settings"));
    const ttl = screen.getByLabelText("Token time-to-live");
    await user.clear(ttl);
    expect(value("Token time-to-live")).toBe("Not set");
    await user.type(ttl, "2");
    expect(value("Token time-to-live")).toBe("2h");
    const max = screen.getByLabelText("Token maximum lifetime");
    await user.clear(max);
    await user.type(max, "9");
    expect(value("Token maximum lifetime")).toBe("9h");
    await user.selectOptions(screen.getByLabelText("Access group"), "100");
    expect(value("Access group")).toBe("sample-group (100)");
    await user.selectOptions(screen.getByLabelText("Enforcement"), "recreate");
    expect(value("Enforcement")).toBe("Recreate on first bind");
  });

  it("omits the key on a bound screen", () => {
    render(<Binding data={binding(true)} />);
    const summary = document.querySelector<HTMLElement>(".decision-summary")!;
    expect(within(summary).queryByText("Key")).toBeNull();
    expect(within(summary).getByText("Policies")).toBeInTheDocument();
  });

  it.each([
    [
      "identity problems",
      { IdentityProblems: ["sample listing problem"] },
      /^SSH identities.*Needs attention/,
    ],
    [
      "unpermitted identities",
      { Unpermitted: ["sample-key"] },
      /^SSH identities.*Needs attention/,
    ],
    [
      "HCL warnings",
      { Warnings: ["sample warning"] },
      /^OpenBao policy.*Needs attention/,
    ],
  ])("marks the policy tab that holds %s", (_, data, name) => {
    render(<PolicyEditor data={{ ...policy, ...data }} />);
    expect(tab(name)).toBeInTheDocument();
  });

  it("marks no policy tab when nothing needs attention", () => {
    render(<PolicyEditor data={policy} />);
    expect(screen.queryByText(/Needs attention/)).toBeNull();
  });

  it("marks settings when the agent cannot assign the group, and clears it", async () => {
    const user = userEvent.setup();
    const data = binding(true);
    data.Row.AssignableGroups = {
      any: false,
      groups: [{ gid: 100, name: "sample-group" }],
    };
    data.Form.Settings = { ...data.Form.Settings, "access-group": "200" };
    render(<Binding data={data} />);
    expect(tab(/^Settings.*Needs attention/)).toBeInTheDocument();
    await user.click(tab(/^Settings/));
    await user.selectOptions(screen.getByLabelText("Access group"), "100");
    expect(tab("Settings")).toBeInTheDocument();
  });

  it("marks the effective policy tab that holds composition warnings", () => {
    const data = binding(true);
    data.Row.Warnings = ["sample composition warning"];
    render(<Binding data={data} />);
    expect(tab(/^Effective policy.*Needs attention/)).toBeInTheDocument();
  });
});

describe("constraint failures", () => {
  it("shows the panel of the first invalid control before the browser reports it", async () => {
    const user = userEvent.setup();
    render(<Binding data={binding(true)} />);
    await user.click(tab("Settings"));
    await user.clear(screen.getByLabelText("Token time-to-live"));
    await user.click(tab("Policies"));
    const form = formOf("Save binding");
    expect(form.checkValidity()).toBe(false);
    expect(selected()).toBe("Settings");
    expect(screen.getByLabelText("Token time-to-live")).toBeVisible();
  });

  it("follows the first invalid control when two tabs hold one", async () => {
    const user = userEvent.setup();
    render(<PolicyEditor data={{ ...policy, New: true, Name: "" }} />);
    await user.click(tab("Container contract"));
    expect(formOf("Save and validate").checkValidity()).toBe(false);
    // The name is above the tabs, so the selection does not move.
    expect(selected()).toBe("Container contract");
    expect(screen.getByLabelText("Name")).toBeVisible();
  });

  it("shows the panel of the tree's first invalid control when two tabs hold one", () => {
    function TwoInvalid() {
      const ids = ["first", "second", "third"];
      const {
        tab: selectedId,
        setTab,
        onInvalidCapture,
      } = useScreenTabs(ids, {});
      return (
        <form onInvalidCapture={onInvalidCapture} aria-label="Two invalid">
          <ScreenTabs
            label="Sections"
            value={selectedId}
            onValueChange={setTab}
            tabs={[
              { id: "first", label: "First", content: <p>nothing</p> },
              {
                id: "second",
                label: "Second",
                content: <input required aria-label="In second" />,
              },
              {
                id: "third",
                label: "Third",
                content: <input required aria-label="In third" />,
              },
            ]}
          />
        </form>
      );
    }
    render(<TwoInvalid />);
    expect(screen.getByRole<HTMLFormElement>("form").checkValidity()).toBe(
      false,
    );
    expect(selected()).toBe("Second");
    expect(screen.getByLabelText("In second")).toBeVisible();
  });

  it("ignores a valid form", () => {
    render(<Binding data={binding(true)} />);
    expect(formOf("Save binding").checkValidity()).toBe(true);
    expect(selected()).toBe("Status");
    fireEvent.invalid(document.querySelector("input[name=csrf]")!);
    expect(selected()).toBe("Status");
  });
});

describe("top actions", () => {
  it.each([
    ["Bind", binding(false), ["Bind policies", "Preview effective policy"], []],
    [
      "Bound",
      binding(true),
      ["Save binding", "Preview effective policy"],
      ["Request recreate", "Unbind and revoke AppRole"],
    ],
  ])(
    "keeps the %s actions above the tabs with no copy",
    (_, data, buttons, links) => {
      render(<Binding data={data} />);
      const list = screen.getByRole("tablist");
      for (const name of buttons) {
        const action = screen.getByRole("button", { name });
        expect(
          action.compareDocumentPosition(list) &
            Node.DOCUMENT_POSITION_FOLLOWING,
        ).toBeTruthy();
      }
      for (const name of links) {
        const action = screen.getByRole("link", { name });
        expect(
          action.compareDocumentPosition(list) &
            Node.DOCUMENT_POSITION_FOLLOWING,
        ).toBeTruthy();
        expect(action.closest(".actions-separate")).not.toBeNull();
      }
      expect(screen.getAllByRole("button", { name: buttons[0] })).toHaveLength(
        1,
      );
    },
  );

  it("makes the save the form's first submit button", () => {
    render(<Binding data={binding(true)} />);
    const form = formOf("Save binding");
    expect(form.querySelector("button[type=submit]")).toHaveTextContent(
      "Save binding",
    );
  });

  it("separates delete from save on a saved policy", () => {
    render(<PolicyEditor data={policy} />);
    expect(
      screen
        .getByRole("link", { name: "Delete policy" })
        .closest(".actions-separate"),
    ).not.toBeNull();
    expect(
      screen
        .getByRole("button", { name: "Save and validate" })
        .closest(".actions-separate"),
    ).toBeNull();
  });

  it("says where the HCL is", () => {
    render(<PolicyEditor data={policy} />);
    expect(document.body.textContent).toContain(
      "the HCL on the OpenBao policy tab",
    );
    expect(document.body.textContent).not.toContain("the HCL above");
  });
});
