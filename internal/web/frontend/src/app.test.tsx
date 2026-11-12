// ---
// relationships:
//   verifies: web-interface
// ---
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { App } from "./app";
import type {
  AddBindingData,
  BindingData,
  BindingsData,
  ContainerRow,
  Layout,
  Page,
  PolicyData,
  UpdateStatus,
} from "./types";
import { ago, until, stamp } from "./lib/time";

const layout: Layout = {
  Title: "Sample",
  Current: "agents",
  CSRF: "sample-csrf",
  Operator: "operator@example.com",
  Pending: 2,
  OpenBaoOK: true,
  OpenBaoURL: "",
  Controller: "controller.example.com",
  Notice: "",
  Problem: "",
};
const updateStatus: UpdateStatus = {
  Enabled: false,
  Latest: "",
  Checked: "0001-01-01T00:00:00Z",
  LastSuccess: "0001-01-01T00:00:00Z",
  Unavailable: false,
};
const versionInfo = {
  Version: "3.4.5",
  Updates: updateStatus,
  UpdateAvailable: false,
  VersionComparable: true,
};
const policy: PolicyData = {
  AgentTokenRenewal: true,
  ...layout,
  Current: "policies",
  New: true,
  Name: "sample",
  Revision: 1,
  BindingRows: [],
  Bindings: 1,
  Agents: 1,
  Warnings: [],
  KVMounts: [],
  AvailableTransitKeys: ["sample-key"],
  AvailableCARoles: ["sample-role"],
  IdentityProblems: [],
  HCL: 'path "sample/*" { capabilities = ["read"] }',

  TransitKeys: "sample-key",
  CARoles: "sample-role",
  NotForwardableTransitKeys: "sample-restricted-key",
  NotForwardableCARoles: "sample-restricted-role",
  MountTarget: "/run/sample",
  Env: "EXAMPLE=value",

  Unpermitted: ["sample-key"],
  PolicyPath: "sys/policies/acl/sample",
};
const row: ContainerRow = {
  Screen: "/bindings/new?agent=sample-host&container=sample-id&q=sample",
  Agent: "sample-host",
  Connected: false,
  LastReport: "2026-01-01T00:00:00Z",
  ID: "sample-id",
  Name: "sample-container",
  Image: "alpine:latest",
  State: "running",
  KeyKind: "name",
  KeyValue: "sample-container",
  Policies: ["sample"],
  Revision: 1,
  Applied: true,
  Warnings: [],
  Settings: { "token-ttl": "1h", "token-max-ttl": "8h", enforcement: "report" },
  Effective: {
    sources: [],
    openbao: { policy: "" },
    contract: { "mount-target": "/run/sample", enforcement: "report" },
    settings: {
      "token-ttl": "1h",
      "token-max-ttl": "8h",
      enforcement: "report",
    },
  },
  Badge: "Report",
  BadgeClass: "neutral",
  Bound: false,
  BindingID: "sample-binding",
  Token: "none",
  Checks: [{ Label: "sample check", Mark: "FAIL", Status: "bad" }],
  Candidates: [
    {
      Kind: "name",
      Value: "sample-container",
      Encoded: "name:sample-container",
      Note: "sample note",
    },
  ],
};
function draw(page: Page) {
  return render(<App page={page} />);
}
function formFor(button: string) {
  const form = screen.getByRole("button", { name: button }).closest("form");
  expect(form).not.toBeNull();
  return form!;
}
function expectPost(
  button: string,
  action: string,
  fields: Record<string, string> = {},
) {
  const form = formFor(button);
  expect(form).toHaveAttribute("method", "post");
  expect(form).toHaveAttribute("action", action);
  const values = new FormData(form);
  expect(values.get("csrf")).toBe(layout.CSRF);
  for (const [name, value] of Object.entries(fields))
    expect(values.get(name), name).toBe(value);
  return form;
}

describe("sign-in", () => {
  it.each([
    ["", "Sign in", "Continue with Sample ID"],
    [
      "denied",
      "This account can't operate Wyrwood",
      "Sign in with a different account",
    ],
    ["unavailable", "Can't reach Sample ID", "Try again"],
    ["invalid", "Sign-in didn't complete", "Continue with Sample ID"],
    ["expired", "Sign in", "Continue with Sample ID"],
  ])(
    "renders %s and starts the existing OIDC flow",
    (Problem, heading, button) => {
      draw({
        page: "sign-in",
        data: {
          ...layout,
          Problem,
          Provider: "Sample ID",
          IssuerHost: "id.example.com",
          Version: "sample",
          Account: "sample@example.com",
        },
      });
      expect(
        screen.getByRole("heading", { name: heading }),
      ).toBeInTheDocument();
      const form = formFor(button);
      expect(form).toHaveAttribute("action", "/auth/start");
      expect(form).toHaveAttribute("method", "post");
      expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
      expect(
        screen.queryByRole("link", { name: /Report an issue/ }),
      ).not.toBeInTheDocument();
      if (Problem === "denied")
        expect(screen.getByText("sample@example.com")).toBeInTheDocument();
      if (Problem === "expired")
        expect(screen.getByRole("status")).toHaveTextContent(
          "Your session ended",
        );
    },
  );
});

it("keeps sidebar routes, pending count, account identity, and sign out", async () => {
  const user = userEvent.setup();
  draw({
    page: "agents",
    data: {
      ...layout,
      ...versionInfo,
      HostKey: "sample-fingerprint",
      PendingKeys: null,
      Approved: null,
    },
  });
  const nav = screen.getByRole("navigation", { name: "Primary" });
  for (const [name, href] of [
    ["Agents", "/agents"],
    ["Bindings", "/bindings"],
    ["Policies", "/policies"],
    ["OpenBao keys", "/keys"],
    ["Events", "/events"],
  ])
    expect(
      within(nav).getByRole("link", { name: new RegExp(name) }),
    ).toHaveAttribute("href", href);
  expect(within(nav).getByRole("link", { name: /Agents/ })).toHaveAttribute(
    "aria-current",
    "page",
  );
  expect(screen.getByLabelText("2 pending")).toBeInTheDocument();
  expect(screen.getByText(layout.Operator)).toBeInTheDocument();
  expect(
    screen.getByRole("region", { name: "Controller version" }),
  ).toHaveTextContent(versionInfo.Version);
  const account = within(nav).getByRole("button", { name: /Account/ });
  expect(account).toHaveAttribute("aria-haspopup", "menu");
  expect(account).toHaveAttribute("aria-expanded", "false");
  expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  await user.click(account);
  expect(account).toHaveAttribute("aria-expanded", "true");
  const menu = screen.getByRole("menu", { name: /Account/ });
  expect(
    within(menu).getByRole("menuitem", { name: "Security" }),
  ).toHaveAttribute("href", "/security");
  const form = (
    within(menu).getByRole("menuitem", {
      name: "Sign out",
    }) as HTMLButtonElement
  ).form!;
  expect(form).toHaveAttribute("method", "post");
  expect(form).toHaveAttribute("action", "/sign-out");
  expect(new FormData(form).get("csrf")).toBe(layout.CSRF);
});

it.each(["{Enter}", " ", "{ArrowDown}"])(
  "opens the account menu with %s and restores focus on Escape",
  async (key) => {
    const user = userEvent.setup();
    draw({
      page: "agents",
      data: {
        ...layout,
        ...versionInfo,
        HostKey: "",
        PendingKeys: null,
        Approved: null,
      },
    });
    const account = screen.getByRole("button", { name: /Account/ });
    account.focus();
    await user.keyboard(key);
    const security = screen.getByRole("menuitem", { name: "Security" });
    expect(security).toHaveFocus();
    await user.keyboard("{ArrowDown}");
    expect(screen.getByRole("menuitem", { name: "Sign out" })).toHaveFocus();
    await user.keyboard("{ArrowUp}");
    expect(security).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
    expect(account).toHaveFocus();
    expect(account).toHaveAttribute("aria-expanded", "false");
  },
);

it.each(["pointer", "Enter", "Space"])(
  "submits sign out with the anti-forgery token using %s",
  async (activation) => {
    const user = userEvent.setup();
    draw({
      page: "agents",
      data: {
        ...layout,
        ...versionInfo,
        HostKey: "",
        PendingKeys: null,
        Approved: null,
      },
    });
    const account = screen.getByRole("button", { name: /Account/ });
    account.focus();
    await user.keyboard("{Enter}");
    const signOut = screen.getByRole("menuitem", { name: "Sign out" });
    let submitted = false;
    (signOut as HTMLButtonElement).form!.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.target as HTMLFormElement;
      expect(form).toHaveAttribute("method", "post");
      expect(form).toHaveAttribute("action", "/sign-out");
      expect(new FormData(form).get("csrf")).toBe(layout.CSRF);
      submitted = true;
    });
    if (activation === "pointer") await user.click(signOut);
    else {
      await user.keyboard("{ArrowDown}");
      await user.keyboard(activation === "Enter" ? "{Enter}" : " ");
    }
    expect(submitted).toBe(true);
    // Real browsers need the button connected for its native submit action.
    expect(signOut).toBeInTheDocument();
  },
);

it("marks Security as the current menu item", async () => {
  const user = userEvent.setup();
  draw({
    page: "agents",
    data: {
      ...layout,
      Current: "security",
      ...versionInfo,
      HostKey: "",
      PendingKeys: null,
      Approved: null,
    },
  });
  const account = screen.getByRole("button", { name: /Account/ });
  account.focus();
  await user.keyboard("{Enter}");
  expect(screen.getByRole("menuitem", { name: "Security" })).toHaveAttribute(
    "aria-current",
    "page",
  );
});

const agentsPage: Page = {
  page: "agents",
  data: {
    ...layout,
    ...versionInfo,
    HostKey: "sample-fingerprint",
    PendingKeys: null,
    Approved: null,
  },
};
describe("Report an issue link", () => {
  it("goes to the GitHub form with no site data, in a new tab", () => {
    draw(agentsPage);
    const nav = screen.getByRole("navigation", { name: "Primary" });
    const link = within(nav).getByRole("link", {
      name: "Report an issue (opens GitHub in a new tab)",
    });
    expect(link.getAttribute("href")).toBe(
      "https://github.com/wyrd-company/wyrwood/issues/new",
    );
    expect(link).toHaveAttribute("target", "_blank");
    expect(link.getAttribute("rel")).toBe("noopener noreferrer");
    expect(link.parentElement).toHaveClass("nav-foot");
  });

  it("shows on the confirm page", () => {
    draw({
      page: "confirm",
      data: {
        ...layout,
        Heading: "Sample",
        Body: "Sample",
        Action: "/sample",
        Button: "Sample",
        Danger: false,
        Back: "/agents",
      },
    });
    expect(
      screen.getByRole("link", { name: /Report an issue/ }),
    ).toBeInTheDocument();
  });

  it("is reachable by keyboard", async () => {
    const user = userEvent.setup();
    draw(agentsPage);
    const link = screen.getByRole("link", { name: /Report an issue/ });
    for (let stop = 0; stop < 20 && document.activeElement !== link; stop += 1)
      await user.tab();
    expect(link).toHaveFocus();
  });
});

const openBaoURL =
  "https://vault.example:8443/proxy/ui/openbao/secrets?namespace=team%2Fsample";
function expectOpenBaoLink(link: HTMLElement) {
  expect(link).toHaveAttribute("href", openBaoURL);
  expect(link).toHaveAttribute("target", "_blank");
  expect(link).toHaveAttribute("rel", "noopener noreferrer");
}
it("offers the OpenBao UI beside OpenBao keys only when configured", async () => {
  const user = userEvent.setup();
  const agents = {
    ...layout,
    ...versionInfo,
    HostKey: "sample-fingerprint",
    PendingKeys: null,
    Approved: null,
  };
  const { unmount } = draw({ page: "agents", data: agents });
  expect(
    screen.queryByRole("link", { name: /OpenBao UI/ }),
  ).not.toBeInTheDocument();
  unmount();
  draw({ page: "agents", data: { ...agents, OpenBaoURL: openBaoURL } });
  const nav = screen.getByRole("navigation", { name: "Primary" });
  const link = within(nav).getByRole("link", {
    name: "OpenBao UI (opens in a new tab)",
  });
  expectOpenBaoLink(link);
  expect(link.previousElementSibling).toHaveAttribute("href", "/keys");
  await user.click(within(nav).getByRole("button", { name: /Account/ }));
  expect(screen.getByRole("menuitem", { name: "Security" })).toHaveAttribute(
    "href",
    "/security",
  );
});
it.each([true, false])(
  "links the policy editor (new %s) to the OpenBao UI without leaving the form",
  async (New) => {
    const user = userEvent.setup();
    draw({ page: "policy", data: { ...policy, New, OpenBaoURL: openBaoURL } });
    const heading = screen.getByRole("heading", { name: "OpenBao policy" });
    const link = within(heading.parentElement!).getByRole("link", {
      name: /Manage secrets in the OpenBao UI/,
    });
    expectOpenBaoLink(link);
    expect(link.closest("form")).toBe(formFor("Save and validate"));
    await user.click(screen.getByRole("button", { name: "Raw HCL" }));
    await user.clear(screen.getByLabelText("OpenBao policy HCL"));
    await user.type(screen.getByLabelText("OpenBao policy HCL"), "unsaved");
    expectPost("Save and validate", "/policies", {
      hcl: "unsaved",
      ...(New ? { new: "yes" } : { name: policy.Name }),
    });
  },
);
it("omits the policy editor OpenBao UI link without a configured URL", () => {
  draw({ page: "policy", data: policy });
  expect(
    screen.queryByRole("link", { name: /OpenBao UI/ }),
  ).not.toBeInTheDocument();
});

it("keeps approval decisions, fingerprints, host links, and cached health", () => {
  draw({
    page: "agents",
    data: {
      ...layout,
      ...versionInfo,
      HostKey: "controller-fingerprint",
      PendingKeys: [
        {
          Name: "sample-host",
          Fingerprint: "sample-fingerprint",
          FirstSeen: "2026-01-01T00:00:00Z",
        },
      ],
      Approved: [
        {
          Name: "sample/host",
          Version: "2.9.1",
          OutOfDate: true,
          Connected: false,
          Containers: 1,
          Bound: 1,
          Health: [{ Count: 1, Category: "degraded" }],
          LastReport: "0001-01-01T00:00:00Z",
        },
      ],
    },
  });
  expect(screen.getByText("controller-fingerprint")).toBeInTheDocument();
  const form = expectPost("Approve agent", "/agents/decide", {
    fingerprint: "sample-fingerprint",
  });
  expect(
    within(form).getByRole("button", { name: "Approve agent" }),
  ).toHaveAttribute("value", "approve");
  expect(within(form).getByRole("button", { name: "Reject" })).toHaveAttribute(
    "value",
    "reject",
  );
  expect(screen.getByRole("link", { name: "sample/host" })).toHaveAttribute(
    "href",
    "/bindings?filter-agent=sample%2Fhost",
  );
  expect(screen.getByText(/serving from cache/)).toBeInTheDocument();
  expect(screen.getByText("1 degraded")).toBeInTheDocument();
  expect(screen.getByText("Out of date")).toBeInTheDocument();
});

it("shows controller and agent build versions, including legacy agents", () => {
  draw({
    page: "agents",
    data: {
      ...layout,
      ...versionInfo,
      HostKey: "sample-fingerprint",
      PendingKeys: null,
      Approved: ["2.9.1+sample", ""].map((Version, index) => ({
        Name: `sample-host-${index}`,
        Version,
        OutOfDate: false,
        Connected: false,
        Containers: 0,
        Bound: 0,
        Health: null,
        LastReport: "0001-01-01T00:00:00Z",
      })),
    },
  });
  const controller = screen.getByRole("region", { name: "Controller version" });
  expect(within(controller).getByText("3.4.5")).toBeInTheDocument();
  const known = screen
    .getByRole("link", { name: "sample-host-0" })
    .closest("tr")!;
  expect(within(known).getByText("2.9.1+sample")).toBeInTheDocument();
  const legacy = screen
    .getByRole("link", { name: "sample-host-1" })
    .closest("tr")!;
  expect(within(legacy).getByText("unknown")).toBeInTheDocument();
  expect(within(legacy).getByText("Update available")).toBeInTheDocument();
});

it("preserves every policy value, edit/new identity, validation feedback and access-group warning", async () => {
  const user = userEvent.setup();
  draw({
    page: "policy",
    data: {
      ...policy,
      Problem: "Sample validation failure",
      Warnings: ["Token lifecycle HCL is missing"],
    },
  });
  expect(screen.getByRole("alert")).toHaveTextContent(
    "Sample validation failure",
  );
  expect(screen.getByRole("status")).toHaveTextContent(
    "Token lifecycle HCL is missing",
  );
  const fields = {
    new: "yes",
    name: policy.Name,
    hcl: policy.HCL,
    "transit-keys": policy.TransitKeys,
    "ca-roles": policy.CARoles,
    "not-forwardable-transit-keys": policy.NotForwardableTransitKeys,
    "not-forwardable-ca-roles": policy.NotForwardableCARoles,
    "mount-target": policy.MountTarget,
    env: policy.Env,
  };
  expectPost("Save and validate", "/policies", fields);
  await user.click(screen.getByRole("button", { name: "Raw HCL" }));
  await user.clear(screen.getByLabelText("OpenBao policy HCL"));
  await user.type(screen.getByLabelText("OpenBao policy HCL"), "sample hcl");
  expectPost("Save and validate", "/policies", {
    hcl: "sample hcl",
  });
  expect(
    screen.getByText(/sample-key is not allowed by the HCL/),
  ).toBeInTheDocument();
});
it.each([1000, 0])(
  "keeps binding access group %s without an owner-only warning",
  (group) => {
    const data = binding(true);
    data.Form.Settings["access-group"] = String(group);
    draw({ page: "binding", data });
    expect(screen.queryByText(/No access group:/)).not.toBeInTheDocument();
    expectPost("Save binding", "/bindings/sample-binding/policy", {
      "access-group": String(group),
      policies: "sample",
    });
  },
);

const bindingRow = {
  ID: "sample-binding",
  Agent: "sample-host",
  AgentNotApproved: false,
  Connected: false,
  LastReport: "2026-01-01T00:00:00Z",
  KeyKind: "compose",
  KeyValue: "sample/worker",
  Policies: ["first", "second"],
  Containers: [
    {
      ID: "sample-id",
      Name: "sample-container",
      Image: "busybox:latest",
      State: "running",
      Screen: "/bindings/sample-binding?container=sample-id",
    },
  ],
  Badge: "Conforms",
  BadgeClass: "good",
  Screen: "/bindings/sample-binding",
};
function listData() {
  return {
    ...layout,
    Current: "bindings",
    Agents: [{ Name: "sample-host", Count: 1, Selected: true }],
    FilterAgent: "",
    Query: "",
    Sort: "name",
    Order: "asc",
  };
}
function bindings(): BindingsData {
  return {
    ...listData(),
    Add: "/bindings/add?q=sample",
    Rows: [bindingRow],
  };
}
function addBinding(): AddBindingData {
  return {
    ...listData(),
    Back: "/bindings?q=sample",
    TypedScreen: "/bindings/new/key?q=sample",
    Rows: [{ ...row, Bound: false }],
  };
}
function binding(Bound: boolean): BindingData {
  return {
    ...layout,
    Current: "bindings",
    Row: { ...row, Bound },
    Reported: true,
    Policies: [{ Name: "sample", Selected: Bound }],
    Form: {
      Key: Bound ? "" : "name:sample-container",
      Revision: 1,
      Understood: false,
      Settings: {
        "token-ttl": "1h",
        "token-max-ttl": "8h",
        "access-group": "",
        enforcement: "report",
      },
    },
    Screen: "/bindings/sample-binding?q=sample",
    Action: Bound ? "/bindings/sample-binding/policy" : "/bindings",
    Recreate: "/bindings/sample-binding/recreate?q=sample",
    Unbind: "/bindings/sample-binding/unbind?q=sample",
    Back: Bound ? "/bindings?q=sample" : "/bindings/add?q=sample",
  };
}
it("lists bindings at full width with row links and no detail panel", () => {
  const view = draw({ page: "bindings", data: bindings() });
  const filter = screen
    .getByRole("button", { name: "Apply filters" })
    .closest("form")!;
  expect(filter).toHaveAttribute("method", "get");
  expect(filter).toHaveAttribute("action", "/bindings");
  expect(new FormData(filter).get("filter-agent")).toBe("");
  expect(
    screen.getByRole("link", { name: /^sample-container/ }),
  ).toHaveAttribute("href", bindingRow.Containers[0].Screen);
  expect(screen.getByRole("link", { name: "Add binding" })).toHaveAttribute(
    "href",
    "/bindings/add?q=sample",
  );
  for (const text of [
    "busybox:latest",
    "sample-host",
    "compose",
    "sample/worker",
    "first, second",
    "Conforms",
  ]) {
    expect(screen.getByText(text)).toBeVisible();
  }
  expect(view.container.querySelector("main")).toHaveClass("wide");
  expect(view.container.querySelector("aside.card")).toBeNull();
  expect(view.container.querySelector("tr.selected")).toBeNull();
  expect(
    screen.queryByRole("button", { name: "Bind policies" }),
  ).not.toBeInTheDocument();
});
it("shows a binding with no reported container, with its agent and key", () => {
  const data = bindings();
  data.Rows = [
    {
      ...bindingRow,
      Containers: null,
      Badge: "Not reported",
      BadgeClass: "neutral",
    },
  ];
  draw({ page: "bindings", data });
  expect(screen.getByRole("link", { name: /^sample\/worker/ })).toHaveAttribute(
    "href",
    bindingRow.Screen,
  );
  expect(screen.getByText("No container reported")).toBeVisible();
  expect(screen.getByText("Not reported")).toBeVisible();
  expect(screen.getByText("sample-host")).toBeVisible();
  expect(screen.getByText("Disconnected · last report shown")).toBeVisible();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});
it("shows every container that one binding governs", () => {
  const data = bindings();
  const other = {
    ...bindingRow.Containers[0],
    ID: "other-id",
    Name: "other-container",
    Screen: "/bindings/sample-binding?container=other-id",
  };
  data.Rows = [
    {
      ...bindingRow,
      Containers: [...bindingRow.Containers, other],
    },
  ];
  draw({ page: "bindings", data });
  expect(screen.getByRole("link", { name: /other-container/ })).toHaveAttribute(
    "href",
    other.Screen,
  );
  expect(screen.getByRole("link", { name: /^sample-container/ })).toBeVisible();
});
it("lists containers with no binding on the add screen", () => {
  const view = draw({ page: "add-binding", data: addBinding() });
  expect(formFor("Apply filters")).toHaveAttribute("action", "/bindings/add");
  expect(
    screen.getByRole("link", { name: /^sample-container/ }),
  ).toHaveAttribute("href", row.Screen);
  expect(
    screen.getByRole("link", { name: "Back to bindings" }),
  ).toHaveAttribute("href", "/bindings?q=sample");
  expect(screen.getByRole("link", { name: "Clear filters" })).toHaveAttribute(
    "href",
    "/bindings/add",
  );
  expect(screen.getByText(row.State)).toBeVisible();
  expect(view.container.querySelector("main")).toHaveClass("wide");
});
it("preserves binding keys and explicit recreate consent on the bind screen", async () => {
  draw({ page: "binding", data: binding(false) });
  expect(
    screen.getByRole("link", { name: "Back to Add binding" }),
  ).toHaveAttribute("href", "/bindings/add?q=sample");
  expect(screen.getByRole("checkbox", { name: "sample" })).not.toBeChecked();
  await userEvent.click(screen.getByRole("checkbox", { name: "sample" }));
  expectPost("Bind policies", "/bindings", {
    agent: "sample-host",
    container: "sample-id",
    key: "name:sample-container",
    policies: "sample",
  });
  expect(new FormData(formFor("Bind policies")).has("understood")).toBe(false);
  expect(
    screen.getByText(/Recreate discards the writable layer/),
  ).toBeInTheDocument();
  await userEvent.click(screen.getByRole("tab", { name: "Settings" }));
  await userEvent.click(screen.getByRole("checkbox", { name: /I understand/ }));
  expectPost("Bind policies", "/bindings?tab=settings", { understood: "yes" });
});
it("shows a failed submission's message and every entered value", () => {
  const data = binding(false);
  data.Problem = "Sample actionable problem";
  data.Row.Candidates = [
    {
      Kind: "compose",
      Value: "sample/one",
      Note: "most stable",
      Encoded: "compose:sample/one",
    },
    {
      Kind: "name",
      Value: "sample-container",
      Note: "less stable",
      Encoded: "name:sample-container",
    },
  ];
  data.Policies = [
    { Name: "sample", Selected: false },
    { Name: "second", Selected: true },
  ];
  data.Form = {
    Key: "name:sample-container",
    Revision: 1,
    Understood: true,
    Settings: {
      "token-ttl": "not-a-duration",
      "token-max-ttl": "2h",
      "access-group": "not-a-gid",
      enforcement: "recreate",
    },
  };
  data.Tab = "settings";
  draw({ page: "binding", data });
  expect(screen.getByRole("alert")).toHaveTextContent(
    "Sample actionable problem",
  );
  expect(screen.getByRole("checkbox", { name: /I understand/ })).toBeChecked();
  expectPost("Bind policies", "/bindings?tab=settings", {
    key: "name:sample-container",
    policies: "second",
    "token-ttl": "not-a-duration",
    "token-max-ttl": "2h",
    "access-group": "not-a-gid",
    enforcement: "recreate",
    understood: "yes",
  });
});
it("offers saved values after a failed change to a bound container", () => {
  const data = binding(true);
  data.Problem = "the binding changed; reload before saving";
  data.Form.Revision = 3;
  draw({ page: "binding", data });
  expect(
    screen.getByRole("link", { name: "Reload saved values" }),
  ).toHaveAttribute("href", data.Screen);
  expectPost("Save binding", "/bindings/sample-binding/policy", {
    revision: "3",
  });
});
it("keeps bound container diagnostics, change policy, and confirmation links", () => {
  draw({ page: "binding", data: binding(true) });
  expect(screen.getByText("sample check")).toBeInTheDocument();
  expect(screen.getByText("FAIL")).toBeInTheDocument();
  expectPost("Save binding", "/bindings/sample-binding/policy", {
    agent: "sample-host",
    policies: "sample",
  });
  expect(
    screen.getByRole("link", { name: "Request recreate" }),
  ).toHaveAttribute("href", "/bindings/sample-binding/recreate?q=sample");
  expect(
    screen.getByRole("link", { name: "Unbind and revoke AppRole" }),
  ).toHaveAttribute("href", "/bindings/sample-binding/unbind?q=sample");
  expect(screen.getByText("AppRole assignment applied")).toBeInTheDocument();
});
it("says so when a binding's container is not reported", () => {
  const data = binding(true);
  data.Reported = false;
  draw({ page: "binding", data });
  expect(screen.getByText(/does not report a container/)).toBeInTheDocument();
  expect(screen.queryByText("sample check")).not.toBeInTheDocument();
  expect(
    screen.getByRole("link", { name: "Unbind and revoke AppRole" }),
  ).toBeInTheDocument();
});
it("shows a policy creation link when no policy can be bound", () => {
  draw({ page: "binding", data: { ...binding(false), Policies: null } });
  expect(screen.getByRole("link", { name: "New policy" })).toHaveAttribute(
    "href",
    "/policies/edit",
  );
  expect(
    screen.queryByRole("button", { name: "Bind policies" }),
  ).not.toBeInTheDocument();
});
it.each([false, true])(
  "keeps confirmation submission and cancel for danger=%s",
  (Danger) => {
    draw({
      page: "confirm",
      data: {
        ...layout,
        Heading: "Sample confirmation",
        Body: "Sample consequence",
        Action: "/bindings/sample/unbind",
        Button: "Confirm",
        Back: "/bindings?filter-agent=sample",
        Danger,
      },
    });
    expectPost("Confirm", "/bindings/sample/unbind");
    expect(screen.getByRole("link", { name: "Cancel" })).toHaveAttribute(
      "href",
      "/bindings?filter-agent=sample",
    );
  },
);
it("keeps operation errors and back navigation", () => {
  draw({
    page: "confirm",
    data: {
      ...layout,
      Problem: "Sample error",
      Heading: "That did not work",
      Body: "",
      Action: "",
      Button: "",
      Back: "/keys",
      Danger: false,
    },
  });
  expect(screen.getByRole("alert")).toHaveTextContent("Sample error");
  expect(screen.getByRole("link", { name: "Back" })).toHaveAttribute(
    "href",
    "/keys",
  );
});
it("keeps policy revision, binding totals, saved operator and editor link", () => {
  draw({
    page: "policies",
    data: {
      ...layout,
      Policies: [
        {
          Name: "sample",
          Revision: 2,

          Bindings: 1,
          Agents: 1,
          SavedAt: "0001-01-01T00:00:00Z",
          SavedBy: "sample@example.com",
        },
      ],
    },
  });
  expect(screen.getByRole("link", { name: "sample" })).toHaveAttribute(
    "href",
    "/policies/edit?name=sample",
  );
  expect(screen.getByText("1 container on 1 agent")).toBeInTheDocument();
  expect(screen.getByText(/by sample@example.com/)).toBeInTheDocument();
});
it("keeps Transit creation/rotation and SSH role forms with all existing key types", async () => {
  draw({
    page: "keys",
    data: {
      ...layout,
      TransitMount: "transit",
      SSHMount: "ssh",
      Problems: [
        "sample listing problem",
        "Transit key sample-other could not be read: permission refused.",
      ],
      Transit: [
        {
          Name: "sample-key",
          Type: "ed25519",
          Version: 2,
          Fingerprint: "sample-fingerprint",
          UsedBy: ["sample"],
        },
      ],
      Roles: [
        {
          Name: "sample-role",
          AllowedUsers: "sample-user",
          TTL: "30m",
          UsedBy: null,
        },
      ],
    },
  });
  expect(
    screen.getAllByRole("alert").map((alert) => alert.textContent),
  ).toEqual([
    "sample listing problem",
    "Transit key sample-other could not be read: permission refused.",
  ]);
  expectPost("Rotate", "/keys/transit/rotate", { name: "sample-key" });
  await userEvent.type(screen.getByLabelText("New Transit key"), "sample-new");
  expectPost("Create key", "/keys/transit", {
    name: "sample-new",
    type: "ed25519",
  });
  expect(
    within(screen.getByLabelText("Type"))
      .getAllByRole("option")
      .map((option) => option.getAttribute("value")),
  ).toEqual(["ed25519", "rsa-2048", "rsa-3072", "rsa-4096"]);
  expectPost("Create role", "/keys/ssh", { ttl: "30m" });
  expect(screen.getByLabelText("New SSH role")).toHaveAttribute("required");
  expect(screen.getByLabelText("Allowed users")).toHaveAttribute(
    "name",
    "allowed-users",
  );
});
it("keeps event filters, categorical error, operator and UTC time", () => {
  draw({
    page: "events",
    data: {
      ...layout,
      Outcome: "denied",
      Outcomes: ["ok", "denied", "failed", "timeout"],
      Events: [
        {
          Time: "2026-01-01T01:02:03Z",
          Operation: "sample-operation",
          Outcome: "denied",
          Error: "sample-error",
          Class: "bad",
          Subject: "sample-subject",
          Operator: "sample@example.com",
          Latency: "1ms",
        },
      ],
    },
  });
  const filters = screen.getByRole("group", { name: "Filter by outcome" });
  expect(within(filters).getByRole("link", { name: "denied" })).toHaveAttribute(
    "aria-current",
    "true",
  );
  expect(within(filters).getByRole("link", { name: "All" })).toHaveAttribute(
    "href",
    "/events",
  );
  for (const outcome of ["ok", "denied", "failed", "timeout"])
    expect(
      within(filters).getByRole("link", { name: outcome }),
    ).toHaveAttribute("href", `/events?outcome=${outcome}`);
  expect(screen.getByText("2026-01-01 01:02:03Z")).toBeInTheDocument();
  expect(screen.getByText("sample-error")).toBeInTheDocument();
  expect(screen.getByText("sample@example.com")).toBeInTheDocument();
});
it("keeps security identity, provider account link, discovery and session revocation", () => {
  draw({
    page: "security",
    data: {
      ...layout,
      Email: "sample@example.com",
      Name: "Sample",
      AdmittedGroup: "sample-group",
      AllowedGroups: ["sample-group"],
      Provider: "Sample ID",
      Issuer: "https://id.example.com",
      ClientID: "sample-client",
      RedirectURL: "https://app.example.com/auth/callback",
      Reachable: false,
      Fetched: "0001-01-01T00:00:00Z",
      Sessions: [
        {
          Current: true,
          CreatedAt: "2026-01-01T00:00:00Z",
          ExpiresAt: "2027-01-01T00:00:00Z",
        },
        {
          Current: false,
          CreatedAt: "2026-01-01T00:00:00Z",
          ExpiresAt: "2027-01-01T00:00:00Z",
        },
      ],
    },
  });
  expect(
    screen.getByRole("link", { name: "Manage your account in Sample ID" }),
  ).toHaveAttribute("href", "https://id.example.com");
  expect(screen.getByText("This browser")).toBeInTheDocument();
  expect(screen.getByText("Other browser")).toBeInTheDocument();
  expectPost("Sign out other sessions", "/security/sessions");
  expect(screen.getByText("Unreachable")).toBeInTheDocument();
});
it("renders untrusted policy text as text", () => {
  const malicious = '</textarea><script>alert("sample")</script>';
  const { container } = draw({
    page: "policy",
    data: { ...policy, HCL: malicious },
  });
  expect(screen.getByLabelText("OpenBao policy HCL")).toHaveValue(malicious);
  expect(container.querySelector("script")).toBeNull();
});
it("preserves relative time units and zero-time semantics", () => {
  expect(ago("0001-01-01T00:00:00Z")).toBe("never");
  expect(ago(new Date(Date.now() - 120000).toISOString())).toBe("2 min ago");
  expect(until(new Date(Date.now() + 3700000).toISOString())).toBe("in 1 h");
  expect(stamp("2026-01-01T01:00:00+01:00")).toBe("2026-01-01 00:00:00Z");
});

it("keeps not-forwardable identity selectors editable and clearable", async () => {
  const user = userEvent.setup();
  draw({ page: "policy", data: { ...policy, New: false } });
  await user.click(screen.getByRole("tab", { name: /^SSH identities/ }));
  const keys = screen.getByRole("checkbox", {
    name: "Not forwardable sample-restricted-key",
  });
  const roles = screen.getByRole("checkbox", {
    name: "Not forwardable sample-restricted-role",
  });
  expect(keys).toBeChecked();
  expect(roles).toBeChecked();
  await user.click(keys);
  await user.click(roles);
  expectPost("Save and validate", "/policies?tab=ssh-identities", {
    "not-forwardable-transit-keys": "",
    "not-forwardable-ca-roles": "",
    "transit-keys": policy.TransitKeys,
    "ca-roles": policy.CARoles,
  });
});

it.each([
  ["disabled", updateStatus, false, true, "Update checks disabled."],
  [
    "pending",
    { ...updateStatus, Enabled: true },
    false,
    true,
    "Checking for updates…",
  ],
  [
    "offline",
    { ...updateStatus, Enabled: true, Unavailable: true },
    false,
    true,
    "Update check unavailable.",
  ],
  [
    "stale",
    {
      ...updateStatus,
      Enabled: true,
      Latest: "3.5.0",
      LastSuccess: "2026-01-01T00:00:00Z",
      Checked: "2026-01-02T00:00:00Z",
      Unavailable: true,
    },
    true,
    true,
    "Update check unavailable.",
  ],
  [
    "available",
    {
      ...updateStatus,
      Enabled: true,
      Latest: "3.5.0",
      LastSuccess: "2026-01-01T00:00:00Z",
      Checked: "2026-01-01T00:00:00Z",
    },
    true,
    true,
    "Update available",
  ],
  [
    "current",
    {
      ...updateStatus,
      Enabled: true,
      Latest: "3.4.5",
      LastSuccess: "2026-01-01T00:00:00Z",
      Checked: "2026-01-01T00:00:00Z",
    },
    false,
    true,
    "Up to date.",
  ],
  [
    "development",
    {
      ...updateStatus,
      Enabled: true,
      Latest: "3.4.5",
      LastSuccess: "2026-01-01T00:00:00Z",
      Checked: "2026-01-01T00:00:00Z",
    },
    false,
    false,
    "Version comparison unavailable for this build.",
  ],
] as const)(
  "shows release-check state %s",
  (_name, Updates, UpdateAvailable, VersionComparable, expected) => {
    draw({
      page: "agents",
      data: {
        ...layout,
        ...versionInfo,
        Updates,
        UpdateAvailable,
        VersionComparable,
        HostKey: "sample-fingerprint",
        PendingKeys: null,
        Approved: null,
      },
    });
    const panel = screen.getByRole("region", { name: "Controller version" });
    expect(panel).toHaveTextContent(expected);
    if (Updates.Latest)
      expect(
        within(panel).getByRole("link", { name: Updates.Latest }),
      ).toHaveAttribute(
        "href",
        `https://github.com/wyrd-company/wyrwood/releases/tag/${Updates.Latest}`,
      );
    if (
      !VersionComparable ||
      Updates.Unavailable ||
      !Updates.Enabled ||
      Updates.Checked.startsWith("0001-")
    )
      expect(panel).not.toHaveTextContent("Up to date.");
    if (UpdateAvailable)
      expect(within(panel).getByText("Update available")).toBeInTheDocument();
  },
);

it("previews several selected policies with binding settings and lifecycle grants", async () => {
  const user = userEvent.setup();
  const data = binding(false);
  data.Policies = [
    { Name: "sample", Selected: true },
    { Name: "second", Selected: false },
  ];
  const effective = {
    ...row.Effective,
    sources: [
      { name: "sample", revision: 1, hcl: "sample HCL" },
      { name: "second", revision: 2, hcl: "second HCL" },
    ],
    openbao: { policy: "combined source HCL" },
  };
  const fetcher = vi.fn().mockResolvedValue({
    ok: true,
    json: async () => ({
      effective,
      warnings: [],
    }),
  });
  vi.stubGlobal("fetch", fetcher);
  try {
    draw({ page: "binding", data });
    await user.click(screen.getByRole("checkbox", { name: "second" }));
    await user.click(
      screen.getByRole("button", { name: "Preview effective policy" }),
    );
    expect(await screen.findByText("combined source HCL")).toBeInTheDocument();
    expect(screen.getByText(/Agent token renewal:/)).toBeInTheDocument();
    const [url, request] = fetcher.mock.calls[0];
    expect(url).toBe("/bindings/preview");
    expect(request.body.getAll("policies")).toEqual(["sample", "second"]);
    expect(request.body.get("csrf")).toBe("sample-csrf");
    expect(request.body.get("token-ttl")).toBe("1h");
    await user.click(screen.getByRole("tab", { name: "Key and policies" }));
    await user.click(screen.getByRole("checkbox", { name: "second" }));
    expect(screen.queryByText("combined source HCL")).not.toBeInTheDocument();
  } finally {
    vi.unstubAllGlobals();
  }
});

it("shows a composition conflict without losing the selected policies", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: false,
      json: async () => ({
        error: "Policies require different mount targets",
      }),
    }),
  );
  try {
    const data = binding(false);
    data.Policies = [{ Name: "sample", Selected: true }];
    draw({ page: "binding", data });
    await userEvent.click(
      screen.getByRole("button", { name: "Preview effective policy" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "different mount targets",
    );
    expect(
      screen.getByRole("checkbox", { name: "sample", hidden: true }),
    ).toBeChecked();
  } finally {
    vi.unstubAllGlobals();
  }
});

it("keeps duplicate container IDs distinct across agents and submits the screen's agent", () => {
  const data = addBinding();
  const other = {
    ...row,
    Agent: "other/host",
    Connected: true,
    Screen: "/bindings/new?agent=other%2Fhost&container=sample-id",
  };
  data.Rows = [{ ...row }, other];
  const view = draw({ page: "add-binding", data });
  const links = screen.getAllByRole("link", { name: /^sample-container/ });
  expect(links).toHaveLength(2);
  expect(links[1]).toHaveAttribute("href", other.Screen);
  expect(screen.getByText("Connected", { exact: true })).toBeVisible();
  expect(screen.getByText("Disconnected · last report shown")).toBeVisible();
  view.unmount();
  draw({ page: "binding", data: { ...binding(false), Row: other } });
  expectPost("Bind policies", "/bindings", {
    agent: "other/host",
    container: "sample-id",
  });
});

it("renders rows and filter controls", async () => {
  const user = userEvent.setup();
  draw({ page: "bindings", data: bindings() });
  expect(screen.getByRole("link", { name: /^sample-container/ })).toBeVisible();
  await user.selectOptions(screen.getByLabelText("Agent"), "sample-host");
  await user.type(screen.getByLabelText("Filter bindings"), "alpine");
  await user.selectOptions(screen.getByLabelText("Sort by"), "policies");
  await user.selectOptions(screen.getByLabelText("Order"), "desc");
  expect(Object.fromEntries(new FormData(formFor("Apply filters")))).toEqual({
    "filter-agent": "sample-host",
    q: "alpine",
    sort: "policies",
    order: "desc",
  });
  expect(screen.getByRole("link", { name: "Clear filters" })).toHaveAttribute(
    "href",
    "/bindings",
  );
});

it("names the agent's count in the unit of each list", () => {
  const view = draw({ page: "bindings", data: bindings() });
  expect(
    screen.getByRole("option", { name: "sample-host · 1 binding" }),
  ).toBeVisible();
  view.unmount();
  draw({
    page: "add-binding",
    data: {
      ...addBinding(),
      Agents: [{ Name: "sample-host", Count: 2, Selected: false }],
    },
  });
  expect(
    screen.getByRole("option", { name: "sample-host · 2 containers" }),
  ).toBeVisible();
});

it("offers Add binding when no binding exists", () => {
  draw({ page: "bindings", data: { ...bindings(), Rows: [] } });
  expect(screen.getByText(/No bindings yet/)).toBeVisible();
  expect(screen.getByRole("link", { name: "Add binding" })).toBeVisible();
});

it.each([
  ["sample-host", ""],
  ["", "absent"],
])(
  "clears a bindings filter that matches nothing with one link (%s, %s)",
  (FilterAgent, Query) => {
    draw({
      page: "bindings",
      data: { ...bindings(), FilterAgent, Query, Rows: [] },
    });
    const message = screen.getByText(/No bindings match these filters\./);
    expect(message).toBeVisible();
    expect(
      within(message).getByRole("link", { name: "Clear filters" }),
    ).toHaveAttribute("href", "/bindings");
  },
);

it.each([
  ["", "", "Every reported container has a binding."],
  ["sample-host", "", "No containers match these filters."],
  ["", "absent", "No containers match these filters."],
])("explains an empty add screen (%s, %s)", (FilterAgent, Query, message) => {
  draw({
    page: "add-binding",
    data: { ...addBinding(), FilterAgent, Query, Rows: [] },
  });
  expect(screen.getByText(message)).toBeVisible();
});

it("sets a grant at operator key approval and asks before revocation", () => {
  draw({
    page: "operator-keys",
    data: {
      ...layout,
      PendingOperatorKeys: 1,
      Current: "operator-keys",
      HostKey: "controller-fingerprint",
      PendingKeys: [
        {
          Label: "sample-label",
          Fingerprint: "SHA256:sample",
          FirstSeen: "2026-01-01T00:00:00Z",
        },
      ],
      Approved: [
        {
          Label: "approved-label",
          Fingerprint: "SHA256:approved",
          State: "approved",
          Agents: ["sample-host"],
          Policies: ["*"],
          Actions: ["read", "bind"],
          DecidedAt: "2026-01-01T00:00:00Z",
          DecidedBy: "sample-operator",
          RevokedAt: "0001-01-01T00:00:00Z",
          RevokedBy: "",
          LastUsed: "0001-01-01T00:00:00Z",
        },
      ],
      Ended: [
        {
          Label: "ended-label",
          Fingerprint: "SHA256:ended",
          State: "revoked",
          Agents: [],
          Policies: null,
          Actions: ["read"],
          DecidedAt: "2026-01-01T00:00:00Z",
          DecidedBy: "sample-operator",
          RevokedAt: "2026-01-02T00:00:00Z",
          RevokedBy: "other-operator",
          LastUsed: "0001-01-01T00:00:00Z",
        },
      ],
      GrantAgents: ["sample-host"],
      GrantPolicies: ["sample-policy"],
    },
  });
  const form = expectPost("Approve key", "/operator-keys/approve", {
    fingerprint: "SHA256:sample",
  });
  expect(within(form).getByLabelText("Label")).toHaveValue("sample-label");
  expect(within(form).getByLabelText("Other agent names")).toHaveValue("");
  expect(within(form).getByLabelText("Other policy names")).toHaveValue("");
  expect(
    within(form).getByRole("checkbox", { name: "sample-host" }),
  ).not.toBeChecked();
  expect(
    within(form).getByRole("checkbox", { name: "sample-policy" }),
  ).not.toBeChecked();
  expect(
    within(form).getByRole("checkbox", { name: "Read policies and bindings" }),
  ).toBeChecked();
  expect(
    within(form).getByRole("checkbox", { name: "Create and remove bindings" }),
  ).not.toBeChecked();
  expect(
    within(form).getByRole("checkbox", { name: "Create and change policies" }),
  ).not.toBeChecked();
  expect(within(form).getByRole("button", { name: "Reject" })).toHaveAttribute(
    "formaction",
    "/operator-keys/reject",
  );
  expect(
    screen.getByRole("link", { name: "Revoke approved-label" }),
  ).toHaveAttribute(
    "href",
    "/operator-keys/revoke?fingerprint=SHA256%3Aapproved",
  );
  expect(screen.getByText("all")).toBeInTheDocument();
  expect(screen.getByText("never")).toBeInTheDocument();
  expect(screen.getByText("other-operator")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /Operator keys/ })).toHaveAttribute(
    "aria-current",
    "page",
  );
  expect(screen.getByLabelText("1 pending")).toBeInTheDocument();
});

describe("typed-key binding", () => {
  function typed(): BindingData {
    const data = binding(false);
    return {
      ...data,
      Title: "Bind by typed key",
      Row: {
        ...data.Row,
        Agent: "",
        Name: "",
        ID: "",
        Candidates: null,
        Connected: false,
        AssignableGroups: null,
      },
      Reported: false,
      Typed: true,
      AgentChoices: [
        {
          Name: "group-host",
          Selected: false,
          Connected: true,
          AssignableGroups: { groups: [{ gid: 4242, name: "apps" }] },
        },
        {
          Name: "privileged-host",
          Selected: false,
          Connected: true,
          AssignableGroups: { groups: [], any: true },
        },
        { Name: "offline-host", Selected: false, Connected: false },
      ],
      Form: { ...data.Form, Key: "", Agent: "" },
    };
  }
  function groupSelect(container: HTMLElement) {
    return container.querySelector<HTMLSelectElement>("#binding-group")!;
  }

  it("offers the selected agent's groups and submits the chosen one", async () => {
    const user = userEvent.setup();
    const { container } = draw({ page: "binding", data: typed() });
    await user.selectOptions(screen.getByLabelText("Agent"), "group-host");
    await user.type(screen.getByLabelText("Key value"), "shop/web");
    await user.type(screen.getByLabelText("Directory name"), "shop-web");
    await user.click(screen.getByRole("tab", { name: /Settings/ }));
    expect(
      [...groupSelect(container).options].map((option) => option.value),
    ).toEqual(["", "4242"]);
    await user.selectOptions(groupSelect(container), "4242");
    expectPost("Bind policies", "/bindings?tab=settings", {
      typed: "yes",
      agent: "group-host",
      key: "compose:shop/web",
      directory: "shop-web",
      "access-group": "4242",
    });
    expect(
      within(screen.getByLabelText("Binding decisions")).getByText(
        "apps (4242)",
      ),
    ).toBeInTheDocument();

    // Another agent's capabilities replace them, and the choice is unverified.
    await user.selectOptions(screen.getByLabelText("Agent"), "offline-host");
    expect(
      [...groupSelect(container).options].map((option) => option.textContent),
    ).toEqual(["Owner-only (omit access group)", "4242 (unverified)"]);
    expect(screen.getByText(/the agent is offline/)).toBeInTheDocument();
  });

  it("takes another numeric group for an agent that can assign any", async () => {
    const user = userEvent.setup();
    const { container } = draw({ page: "binding", data: typed() });
    await user.selectOptions(screen.getByLabelText("Agent"), "privileged-host");
    await user.click(screen.getByRole("tab", { name: /Settings/ }));
    await user.selectOptions(groupSelect(container), "custom");
    await user.type(screen.getByLabelText("Numeric access group"), "1234");
    expectPost("Bind policies", "/bindings?tab=settings", {
      agent: "privileged-host",
      "access-group": "1234",
    });
  });

  it("offers only owner-only access before an agent is chosen", () => {
    const { container } = draw({ page: "binding", data: typed() });
    expect(
      [...groupSelect(container).options].map((option) => option.value),
    ).toEqual([""]);
  });
});
