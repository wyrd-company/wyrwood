// ---
// relationships:
//   verifies: web-interface
// ---
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { App } from "./app";
import type {
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
  ...layout,
  Current: "policies",
  New: true,
  Name: "sample",
  Revision: 1,
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
      First: true,
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
    ["Containers", "/containers"],
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
    "/containers?agent=sample%2Fhost",
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
    const data = containers(true);
    data.Selected = {
      ...data.Selected,
      Settings: { ...data.Selected.Settings, "access-group": group },
    };
    draw({ page: "containers", data });
    expect(screen.queryByText(/No access group:/)).not.toBeInTheDocument();
    expectPost("Save binding", "/bindings/sample-binding/policy", {
      "access-group": String(group),
      policies: "sample",
    });
  },
);

function containers(Bound: boolean) {
  return {
    ...layout,
    Current: "containers",
    Agents: [{ Name: "sample-host", Containers: 1, Selected: true }],
    Agent: "sample-host",
    Connected: false,
    Rows: [{ ...row, Bound }],
    Selected: { ...row, Bound },
    Policies: [{ Name: "sample", Selected: true }],
    Recreate: ["sample"],
  };
}
it("preserves container filtering, selection, binding keys and explicit recreate consent", async () => {
  draw({ page: "containers", data: containers(false) });
  const filter = screen.getByRole("button", { name: "Show" }).closest("form")!;
  expect(filter).toHaveAttribute("method", "get");
  expect(filter).toHaveAttribute("action", "/containers");
  expect(new FormData(filter).get("agent")).toBe("sample-host");
  expect(
    screen.getByRole("link", { name: /sample-container/ }),
  ).toHaveAttribute(
    "href",
    "/containers?agent=sample-host&container=sample-id",
  );
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
  await userEvent.click(screen.getByRole("checkbox", { name: /I understand/ }));
  expectPost("Bind policies", "/bindings", { understood: "yes" });
});
it("keeps bound container diagnostics, change policy, and confirmation links", () => {
  draw({ page: "containers", data: containers(true) });
  expect(screen.getByText("sample check")).toBeInTheDocument();
  expect(screen.getByText("FAIL")).toBeInTheDocument();
  expectPost("Save binding", "/bindings/sample-binding/policy", {
    policies: "sample",
  });
  expect(
    screen.getByRole("link", { name: "Request recreate" }),
  ).toHaveAttribute("href", "/bindings/sample-binding/recreate");
  expect(
    screen.getByRole("link", { name: "Unbind and revoke AppRole" }),
  ).toHaveAttribute("href", "/bindings/sample-binding/unbind");
});
it("shows a policy creation link when no policy can be bound", () => {
  draw({ page: "containers", data: { ...containers(false), Policies: null } });
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
        Back: "/containers?agent=sample",
        Danger,
      },
    });
    expectPost("Confirm", "/bindings/sample/unbind");
    expect(screen.getByRole("link", { name: "Cancel" })).toHaveAttribute(
      "href",
      "/containers?agent=sample",
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
      Unavailable: true,
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
  expect(screen.getByRole("alert")).toHaveTextContent("OpenBao did not answer");
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
  expectPost("Save and validate", "/policies", {
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

it("previews several selected policies with binding settings and renewal warning", async () => {
  const user = userEvent.setup();
  const data = containers(false);
  data.Policies.push({ Name: "second", Selected: false });
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
      warnings: ["No explicit renew-self update grant"],
    }),
  });
  vi.stubGlobal("fetch", fetcher);
  try {
    draw({ page: "containers", data });
    await user.click(screen.getByRole("checkbox", { name: "second" }));
    await user.click(
      screen.getByRole("button", { name: "Preview effective policy" }),
    );
    expect(await screen.findByText("combined source HCL")).toBeInTheDocument();
    expect(
      screen.getByText("No explicit renew-self update grant"),
    ).toBeInTheDocument();
    const [url, request] = fetcher.mock.calls[0];
    expect(url).toBe("/bindings/preview");
    expect(request.body.getAll("policies")).toEqual(["sample", "second"]);
    expect(request.body.get("csrf")).toBe("sample-csrf");
    expect(request.body.get("token-ttl")).toBe("1h");
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
    draw({ page: "containers", data: containers(false) });
    await userEvent.click(
      screen.getByRole("button", { name: "Preview effective policy" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "different mount targets",
    );
    expect(screen.getByRole("checkbox", { name: "sample" })).toBeChecked();
  } finally {
    vi.unstubAllGlobals();
  }
});
