// ---
// relationships:
//   verifies: web-interface
// ---
import {
  render,
  screen,
  within,
  waitFor,
  fireEvent,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { HCLEditor } from "./components/hcl-editor";
import { DurationPicker } from "./components/duration-picker";
import { IdentityPicker } from "./components/identity-picker";
import { EnvironmentEditor } from "./components/environment-editor";
import { graphicalRules, addSelfOperations } from "./lib/policy-hcl";

const basic =
  '# Keep this comment\npath "kv/data/example/*" { capabilities = ["read"] }\n// Keep this too\n';
function hcl() {
  return new FormData(screen.getByTestId("form") as HTMLFormElement).get(
    "hcl",
  ) as string;
}
function editor(value: string, mounts: string[] = []) {
  return render(
    <form data-testid="form">
      <HCLEditor value={value} mounts={mounts} />
    </form>,
  );
}
afterEach(() => vi.unstubAllGlobals());
it("round-trips graphical HCL exactly and edits only the selected source span", async () => {
  const user = userEvent.setup();
  editor(basic);
  expect(hcl()).toBe(basic);
  await user.click(screen.getByRole("button", { name: "Raw HCL" }));
  expect(screen.getByLabelText("OpenBao policy HCL")).toHaveValue(basic);
  await user.click(screen.getByRole("button", { name: "Graphical paths" }));
  expect(hcl()).toBe(basic);
  await user.click(
    within(screen.getByRole("group", { name: "Path 1" })).getByRole(
      "checkbox",
      { name: "list" },
    ),
  );
  expect(hcl()).toBe(basic.replace('["read"]', '["read","list"]'));
  await user.clear(screen.getByLabelText("Path 1"));
  await user.type(screen.getByLabelText("Path 1"), "kv/data/other/+");
  expect(hcl()).toContain('path "kv/data/other/+"');
  expect(hcl()).toContain("# Keep this comment");
  expect(hcl()).toContain("// Keep this too");
});
it.each([
  'path "kv/data/line\\nbreak" { capabilities = ["read"] }',
  'path "kv/data/line\\rbreak" { capabilities = ["read"] }',
  'path "kv/data/example" { capabilities = ["read"] min_wrapping_ttl = "1m" }',
  'path "kv/data/example" { capabilities = ["read"] allowed_parameters = { "value" = [] } }',
  'path "kv/data/example" { policy = "read" }',
  'path "kv/data/example" { capabilities = ["read", "future-capability"] }',
  'path "kv/data/${identity.entity.id}" { capabilities = ["read"] }',
  'path "kv/data/%{value}" { capabilities = ["read"] }',
  'path "kv/data/example" { capabilities = ["read"] # keep inline comment\n}',
  '{"path":{"kv/data/example":{"capabilities":["read"]}}}',
  basic + 'unknown = "preserve"',
  'path "broken" { capabilities = [',
])("keeps unsupported HCL raw and complete: %s", async (value) => {
  editor(value);
  expect(graphicalRules(value)).toBeNull();
  expect(screen.getByLabelText("OpenBao policy HCL")).toHaveValue(value);
  expect(
    screen.getByRole("button", { name: "Graphical paths" }),
  ).toBeDisabled();
  expect(
    screen.getByRole("button", { name: "Add token self-operation preset" }),
  ).toBeDisabled();
  expect(hcl()).toBe(value);
});
it("preserves arbitrary raw edits and returns to graphics only after all constructs are representable", async () => {
  const user = userEvent.setup();
  editor(basic);
  await user.click(screen.getByRole("button", { name: "Raw HCL" }));
  const raw = screen.getByLabelText("OpenBao policy HCL");
  await user.clear(raw);
  await user.type(raw, 'arbitrary = "retain me"');
  expect(hcl()).toBe('arbitrary = "retain me"');
  expect(
    screen.getByRole("button", { name: "Graphical paths" }),
  ).toBeDisabled();
  await user.clear(raw);
  expect(screen.getByRole("button", { name: "Graphical paths" })).toBeEnabled();
  await user.click(screen.getByRole("button", { name: "Graphical paths" }));
  expect(hcl()).toBe("");
});
it("adds and removes a custom path and adds the idempotent self-operation preset", async () => {
  const user = userEvent.setup();
  editor("");
  await user.type(screen.getByLabelText("New path"), "other/data/+/example*");
  await user.click(screen.getByRole("button", { name: "Add path" }));
  expect(hcl()).toContain('path "other/data/+/example*"');
  await user.click(
    screen.getByRole("button", { name: "Add token self-operation preset" }),
  );
  const preset = hcl();
  expect(
    graphicalRules(preset)?.map((rule) => [rule.path, rule.capabilities]),
  ).toEqual([
    ["other/data/+/example*", ["read"]],
    ["auth/token/lookup-self", ["read"]],
    ["auth/token/renew-self", ["update"]],
    ["auth/token/revoke-self", ["update"]],
  ]);
  expect(addSelfOperations(preset)).toBe(preset);
  await user.click(screen.getByRole("button", { name: "Remove path 1" }));
  expect(hcl()).not.toContain("other/data");
  expect(hcl()).toContain("auth/token/renew-self");
});
it("browses configured KV mounts, nested folders, subtrees, and metadata LIST paths", async () => {
  const user = userEvent.setup();
  const fetcher = vi.fn(async (url: string) => ({
    ok: true,
    json: async () => ({
      Paths: url.includes("prefix=folder%2F")
        ? ["nested"]
        : ["folder/", "sample"],
    }),
  }));
  vi.stubGlobal("fetch", fetcher);
  editor("", ["kv", "team/kv"]);
  await user.click(await screen.findByRole("button", { name: "Add sample" }));
  expect(hcl()).toContain('path "kv/data/sample" { capabilities = ["read"] }');
  await user.click(screen.getByRole("button", { name: "Add folder/" }));
  expect(hcl()).toContain('path "kv/data/folder/*"');
  await user.click(screen.getByRole("button", { name: "Open folder/" }));
  await user.click(await screen.findByRole("button", { name: "Add nested" }));
  expect(hcl()).toContain('path "kv/data/folder/nested"');
  await user.click(
    screen.getByRole("button", { name: "Add LIST path for this directory" }),
  );
  expect(hcl()).toContain(
    'path "kv/metadata/folder/*" { capabilities = ["list"] }',
  );
  await user.selectOptions(screen.getByLabelText("KV mount"), "team/kv");
  await waitFor(() =>
    expect(fetcher).toHaveBeenLastCalledWith(
      "/policies/kv?mount=team%2Fkv&prefix=",
      expect.anything(),
    ),
  );
  await user.click(await screen.findByRole("button", { name: "Add sample" }));
  expect(hcl()).toContain('path "team/kv/data/sample"');
});
it("shows list failures with retry while keeping manual paths usable", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false }));
  const user = userEvent.setup();
  editor("", ["kv"]);
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "metadata LIST permission",
  );
  await user.type(screen.getByLabelText("New path"), "kv/data/manual");
  await user.click(screen.getByRole("button", { name: "Add path" }));
  expect(hcl()).toContain('path "kv/data/manual"');
  await user.click(screen.getByRole("button", { name: "Refresh paths" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "metadata LIST permission",
  );
});
it("retains missing and selector-only identities and edits offered and forwarding toggles independently", async () => {
  const user = userEvent.setup();
  render(
    <form data-testid="form">
      <IdentityPicker
        title="Transit keys"
        name="transit-keys"
        available={["available"]}
        selected="missing"
        restricted="selector-only"
      />
    </form>,
  );
  const values = () =>
    new FormData(screen.getByTestId("form") as HTMLFormElement);
  expect(screen.getByRole("checkbox", { name: /^missing/ })).toBeChecked();
  expect(
    screen.getByRole("checkbox", { name: "Not forwardable selector-only" }),
  ).toBeChecked();
  expect(values().get("transit-keys")).toBe("missing");
  expect(values().get("not-forwardable-transit-keys")).toBe("selector-only");
  await user.click(screen.getByRole("checkbox", { name: /^available$/ }));
  await user.click(
    screen.getByRole("checkbox", { name: "Not forwardable available" }),
  );
  expect(values().get("transit-keys")).toBe("missing\navailable");
  expect(values().get("not-forwardable-transit-keys")).toBe(
    "selector-only\navailable",
  );
  await user.type(
    screen.getByLabelText("Additional transit keys name"),
    "future-selector",
  );
  await user.click(screen.getByRole("button", { name: "Add identity name" }));
  expect(
    screen.getByText(
      "Not selected. Choose offered or not-forwardable to save this name.",
    ),
  ).toBeInTheDocument();
  await user.click(
    screen.getByRole("checkbox", { name: "Not forwardable future-selector" }),
  );
  expect(values().get("transit-keys")).toBe("missing\navailable");
  expect(values().get("not-forwardable-transit-keys")).toBe(
    "selector-only\navailable\nfuture-selector",
  );
  await user.click(
    screen.getByRole("checkbox", { name: "Not forwardable future-selector" }),
  );
  await user.click(screen.getByRole("checkbox", { name: /^available$/ }));
  expect(values().get("not-forwardable-transit-keys")).toBe(
    "selector-only\navailable",
  );
});
it("keeps environment equals signs and mount placeholders and supports adding and removing variables", async () => {
  const user = userEvent.setup();
  render(
    <form data-testid="form">
      <EnvironmentEditor
        value={"EXAMPLE=abc=def\nSOCKET={mount-target}/example.sock"}
      />
    </form>,
  );
  const env = () =>
    new FormData(screen.getByTestId("form") as HTMLFormElement).get("env");
  expect(env()).toBe("EXAMPLE=abc=def\nSOCKET={mount-target}/example.sock");
  await user.click(screen.getByRole("button", { name: "Add variable" }));
  expect(env()).toBe("EXAMPLE=abc=def\nSOCKET={mount-target}/example.sock");
  await user.type(screen.getByLabelText("Variable 3 name"), "SAMPLE");
  await user.type(screen.getByLabelText("Variable 3 value"), "value");
  await user.click(screen.getByRole("button", { name: "Remove variable 1" }));
  expect(env()).toBe("SOCKET={mount-target}/example.sock\nSAMPLE=value");
});
it("submits duration picker amounts and units with binding minutes/hours and role seconds", async () => {
  const user = userEvent.setup();
  render(
    <form data-testid="form">
      <label htmlFor="duration">Duration</label>
      <DurationPicker id="duration" name="token-ttl" value="30m" binding />
    </form>,
  );
  const duration = () =>
    new FormData(screen.getByTestId("form") as HTMLFormElement).get(
      "token-ttl",
    );
  expect(duration()).toBe("30m");
  expect(
    screen.queryByRole("option", { name: "Seconds" }),
  ).not.toBeInTheDocument();
  await user.clear(screen.getByLabelText("Duration"));
  expect(duration()).toBe("");
  await user.type(screen.getByLabelText("Duration"), "4");
  await user.selectOptions(screen.getByLabelText("token-ttl unit"), "h");
  expect(duration()).toBe("4h");
});

it("does not turn literal KV names into wildcard grants, including inside a browsed folder", async () => {
  const user = userEvent.setup();
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => ({
      ok: true,
      json: async () => ({
        Paths: url.includes("prefix=%2B%2F")
          ? ["nested"]
          : ["+/", "sample*", "mid*dle", "${sample}", "%{sample}", "safe"],
      }),
    })),
  );
  editor("", ["kv"]);
  for (const name of ["+/", "sample*", "mid*dle", "${sample}", "%{sample}"]) {
    expect(
      await screen.findByRole("button", { name: `Add ${name}` }),
    ).toBeDisabled();
  }
  expect(
    screen.getByText(/cannot be added as literal paths/),
  ).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Add safe" }));
  expect(hcl()).toBe('path "kv/data/safe" { capabilities = ["read"] }\n');
  await user.click(screen.getByRole("button", { name: "Open +/" }));
  expect(
    await screen.findByRole("button", { name: "Add nested" }),
  ).toBeDisabled();
  expect(
    screen.getByRole("button", { name: "Add LIST path for this directory" }),
  ).toBeDisabled();
  expect(hcl()).toBe('path "kv/data/safe" { capabilities = ["read"] }\n');
});
it.each(["${sample}", "%{sample}"])(
  "keeps template syntax %s out of graphical path edits without switching views",
  async (template) => {
    const user = userEvent.setup();
    editor(basic);
    const path = screen.getByLabelText("Path 1");
    await user.click(path);
    fireEvent.change(path, { target: { value: `kv/data/${template}` } });
    expect(path).toHaveFocus();
    expect(path).toHaveValue("kv/data/example/*");
    expect(screen.getByText(/graphical path is unchanged/)).toBeInTheDocument();
    expect(
      screen.queryByLabelText("OpenBao policy HCL"),
    ).not.toBeInTheDocument();
    expect(hcl()).toBe(basic);
    fireEvent.change(screen.getByLabelText("New path"), {
      target: { value: `kv/data/${template}` },
    });
    expect(screen.getByRole("button", { name: "Add path" })).toBeDisabled();
    expect(hcl()).toBe(basic);
    await user.click(screen.getByRole("button", { name: "Raw HCL" }));
    expect(screen.getByLabelText("OpenBao policy HCL")).toHaveValue(basic);
  },
);
it("keeps nonempty invalid environment entries for validation while omitting empty rows", async () => {
  const user = userEvent.setup();
  render(
    <form data-testid="form">
      <EnvironmentEditor value="" />
    </form>,
  );
  const env = () =>
    new FormData(screen.getByTestId("form") as HTMLFormElement).get("env");
  await user.click(screen.getByRole("button", { name: "Add variable" }));
  expect(env()).toBe("");
  await user.type(screen.getByLabelText("Variable 1 value"), "sample");
  expect(env()).toBe("=sample");
  await user.clear(screen.getByLabelText("Variable 1 value"));
  expect(env()).toBe("");
});

it("does not generate grants for literal KV names containing OpenBao ACL templates", async () => {
  const user = userEvent.setup();
  const names = ["{{identity.entity.id}}", "unclosed{{", "nested{{template}}"];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => ({
      ok: true,
      json: async () => ({
        Paths: new URL(url, "http://example.test").searchParams.get("prefix")
          ? ["nested"]
          : ["closing}}", ...names, ...names.map((name) => name + "/")],
      }),
    })),
  );
  editor(basic, ["kv"]);
  for (const name of names) {
    expect(
      await screen.findByRole("button", { name: `Add ${name}` }),
    ).toBeDisabled();
    expect(screen.getByRole("button", { name: `Add ${name}/` })).toBeDisabled();
  }
  expect(screen.getByText(/ACL templating/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Add closing}}" })).toBeEnabled();
  for (const name of names) {
    await user.click(
      await screen.findByRole("button", { name: `Open ${name}/` }),
    );
    expect(
      await screen.findByRole("button", { name: "Add nested" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Add LIST path for this directory" }),
    ).toBeDisabled();
    expect(hcl()).toBe(basic);
    await user.click(screen.getByRole("button", { name: "Up one level" }));
  }
});
it("preserves deliberately authored OpenBao ACL templates in both policy views", async () => {
  const user = userEvent.setup();
  editor("");
  fireEvent.change(screen.getByLabelText("New path"), {
    target: { value: "kv/data/{{identity.entity.id}}" },
  });
  await user.click(screen.getByRole("button", { name: "Add path" }));
  const source =
    'path "kv/data/{{identity.entity.id}}" { capabilities = ["read"] }\n';
  expect(hcl()).toBe(source);
  expect(screen.getByLabelText("Path 1")).toHaveValue(
    "kv/data/{{identity.entity.id}}",
  );
  await user.click(screen.getByRole("button", { name: "Raw HCL" }));
  expect(screen.getByLabelText("OpenBao policy HCL")).toHaveValue(source);
  await user.click(screen.getByRole("button", { name: "Graphical paths" }));
  expect(hcl()).toBe(source);
});
