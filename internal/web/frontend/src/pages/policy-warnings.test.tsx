import userEvent from "@testing-library/user-event";
// ---
// relationships:
//   verifies: web-interface
// ---
import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import type { PolicyData } from "@/types";
import { PolicyEditor } from "./policy-editor";

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
  New: true,
  Name: "sample",
  Revision: 0,
  Bindings: 0,
  Agents: 0,
  HCL: 'path "sample-data/*" { capabilities = ["read"] }',
  Warnings: ["Initial server warning"],
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
const response = (warnings: string[]) =>
  new Response(JSON.stringify({ warnings }), {
    headers: { "Content-Type": "application/json" },
  });
afterEach(() => vi.unstubAllGlobals());

it("checks unsaved HCL on blur through the server API and keeps saving enabled", async () => {
  const fetch = vi.fn().mockResolvedValue(response(["Sample mount warning"]));
  vi.stubGlobal("fetch", fetch);
  render(<PolicyEditor data={data} />);
  expect(screen.getByText("Initial server warning")).toBeVisible();
  fireEvent.click(screen.getByRole("button", { name: "Raw HCL" }));
  const hcl = screen.getByLabelText("OpenBao policy HCL");
  const document = 'path "*" { capabilities = ["read"] }';
  fireEvent.change(hcl, { target: { value: document } });
  expect(screen.queryByText("Initial server warning")).not.toBeInTheDocument();
  fireEvent.blur(hcl);
  expect(await screen.findByText("Sample mount warning")).toBeVisible();
  const [url, request] = fetch.mock.calls[0];
  expect(url).toBe("/policies/warnings");
  expect(request.method).toBe("POST");
  expect(Object.fromEntries(request.body)).toEqual({
    csrf: data.CSRF,
    hcl: document,
  });
  const save = screen.getByRole("button", { name: "Save and validate" });
  expect(save).toBeEnabled();
  const form = save.closest("form")!;
  expect(form).toHaveAttribute("action", "/policies");
  expect(new FormData(form).get("hcl")).toBe(document);
});

it.each(["network", "http", "json"])(
  "keeps saving available after a %s warning-check failure",
  async (failure) => {
    const fetch = vi.fn();
    if (failure === "network") fetch.mockRejectedValue(new Error("offline"));
    if (failure === "http")
      fetch.mockResolvedValue(
        new Response(JSON.stringify({ warnings: [] }), { status: 503 }),
      );
    if (failure === "json") fetch.mockResolvedValue(new Response("sign in"));
    vi.stubGlobal("fetch", fetch);
    render(<PolicyEditor data={data} />);
    fireEvent.click(screen.getByRole("button", { name: "Raw HCL" }));
    fireEvent.blur(screen.getByLabelText("OpenBao policy HCL"));
    expect(
      await screen.findByText(/The HCL warning check is unavailable/),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Save and validate" }),
    ).toBeEnabled();
  },
);

it("discards a warning response when the HCL changed while it was pending", async () => {
  let finish!: (value: Response) => void;
  const fetch = vi.fn().mockReturnValueOnce(
    new Promise<Response>((resolve) => {
      finish = resolve;
    }),
  );
  fetch.mockResolvedValueOnce(response([]));
  vi.stubGlobal("fetch", fetch);
  render(<PolicyEditor data={data} />);
  fireEvent.click(screen.getByRole("button", { name: "Raw HCL" }));
  const hcl = screen.getByLabelText("OpenBao policy HCL");
  fireEvent.blur(hcl);
  expect(
    screen.getByRole("button", { name: "Save and validate" }),
  ).toBeEnabled();
  fireEvent.change(hcl, { target: { value: "changed HCL" } });
  await act(async () => finish(response(["Stale warning"])));
  expect(screen.queryByText("Stale warning")).not.toBeInTheDocument();
  fireEvent.blur(hcl);
  await act(async () => {});
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(screen.queryByText("Stale warning")).not.toBeInTheDocument();
  expect(screen.queryByText("Initial server warning")).not.toBeInTheDocument();
});

it("discards a failed check for HCL that changed while it was pending", async () => {
  let fail!: (reason: Error) => void;
  vi.stubGlobal(
    "fetch",
    vi.fn().mockReturnValue(
      new Promise<Response>((_, reject) => {
        fail = reject;
      }),
    ),
  );
  render(<PolicyEditor data={data} />);
  fireEvent.click(screen.getByRole("button", { name: "Raw HCL" }));
  const hcl = screen.getByLabelText("OpenBao policy HCL");
  fireEvent.blur(hcl);
  fireEvent.change(hcl, { target: { value: "changed HCL" } });
  await act(async () => fail(new Error("offline")));
  expect(
    screen.queryByText(/The HCL warning check is unavailable/),
  ).not.toBeInTheDocument();
});

it.each(["path", "capability", "remove", "add"])(
  "checks the current source after a graphical %s edit",
  async (action) => {
    const fetch = vi
      .fn()
      .mockResolvedValue(response(["Updated mount warning"]));
    vi.stubGlobal("fetch", fetch);
    render(<PolicyEditor data={data} />);
    if (action === "path") {
      const path = screen.getByRole("textbox", { name: "Path 1" });
      fireEvent.change(path, { target: { value: "outside/data/sample" } });
      expect(
        screen.queryByText("Initial server warning"),
      ).not.toBeInTheDocument();
      fireEvent.blur(path);
    } else if (action === "capability") {
      fireEvent.click(screen.getByRole("checkbox", { name: "update" }));
    } else if (action === "remove") {
      fireEvent.click(screen.getByRole("button", { name: "Remove path 1" }));
    } else {
      fireEvent.change(screen.getByRole("textbox", { name: "New path" }), {
        target: { value: "outside/data/sample" },
      });
      fireEvent.click(screen.getByRole("button", { name: "Add path" }));
    }
    expect(await screen.findByText("Updated mount warning")).toBeVisible();
    const save = screen.getByRole("button", { name: "Save and validate" });
    const submitted = new FormData(save.closest("form")!).get("hcl");
    expect(submitted).not.toBe(data.HCL);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(Object.fromEntries(fetch.mock.calls[0][1].body)).toEqual({
      csrf: data.CSRF,
      hcl: submitted,
    });
    expect(save).toBeEnabled();
  },
);

it("checks the source after adding a browsed KV path", async () => {
  const fetch = vi
    .fn()
    .mockImplementation((url: string) =>
      Promise.resolve(
        url.startsWith("/policies/kv?")
          ? new Response(JSON.stringify({ Paths: ["sample"] }))
          : response(["KV mount warning"]),
      ),
    );
  vi.stubGlobal("fetch", fetch);
  render(<PolicyEditor data={{ ...data, KVMounts: ["kv"] }} />);
  fireEvent.click(await screen.findByRole("button", { name: "Add sample" }));
  expect(await screen.findByText("KV mount warning")).toBeVisible();
  const request = fetch.mock.calls.find(
    ([url]) => url === "/policies/warnings",
  )!;
  expect(request[1].body.get("hcl")).toContain('path "kv/data/sample"');
});

it("discards a raw check after a graphical edit while the check is pending", async () => {
  let finish!: (value: Response) => void;
  vi.stubGlobal(
    "fetch",
    vi.fn().mockReturnValue(
      new Promise<Response>((resolve) => {
        finish = resolve;
      }),
    ),
  );
  render(<PolicyEditor data={data} />);
  fireEvent.click(screen.getByRole("button", { name: "Raw HCL" }));
  fireEvent.blur(screen.getByLabelText("OpenBao policy HCL"));
  fireEvent.click(screen.getByRole("button", { name: "Graphical paths" }));
  fireEvent.change(screen.getByRole("textbox", { name: "Path 1" }), {
    target: { value: "outside/data/sample" },
  });
  await act(async () => finish(response(["Stale raw warning"])));
  expect(screen.queryByText("Stale raw warning")).not.toBeInTheDocument();
});

it("submits the renewal setting and previews fixed lifecycle capabilities", async () => {
  const user = userEvent.setup();
  render(<PolicyEditor data={data} />);
  const checkbox = screen.getByRole("checkbox", {
    name: "Agent token renewal",
  });
  const grants = screen.getByLabelText("Lifecycle grants");
  const form = checkbox.closest("form")!;
  expect(checkbox).toBeChecked();
  expect(new FormData(form).get("agent-token-renewal")).toBe("true");
  expect(grants).toHaveTextContent("auth/token/renew-self");
  await user.click(checkbox);
  expect(new FormData(form).get("agent-token-renewal")).toBe("false");
  expect(grants).not.toHaveTextContent("auth/token/renew-self");
  expect(grants).toHaveTextContent("auth/token/lookup-self");
  expect(grants).toHaveTextContent("auth/token/revoke-self");
});
