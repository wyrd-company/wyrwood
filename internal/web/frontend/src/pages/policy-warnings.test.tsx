// ---
// relationships:
//   verifies: web-interface
// ---
import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import type { PolicyData } from "@/types";
import { PolicyEditor } from "./policy-editor";

const data: PolicyData = {
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
  const hcl = screen.getByLabelText("OpenBao policy HCL");
  fireEvent.blur(hcl);
  fireEvent.change(hcl, { target: { value: "changed HCL" } });
  await act(async () => fail(new Error("offline")));
  expect(
    screen.queryByText(/The HCL warning check is unavailable/),
  ).not.toBeInTheDocument();
});
