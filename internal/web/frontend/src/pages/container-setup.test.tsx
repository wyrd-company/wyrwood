// ---
// relationships:
//   verifies: web-interface
// ---
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { ContainerSetup } from "./container-setup";

it("shows and copies the reported setup values", async () => {
  const user = userEvent.setup();
  const write = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();
  const setup = {
    Source: "/srv/sample/app",
    Target: "/opt/sample",
    Compose: "services: {}",
    DockerRun: "docker run alpine",
  };
  render(<ContainerSetup setup={setup} />);
  for (const [label, value] of [
    ["Host source", setup.Source],
    ["Container target", setup.Target],
    ["Docker Compose", setup.Compose],
    ["docker run", setup.DockerRun],
  ]) {
    expect(screen.getByText(value)).toBeVisible();
    await user.click(screen.getByRole("button", { name: `Copy ${label}` }));
    expect(write).toHaveBeenLastCalledWith(value);
    expect(screen.getByText(`${label} copied.`)).toBeVisible();
  }
});

it("keeps selectable examples when clipboard access fails", async () => {
  const user = userEvent.setup();
  vi.spyOn(navigator.clipboard, "writeText").mockRejectedValue(
    new Error("unavailable"),
  );
  render(
    <ContainerSetup
      setup={{
        Source: "/srv/sample",
        Target: "/opt/sample",
        Compose: "services: {}",
        DockerRun: "docker run alpine",
      }}
    />,
  );
  await user.click(screen.getByRole("button", { name: "Copy Host source" }));
  expect(screen.getByRole("status")).toHaveTextContent(
    "Select and copy the Host source text below.",
  );
  expect(screen.getByText("/srv/sample")).toBeVisible();
});

it("does not guess a path when an older report omits setup data", () => {
  render(<ContainerSetup setup={null} />);
  expect(screen.getByText(/Setup examples are unavailable/)).toBeVisible();
  expect(screen.queryByRole("button")).not.toBeInTheDocument();
});
