// ---
// relationships:
//   verifies: composable-policy-bindings
// ---
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { BindingSettings } from "./binding-settings";

it("offers only process groups and owner-only, preserving invalid selections", async () => {
  const user = userEvent.setup();
  const { container } = render(
    <form>
      <BindingSettings
        connected
        groups={{ groups: [{ gid: 987, name: "sample" }, { gid: 1234 }] }}
        settings={{
          "access-group": 0,
          "token-ttl": "1h",
          "token-max-ttl": "8h",
          enforcement: "report",
        }}
      />
    </form>,
  );
  const select = screen.getByLabelText("Access group");
  expect(
    screen.getByRole("option", { name: "sample (987)" }),
  ).toBeInTheDocument();
  expect(screen.getByRole("option", { name: "1234" })).toBeInTheDocument();
  expect(select).toHaveValue("0");
  expect(screen.getByRole("alert")).toHaveTextContent("cannot assign group 0");
  const form = container.querySelector("form")!;
  expect(new FormData(form).get("access-group")).toBe("0");
  await user.selectOptions(select, "987");
  expect(new FormData(form).get("access-group")).toBe("987");
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  await user.selectOptions(select, "");
  expect(new FormData(form).get("access-group")).toBe("");
  expect(screen.getByText(/No access group:/)).toBeInTheDocument();
  expect(screen.getByText(/s6-setuidgid/)).toHaveTextContent(
    "primary GID need not match",
  );
});

it.each([true, false])(
  "labels old or offline capabilities unverified (connected %s)",
  (connected) => {
    render(
      <BindingSettings
        connected={connected}
        groups={connected ? undefined : { groups: [{ gid: 987 }] }}
        settings={{
          "access-group": 987,
          "token-ttl": "1h",
          "token-max-ttl": "8h",
          enforcement: "report",
        }}
      />,
    );
    expect(
      screen.getByRole("option", { name: "987 (unverified)" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Group capabilities are unavailable or stale/),
    ).toBeInTheDocument();
  },
);

it("allows a privileged agent to assign another numeric GID", async () => {
  const user = userEvent.setup();
  const { container } = render(
    <form>
      <BindingSettings connected groups={{ any: true, groups: [{ gid: 0 }] }} />
    </form>,
  );
  await user.selectOptions(screen.getByLabelText("Access group"), "custom");
  await user.type(screen.getByLabelText("Numeric access group"), "1234");
  expect(
    new FormData(container.querySelector("form")!).getAll("access-group"),
  ).toEqual(["1234"]);
});
