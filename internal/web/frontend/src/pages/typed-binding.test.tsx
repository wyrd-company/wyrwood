// ---
// relationships:
//   verifies: web-interface
// ---
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { expect, it } from "vitest";
import type { BindingData } from "@/types";
import { TypedKey } from "./typed-key";
import { DecisionSummary, savedDecisions } from "./decision-summary";

function data(overrides: Partial<BindingData> = {}) {
  return {
    Row: { Bound: false, Candidates: null, Agent: "", Name: "" },
    Typed: true,
    AgentChoices: [
      { Name: "approved-a", Selected: false },
      { Name: "approved-b", Selected: true },
    ],
    Policies: [],
    Form: { Key: "", Revision: 0, Understood: false, Settings: {} },
    ...overrides,
  } as unknown as BindingData;
}

// Keyed holds the selected agent as the binding form does.
function Keyed({ data: d }: { data: BindingData }) {
  const [agent, setAgent] = useState(d.Form.Agent ?? "");
  return <TypedKey data={d} agent={agent} onAgent={setAgent} />;
}

it("posts a typed key, an approved agent, and a directory name", async () => {
  const user = userEvent.setup();
  const { container } = render(
    <form>
      <Keyed data={data({ Form: { ...data().Form, Agent: "approved-b" } })} />
    </form>,
  );
  const form = container.querySelector("form")!;
  const agent = screen.getByLabelText<HTMLSelectElement>("Agent");
  // Only the approved agents the screen lists can be chosen.
  expect(
    [...agent.options].filter((o) => !o.disabled).map((o) => o.value),
  ).toEqual(["approved-a", "approved-b"]);
  expect(agent).toBeRequired();
  expect(agent).toHaveValue("approved-b");

  expect(screen.getByLabelText("Key kind")).toHaveValue("compose");
  await user.type(screen.getByLabelText("Key value"), "shop/web");
  await user.type(screen.getByLabelText("Directory name"), "shop-web");
  const entered = new FormData(form);
  expect(entered.get("typed")).toBe("yes");
  expect(entered.get("agent")).toBe("approved-b");
  expect(entered.get("key")).toBe("compose:shop/web");
  expect(entered.get("directory")).toBe("shop-web");
  // The kind and value are posted only as the key.
  expect(entered.has("key-kind")).toBe(false);
});

it("asks for no directory name for a name key", async () => {
  const user = userEvent.setup();
  const { container } = render(
    <form>
      <Keyed data={data()} />
    </form>,
  );
  const form = container.querySelector("form")!;
  await user.selectOptions(screen.getByLabelText("Key kind"), "name");
  await user.type(screen.getByLabelText("Key value"), "worker");
  expect(screen.queryByLabelText("Directory name")).toBeNull();
  const entered = new FormData(form);
  expect(entered.get("key")).toBe("name:worker");
  expect(entered.has("directory")).toBe(false);

  await user.selectOptions(screen.getByLabelText("Key kind"), "devcontainer");
  expect(screen.getByLabelText("Directory name")).toBeInTheDocument();
  expect(new FormData(form).get("key")).toBe("devcontainer:worker");
});

it("refuses a directory name that the rule refuses", () => {
  render(
    <form>
      <Keyed data={data()} />
    </form>,
  );
  const input = screen.getByLabelText<HTMLInputElement>("Directory name");
  for (const refused of ["a/b", "..", ".hidden", "-web", "web app"]) {
    input.value = refused;
    expect(input.checkValidity(), refused).toBe(false);
  }
  for (const accepted of ["shop-web", "a", "web_1.2"]) {
    input.value = accepted;
    expect(input.checkValidity(), accepted).toBe(true);
  }
  expect(input).toHaveAttribute("maxlength", "255");
});

it("keeps entered values after a refused submission", () => {
  const refused = data({
    Form: {
      Key: "devcontainer:/src/app",
      Agent: "approved-a",
      Directory: "a/b",
      Revision: 0,
      Understood: false,
      Settings: {},
    },
  });
  const { container } = render(
    <form>
      <Keyed data={refused} />
    </form>,
  );
  expect(screen.getByLabelText("Key kind")).toHaveValue("devcontainer");
  expect(screen.getByLabelText("Key value")).toHaveValue("/src/app");
  expect(screen.getByLabelText("Directory name")).toHaveValue("a/b");
  expect(screen.getByLabelText("Agent")).toHaveValue("approved-a");
  expect(new FormData(container.querySelector("form")!).get("key")).toBe(
    "devcontainer:/src/app",
  );
});

it("summarizes the agent, key, and directory name", () => {
  const saved = data({
    Form: {
      Key: "compose:shop/web",
      Agent: "approved-b",
      Directory: "shop-web",
      Revision: 0,
      Understood: false,
      Settings: {},
    },
  });
  render(<DecisionSummary data={saved} decisions={savedDecisions(saved)} />);
  expect(screen.getByText("approved-b")).toBeInTheDocument();
  expect(screen.getByText("compose · shop/web")).toBeInTheDocument();
  expect(screen.getByText("shop-web")).toBeInTheDocument();
});
