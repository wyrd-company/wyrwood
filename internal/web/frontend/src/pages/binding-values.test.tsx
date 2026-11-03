// ---
// relationships:
//   verifies: composable-policy-bindings
// ---
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import type { BindingData } from "@/types";
import { PolicyChoices } from "./binding-sections";
import {
  DecisionSummary,
  enteredDecisions,
  savedDecisions,
} from "./decision-summary";

function data(overrides: Partial<BindingData> = {}) {
  return {
    Row: { Bound: false, Candidates: [] },
    Policies: [
      { Name: "plain", Selected: false, Values: null },
      { Name: "templated", Selected: false, Values: ["slug"] },
      { Name: "also-templated", Selected: false, Values: ["area", "slug"] },
    ],
    Form: { Key: "", Revision: 0, Understood: false, Settings: {} },
    ...overrides,
  } as unknown as BindingData;
}

it("asks for each value that a selected policy uses, once", async () => {
  const user = userEvent.setup();
  const { container } = render(
    <form>
      <PolicyChoices data={data()} />
    </form>,
  );
  expect(screen.queryByText("Values for this binding")).toBeNull();
  await user.click(screen.getByRole("checkbox", { name: "plain" }));
  expect(screen.queryByText("Values for this binding")).toBeNull();

  await user.click(screen.getByRole("checkbox", { name: "templated" }));
  const slug = screen.getByLabelText("slug");
  expect(slug).toBeRequired();
  expect(slug).toHaveAttribute("name", "value.slug");
  expect(screen.queryByLabelText("area")).toBeNull();

  await user.click(screen.getByRole("checkbox", { name: "also-templated" }));
  expect(screen.getAllByLabelText("slug")).toHaveLength(1);
  await user.type(screen.getByLabelText("area"), "beta");
  const form = container.querySelector("form")!;
  expect(new FormData(form).get("value.area")).toBe("beta");

  await user.click(screen.getByRole("checkbox", { name: "also-templated" }));
  expect(screen.queryByLabelText("area")).toBeNull();
  expect(new FormData(form).has("value.area")).toBe(false);
});

it("shows a saved value and refuses text a value cannot hold", () => {
  render(
    <form>
      <PolicyChoices
        data={data({
          Policies: [{ Name: "templated", Selected: true, Values: ["slug"] }],
          Form: {
            Key: "",
            Revision: 1,
            Understood: false,
            Settings: { values: { slug: "alpha" } },
          },
        })}
      />
    </form>,
  );
  const input = screen.getByLabelText<HTMLInputElement>("slug");
  expect(input).toHaveValue("alpha");
  for (const hostile of ["a/b", "*", "..", "a b"]) {
    input.value = hostile;
    expect(input.checkValidity()).toBe(false);
  }
  input.value = "Alpha_1-2";
  expect(input.checkValidity()).toBe(true);
});

it("summarizes saved and entered values", () => {
  const saved = data({
    Form: {
      Key: "",
      Revision: 1,
      Understood: false,
      Settings: { values: { slug: "alpha" } },
    },
  });
  render(<DecisionSummary data={saved} decisions={savedDecisions(saved)} />);
  expect(screen.getByText("Value slug")).toBeInTheDocument();
  expect(screen.getByText("alpha")).toBeInTheDocument();

  const form = document.createElement("form");
  form.innerHTML =
    '<input name="value.slug" value="beta"><input name="value.area" value=""><input name="token-ttl" value="1h">';
  expect(enteredDecisions(form).values).toEqual({ slug: "beta" });
});
