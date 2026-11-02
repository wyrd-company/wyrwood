// ---
// relationships:
//   implements: web-interface
// ---
import { Notice } from "@/components/shared";
import type { BindingData } from "@/types";
import { BindingForm, BindingHeading } from "./binding-form";

export function Binding({ data: d }: { data: BindingData }) {
  const r = d.Row;
  // The form reports its own problem, so its reload link keeps the selected tab.
  const hasForm = r.Bound || Boolean(d.Policies?.length);
  return (
    <main className="wide">
      <a href={d.Back}>
        {r.Bound ? "Back to bindings" : "Back to Add binding"}
      </a>
      <Notice text={d.Notice} />
      {hasForm ? (
        <BindingForm data={d} />
      ) : (
        <>
          {d.Problem && (
            <p className="problem" role="alert">
              {d.Problem}
            </p>
          )}
          <section className="card" aria-labelledby="h-container">
            <BindingHeading data={d} />
            <p className="hint">
              Create a policy before binding.{" "}
              <a href="/policies/edit">New policy</a>
            </p>
          </section>
        </>
      )}
    </main>
  );
}
