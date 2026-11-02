// ---
// relationships:
//   implements: web-interface
// ---
import { Button, CSRF, Field, Input, Panel } from "@/components/shared";
import type { PolicyRenameData } from "@/types";
import { PolicyBindings } from "./policy-bindings";
export function PolicyRename({ data: d }: { data: PolicyRenameData }) {
  return (
    <main>
      <Panel aria-labelledby="h-rename" className="max-w-[640px]">
        <h2 id="h-rename">Rename policy {d.Name}</h2>
        {d.Problem && (
          <p className="problem" role="alert">
            {d.Problem}
          </p>
        )}
        <p>{d.Consequence}</p>
        <p>
          The policy keeps its document and bindings, and moves from{" "}
          <code>{d.Identity}</code> to a new OpenBao policy. A later policy
          created as {d.Name} is a different policy, and a token of this one has
          no access to it.
        </p>
        <form method="post" action={d.Action}>
          <CSRF token={d.CSRF} />
          <input type="hidden" name="revision" value={d.Revision} />
          <input type="hidden" name="generation" value={d.Generation} />
          <Field
            label="New name"
            id="new-name"
            hint="Lower-kebab-case, and not a name another policy uses."
          >
            <Input
              id="new-name"
              name="new-name"
              type="text"
              defaultValue={d.NewName}
              required
              pattern="[a-z][a-z0-9]*(-[a-z0-9]+)*"
              maxLength={64}
            />
          </Field>
          <div className="actions">
            <Button type="submit" className="primary">
              Rename policy
            </Button>
            <Button asChild variant="outline">
              <a href={d.Back}>Cancel</a>
            </Button>
          </div>
        </form>
      </Panel>
      {d.Bindings?.length ? (
        <PolicyBindings
          rows={d.Bindings}
          hint="Each of these bindings moves to the new name."
        />
      ) : null}
    </main>
  );
}
