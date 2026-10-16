// ---
// relationships:
//   implements: web-interface
// ---
import { Button, CSRF, Panel } from "@/components/shared";
import type { ConfirmData } from "@/types";
export function Confirm({ data: d }: { data: ConfirmData }) {
  return (
    <main>
      <Panel aria-labelledby="h-confirm" className="max-w-[640px]">
        <h2 id="h-confirm">{d.Heading}</h2>
        {d.Problem ? (
          <p className="problem" role="alert">
            {d.Problem}
          </p>
        ) : (
          <p>{d.Body}</p>
        )}
        <div className="actions">
          {d.Action && (
            <form method="post" action={d.Action}>
              <CSRF token={d.CSRF} />
              <Button
                variant={d.Danger ? "outline" : "default"}
                type="submit"
                className={d.Danger ? "danger" : "primary"}
              >
                {d.Button}
              </Button>
            </form>
          )}
          <Button asChild variant="outline">
            <a href={d.Back}>{d.Action ? "Cancel" : "Back"}</a>
          </Button>
        </div>
      </Panel>
    </main>
  );
}
