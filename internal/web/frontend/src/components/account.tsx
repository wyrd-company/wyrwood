// ---
// relationships:
//   implements: web-interface
// ---
import { Button, CSRF } from "./shared";
import type { Layout } from "@/types";
export function Account({ data }: { data: Layout }) {
  return (
    <div className="who">
      <span>{data.Operator}</span>
      <form className="inline" method="post" action="/sign-out">
        <CSRF token={data.CSRF} />
        <Button variant="outline" type="submit">
          Sign out
        </Button>
      </form>
    </div>
  );
}
