// ---
// relationships:
//   implements: web-interface
// ---
import type { Page } from "./types";
import { Sidebar } from "./components/sidebar";
import { SignIn } from "./pages/sign-in";
import { Agents } from "./pages/agents";
import { Containers } from "./pages/containers";
import { Confirm } from "./pages/confirm";
import { Policies } from "./pages/policies";
import { PolicyEditor } from "./pages/policy-editor";
import { Keys } from "./pages/keys";
import { Events } from "./pages/events";
import { Security } from "./pages/security";
function Content({ page }: { page: Page }) {
  switch (page.page) {
    case "sign-in":
      return <SignIn data={page.data} />;
    case "agents":
      return <Agents data={page.data} />;
    case "containers":
      return <Containers data={page.data} />;
    case "confirm":
      return <Confirm data={page.data} />;
    case "policies":
      return <Policies data={page.data} />;
    case "policy":
      return <PolicyEditor data={page.data} />;
    case "keys":
      return <Keys data={page.data} />;
    case "events":
      return <Events data={page.data} />;
    case "security":
      return <Security data={page.data} />;
  }
}
export function App({ page }: { page: Page }) {
  if (page.page === "sign-in") return <Content page={page} />;
  return (
    <div className="app">
      <Sidebar data={page.data} />
      <div className="page">
        <header className="topbar">
          <h1>{page.data.Title}</h1>
        </header>
        <Content page={page} />
      </div>
    </div>
  );
}
