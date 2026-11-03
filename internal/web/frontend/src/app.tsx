// ---
// relationships:
//   implements: web-interface
// ---
import type { Page } from "./types";
import { Sidebar } from "./components/sidebar";
import { SignIn } from "./pages/sign-in";
import { Agents } from "./pages/agents";
import { Bindings } from "./pages/bindings";
import { AddBinding } from "./pages/add-binding";
import { Binding } from "./pages/binding";
import { Confirm } from "./pages/confirm";
import { PolicyDelete } from "./pages/policy-delete";
import { PolicyRename } from "./pages/policy-rename";
import { Policies } from "./pages/policies";
import { PolicyEditor } from "./pages/policy-editor";
import { Keys } from "./pages/keys";
import { OperatorKeys } from "./pages/operator-keys";
import { Events } from "./pages/events";
import { Security } from "./pages/security";
import { Settings } from "./pages/settings";
function Content({ page }: { page: Page }) {
  switch (page.page) {
    case "sign-in":
      return <SignIn data={page.data} />;
    case "agents":
      return <Agents data={page.data} />;
    case "bindings":
      return <Bindings data={page.data} />;
    case "add-binding":
      return <AddBinding data={page.data} />;
    case "binding":
      return <Binding data={page.data} />;
    case "confirm":
      return <Confirm data={page.data} />;
    case "policy-delete":
      return <PolicyDelete data={page.data} />;
    case "policy-rename":
      return <PolicyRename data={page.data} />;
    case "policies":
      return <Policies data={page.data} />;
    case "policy":
      return <PolicyEditor data={page.data} />;
    case "keys":
      return <Keys data={page.data} />;
    case "operator-keys":
      return <OperatorKeys data={page.data} />;
    case "events":
      return <Events data={page.data} />;
    case "settings":
      return <Settings data={page.data} />;
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
