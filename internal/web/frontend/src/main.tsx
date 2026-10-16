// ---
// relationships:
//   implements: web-interface
// ---
import { createRoot } from "react-dom/client";
import { App } from "./app";
import type { Page } from "./types";
import "./style.css";
const page: Page = JSON.parse(
  document.getElementById("wyrwood-page")!.textContent!,
);
document.title = `Wyrwood · ${page.data.Title}`;
createRoot(document.getElementById("root")!).render(<App page={page} />);
