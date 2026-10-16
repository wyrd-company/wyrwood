// ---
// relationships:
//   verifies: web-interface
// ---
// Test-only bridge: existing Go workflow assertions inspect the actual React UI.
// This module is never included in the browser bundle or the Go embed.
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { App } from "./app";
console.log(
  renderToStaticMarkup(<App page={JSON.parse(readFileSync(0, "utf8"))} />),
);
