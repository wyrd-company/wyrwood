// ---
// relationships:
//   verifies: web-interface
// ---
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const source = readFileSync(resolve(__dirname, "style.css"), "utf8");

interface Rule {
  prelude: string;
  body: string;
}

// Splits one level of a stylesheet into its braced rules. jsdom computes no
// colors from a sheet with cascade layers, so this reads the source instead.
function rulesOf(css: string): Rule[] {
  const text = css.replace(/\/\*[\s\S]*?\*\//g, "");
  const rules: Rule[] = [];
  let depth = 0;
  let start = 0;
  let open = 0;
  for (let index = 0; index < text.length; index++) {
    if (text[index] === ";" && depth === 0) start = index + 1;
    if (text[index] === "{" && depth++ === 0) open = index;
    if (text[index] === "}" && --depth === 0) {
      rules.push({
        prelude: text.slice(start, open).trim(),
        body: text.slice(open + 1, index),
      });
      start = index + 1;
    }
  }
  return rules;
}

function anchorSelectors(rule: Rule): string[] {
  return rule.prelude
    .split(",")
    .map((selector) => selector.trim())
    .filter((selector) => /^a(:[\w-]+)*$/.test(selector));
}

describe("anchor defaults", () => {
  it("stay out of the unlayered cascade so that Button utilities win on a link", () => {
    const unlayered = rulesOf(source)
      .filter((rule) => !rule.prelude.startsWith("@"))
      .flatMap(anchorSelectors);
    expect(unlayered).toEqual([]);
  });

  it("keep the link colors in the base layer", () => {
    const base = rulesOf(source).filter(
      (rule) => rule.prelude === "@layer base",
    );
    const anchors = base.flatMap((layer) =>
      rulesOf(layer.body).map((rule) => [
        anchorSelectors(rule).join(),
        rule.body.trim(),
      ]),
    );
    expect(anchors).toEqual([
      ["a", "color: var(--accent);"],
      ["a:hover", "color: var(--accent-ink);"],
    ]);
  });
});
