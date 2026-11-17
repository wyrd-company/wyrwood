// Browser walkthrough of the isolated mockup; no product or authorization tests.
// Usage: node verify.mjs /absolute/output-directory
// Install Playwright outside the repo; optionally set PLAYWRIGHT_MODULE to its
// module path and PLAYWRIGHT_BROWSERS_PATH to its browser cache.
import assert from "node:assert/strict";
import { mkdir, writeFile, readFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
const { chromium } = await import(
  process.env.PLAYWRIGHT_MODULE || "playwright"
);
const output = path.resolve(process.argv[2] || "/tmp/wyrwood-grant-mockup");
await mkdir(output, { recursive: true });
await writeFile(
  path.join(output, "result.json"),
  JSON.stringify({ passed: false, reason: "Walkthrough has not completed" }),
);
const browser = await chromium.launch({
  headless: true,
  executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE,
});
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
page.setDefaultTimeout(10000);
const accessibility = [];
const failures = [],
  checks = [],
  screenshots = [];
page.on("pageerror", (e) => failures.push(e.message));
page.on("request", (req) => {
  if (!req.url().startsWith("file:"))
    failures.push(`Unexpected request: ${req.url()}`);
});
const url = pathToFileURL(
  fileURLToPath(new URL("./index.html", import.meta.url)),
).href;
const shot = async (name) => {
  await page.screenshot({
    path: path.join(output, `${name}.png`),
    fullPage: true,
  });
  screenshots.push(name);
};
const go = async (hash) => {
  await page.goto(`${url}#${hash}`);
  await page.locator("#page-title").waitFor();
};
const route = async (hash) => {
  await page.evaluate(
    (h) =>
      new Promise((resolve) => {
        if (location.hash === `#${h}`) return resolve();
        addEventListener("hashchange", () => resolve(), { once: true });
        location.hash = h;
      }),
    hash,
  );
};
const text = async (selector) => page.locator(selector).innerText();
const check = (condition, name) => {
  assert.ok(condition, name);
  checks.push(name);
  console.log(`PASS ${name}`);
};
try {
  await go("keys");
  await shot("01-approved-keys");
  await page
    .getByRole("link", { name: "Edit grant", exact: true })
    .first()
    .click();
  check(
    !(await text("#content")).includes("client needs no change"),
    "Removed key/client filler",
  );
  await page.locator('[data-grant="policies"][value="bob-secrets"]').check();
  check(
    (await text("#live-preview")).includes("shared-key and bob-secrets"),
    "Live preview updates",
  );
  await page.getByRole("button", { name: "Validate", exact: true }).click();
  check(
    await page.locator("#grant-valid").isVisible(),
    "Validate checks the grant inline",
  );
  await shot("02-edit-grant");
  await route("keys");
  check(
    !(await page.locator("tbody tr").first().innerText()).includes(
      "bob-secrets",
    ),
    "Validate leaves saved grant unchanged",
  );
  await route("edit/menagerie");
  await page.locator('[data-grant="policies"][value="bob-secrets"]').check();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  check(
    (await text(".notice")).includes("Grant saved."),
    "Save applies grant directly",
  );
  check(
    (await page
      .getByRole("button", { name: /Confirm|Review|Cancel/ })
      .count()) === 0,
    "No extra key confirmation controls",
  );
  await route("keys");
  check(
    (await page.locator("tbody tr").first().innerText()).includes(
      "bob-secrets",
    ),
    "Direct save updates key list",
  );
  await route("events");
  const event = await text("#content");
  check(
    event.includes("boblangley") &&
      event.includes("key:menagerie") &&
      event.toLowerCase().includes("before") &&
      event.toLowerCase().includes("after"),
    "Saved event retains operator, key and full old/new grant",
  );
  await shot("03-grant-event");
  await route("policy");
  check(
    await page.locator('[data-policy-key="menagerie"]').isChecked(),
    "Policy reflects key-side save",
  );
  check(
    (await page.locator("[data-policy-key]").count()) === 3,
    "One checkbox per existing key",
  );
  check(
    (await page.locator("[data-policy-key]:disabled").count()) === 0,
    "Every key can be selected or removed",
  );
  check(
    (await page.locator("#policy-keys input").count()) === 3,
    "No extra policy selection controls",
  );
  check(
    (await page
      .locator("#policy-keys .caution, #policy-keys .badge, #policy-keys a")
      .count()) === 0,
    "No policy warnings, permission badges or action links",
  );
  check(
    !(await text("#policy-keys")).includes("SHA256:"),
    "No policy fingerprint lines",
  );
  check(
    (await text('[data-policy-key="reader"] + span')).includes("Read") &&
      !(await text('[data-policy-key="reader"] + span')).includes("Bind"),
    "Key action list shows only enabled actions",
  );
  check(
    (await page
      .getByRole("button", { name: /Review|Confirm|Cancel/ })
      .count()) === 0,
    "No extra policy confirmation controls",
  );
  await shot("04-policy-keys");
  await page.locator('[data-policy-key="reader"]').check();
  await page.getByRole("button", { name: "Validate", exact: true }).click();
  check(
    await page.locator("#policy-valid").isVisible(),
    "Validate checks policy without navigation",
  );
  await route("keys");
  check(
    !(await page.locator("tbody tr").nth(1).innerText()).includes(
      "bob-secrets",
    ),
    "Policy validation does not apply checkbox changes",
  );
  await route("policy");
  await page.locator('[data-policy-key="menagerie"]').uncheck();
  await page.locator('[data-policy-key="reader"]').check();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  check(
    (await text(".notice")).includes("Policy saved."),
    "Policy saves directly",
  );
  await route("edit/menagerie");
  check(
    !(await page
      .locator('[data-grant="policies"][value="bob-secrets"]')
      .isChecked()),
    "Policy-side removal updates key grant",
  );
  await route("edit/reader");
  check(
    await page
      .locator('[data-grant="policies"][value="bob-secrets"]')
      .isChecked(),
    "Policy-side addition works without Bind",
  );
  check(
    !(await page.locator('[data-action="bind"]').isChecked()),
    "Policy selection preserves enabled actions",
  );
  await route("policy");
  await page.locator('[data-policy-key="admin"]').uncheck();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await route("edit/admin");
  check(
    !(await page.locator('[data-grant="policies"][value="*"]').isChecked()) &&
      !(await page
        .locator('[data-grant="policies"][value="bob-secrets"]')
        .isChecked()),
    "Wildcard key removal uses explicit remaining policies",
  );
  check(
    (await page
      .locator('[data-grant="policies"][value="shared-key"]')
      .isChecked()) &&
      (await page.locator('[data-grant="policies"][value="teal"]').isChecked()),
    "Wildcard removal preserves other stored policies",
  );
  await route("new-policy");
  await page.locator("#policy-name").fill("Invalid/Name");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  check(
    await page.locator("#policy-error").isVisible(),
    "Invalid policy save is refused",
  );
  await page.locator("#policy-name").fill("alice-secrets");
  await page.locator('[data-policy-key="menagerie"]').check();
  await shot("05-create-policy");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  check(
    (await page.locator("#content h2").first().innerText()).includes(
      "alice-secrets",
    ),
    "Create saves policy directly",
  );
  await route("edit/menagerie");
  check(
    await page
      .locator('[data-grant="policies"][value="alice-secrets"]')
      .isChecked(),
    "New policy is added to selected key",
  );
  await route("events");
  check(
    (await page
      .getByRole("heading", { name: "operator-key-grant-changed", exact: true })
      .count()) === 5,
    "One event per changed grant, no events from validation",
  );
  check(
    (await text("#content")).includes("Policy: alice-secrets"),
    "Policy event records source",
  );
  await page.getByRole("button", { name: "Reset demo" }).click();
  await route("edit/menagerie");
  for (const action of ["read", "bind", "policy-write"])
    await page.locator(`[data-action="${action}"]`).uncheck();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  check(
    await page.locator("#grant-error").isVisible(),
    "Invalid grant cannot be saved",
  );
  await page.locator('[data-action="read"]').check();
  await page.locator("#other-policies").fill("Invalid/Policy");
  await page.getByRole("button", { name: "Validate", exact: true }).click();
  check(
    (await text("#grant-error")).includes("not a valid policy name"),
    "Invalid grant name is refused",
  );
  await page.locator("#other-policies").fill("");
  await page.locator('[data-grant="policies"][value="*"]').check();
  check(
    await page
      .locator('[data-grant="policies"][value="shared-key"]')
      .isDisabled(),
    "All policies disables named choices on key editor",
  );
  await page.getByRole("button", { name: "Reset demo" }).click();
  await route("edit/menagerie");
  await page.locator('[data-grant="policies"][value="bob-secrets"]').focus();
  await page.keyboard.press("Space");
  await page.getByRole("button", { name: "Save", exact: true }).focus();
  await page.keyboard.press("Enter");
  check(
    (await text(".notice")).includes("Grant saved."),
    "Keyboard editing saves without extra step",
  );
  for (const width of [390, 1280]) {
    await page.setViewportSize({ width, height: 900 });
    for (const hash of [
      "keys",
      "edit/menagerie",
      "policy",
      "new-policy",
      "events",
    ]) {
      await route(hash);
      if (process.env.AXE_SCRIPT) {
        if (!(await page.evaluate(() => Boolean(window.axe))))
          await page.addScriptTag({ path: process.env.AXE_SCRIPT });
        const report = await page.evaluate(async () => {
          const result = await axe.run(document, {
            runOnly: {
              type: "tag",
              values: ["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"],
            },
          });
          return {
            violations: result.violations,
            incomplete: result.incomplete.map((item) => ({
              id: item.id,
              nodes: item.nodes.length,
            })),
            passes: result.passes.length,
          };
        });
        accessibility.push({ width, route: hash, ...report });
        check(
          report.violations.length === 0,
          `Axe A/AA: ${hash} at ${width}px`,
        );
      }
      check(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= window.innerWidth,
        ),
        `No page overflow: ${hash} at ${width}px`,
      );
    }
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await route("edit/menagerie");
  await shot("06-phone-edit");
  await page.getByRole("button", { name: "Menu", exact: true }).click();
  check(
    await page.getByRole("link", { name: "Events", exact: true }).isVisible(),
    "Phone menu opens",
  );
  await page.keyboard.press("Escape");
  check(
    (await page
      .getByRole("button", { name: "Menu", exact: true })
      .getAttribute("aria-expanded")) === "false",
    "Escape closes phone menu",
  );
  await route("policy");
  await shot("07-phone-policy");
  await page.setViewportSize({ width: 1280, height: 900 });
  await route("edit/menagerie");
  await page.evaluate(() => {
    const sizes = [...document.querySelectorAll("body *")].map((el) => [
      el,
      parseFloat(getComputedStyle(el).fontSize),
    ]);
    for (const [el, size] of sizes) el.style.fontSize = `${size * 2}px`;
  });
  check(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
    "No page overflow at 200% text",
  );
  check(failures.length === 0, "No browser errors or network requests");
  const htmlSHA256 = createHash("sha256")
    .update(
      await readFile(fileURLToPath(new URL("./index.html", import.meta.url))),
    )
    .digest("hex");
  const head = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: fileURLToPath(new URL(".", import.meta.url)),
    encoding: "utf8",
  }).trim();
  await writeFile(
    path.join(output, "result.json"),
    JSON.stringify(
      {
        passed: true,
        head,
        htmlSHA256,
        checks,
        screenshots,
        failures,
        accessibility,
      },
      null,
      2,
    ),
  );
  console.log(
    JSON.stringify(
      { passed: true, checks: checks.length, screenshots },
      null,
      2,
    ),
  );
} finally {
  await browser.close();
}
