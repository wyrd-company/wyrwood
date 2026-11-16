// Browser walkthrough of the isolated mockup; no product or authorization tests.
// Usage: node verify.mjs /absolute/output-directory
// Install Playwright outside the repo; optionally set PLAYWRIGHT_MODULE to its
// module path and PLAYWRIGHT_BROWSERS_PATH to its browser cache.
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
const { chromium } = await import(
  process.env.PLAYWRIGHT_MODULE || "playwright"
);
const output = path.resolve(process.argv[2] || "/tmp/wyrwood-grant-mockup");
await mkdir(output, { recursive: true });
await writeFile(
  path.join(output, "result.json"),
  JSON.stringify({ passed: false, reason: "Walkthrough has not completed" }),
);
const browser = await chromium.launch({ headless: true });
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
  await page.evaluate((h) => {
    location.hash = h;
  }, hash);
  await page.waitForFunction(
    (h) => location.hash === `#${h}` && !!document.querySelector("main > *"),
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
  await page.locator('[data-grant="policies"][value="bob-secrets"]').check();
  check(
    (await text("#live-preview")).includes("shared-key and bob-secrets"),
    "Live preview includes added policy",
  );
  await shot("02-edit-grant");
  await page.getByRole("button", { name: "Review grant", exact: true }).click();
  await page.getByRole("heading", { name: "Confirm grant changes" }).waitFor();
  check(
    (await text(".grant-diff")).includes("shared-key, bob-secrets"),
    "Confirmation shows full new grant",
  );
  await shot("03-confirm-grant");
  await page.getByRole("link", { name: "Cancel", exact: true }).click();
  check(
    await page
      .locator('[data-grant="policies"][value="bob-secrets"]')
      .isChecked(),
    "Cancel confirmation preserves draft",
  );
  await page.getByRole("link", { name: "Cancel", exact: true }).click();
  check(
    !(await page.locator("tbody tr").first().innerText()).includes(
      "bob-secrets",
    ),
    "Cancel leaves saved grant unchanged",
  );
  await page
    .getByRole("link", { name: "Edit grant", exact: true })
    .first()
    .click();
  await page.locator('[data-grant="policies"][value="bob-secrets"]').check();
  await page.getByRole("button", { name: "Review grant", exact: true }).click();
  await page
    .getByRole("button", { name: "Confirm changes", exact: true })
    .click();
  await page
    .getByRole("heading", { name: "Approved operator keys", exact: true })
    .waitFor();
  check(
    (await page.locator("tbody tr").first().innerText()).includes(
      "bob-secrets",
    ),
    "Confirmed edit updates approved key",
  );
  check(
    (await page.locator("tbody tr").first().innerText()).includes(
      "SHA256:U04dsnYHFG5fUmK4FYYzBHDNU85/LRjOa+k9vNPJQkw",
    ),
    "Key fingerprint remains unchanged",
  );
  await route("events");
  await page
    .getByRole("heading", { name: "operator-key-grant-changed", exact: true })
    .waitFor();
  const event = await text("#content");
  check(
    event.includes("boblangley") &&
      event.includes("key:menagerie") &&
      event.toLowerCase().includes("before") &&
      event.toLowerCase().includes("after"),
    "Event names operator, key and old/new grant",
  );
  await shot("04-grant-event");
  await route("policy");
  await page.locator('[data-policy-key="menagerie"]').waitFor();
  check(
    await page.locator('[data-policy-key="menagerie"]').isChecked(),
    "Policy view reflects key-side edit",
  );
  check(
    await page.locator('[data-policy-key="reader"]').isDisabled(),
    "Policy-side picker does not silently enable Bind",
  );
  check(
    (await page.locator('[data-policy-key="admin"]').isChecked()) &&
      (await page.locator('[data-policy-key="admin"]').isDisabled()),
    "All policies key is included and cannot be excluded here",
  );
  await shot("05-policy-keys");
  await page.locator('[data-policy-key="menagerie"]').uncheck();
  await page
    .getByRole("button", { name: "Save and validate", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Confirm changes", exact: true })
    .click();
  await page
    .getByRole("heading", { name: "Approved operator keys", exact: true })
    .waitFor();
  check(
    !(await page.locator("tbody tr").first().innerText()).includes(
      "bob-secrets",
    ),
    "Policy-side removal updates same key grant",
  );
  await route("new-policy");
  await page.locator("#policy-name").fill("alice-secrets");
  await page.locator('[data-policy-key="menagerie"]').check();
  await shot("06-create-policy");
  await page
    .getByRole("button", { name: "Create and validate", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Create policy", exact: true })
    .click();
  await page
    .getByRole("heading", { name: "Approved operator keys", exact: true })
    .waitFor();
  check(
    (await page.locator("tbody tr").first().innerText()).includes(
      "alice-secrets",
    ),
    "Create-policy flow grants named policy to selected key",
  );
  await route("events");
  await page
    .getByRole("heading", { name: "operator-key-grant-changed", exact: true })
    .first()
    .waitFor();
  check(
    (await page
      .getByRole("heading", { name: "operator-key-grant-changed", exact: true })
      .count()) === 3,
    "One event per confirmed grant change",
  );
  check(
    (await text("#content")).includes("Policy: alice-secrets"),
    "Policy-originated event names source",
  );
  await page.getByRole("button", { name: "Reset demo" }).click();
  await page
    .getByRole("link", { name: "Edit grant", exact: true })
    .first()
    .click();
  for (const action of ["read", "bind", "policy-write"])
    await page.locator(`[data-action="${action}"]`).uncheck();
  await page.getByRole("button", { name: "Review grant", exact: true }).click();
  check(
    await page.locator("#grant-error").isVisible(),
    "No-action grant is refused",
  );
  check(
    !(await text("#live-preview")).includes("Allowed"),
    "Invalid grant preview grants no actions",
  );
  await page.locator('[data-action="read"]').check();
  await page.locator("#other-policies").fill("Invalid/Policy");
  await page.getByRole("button", { name: "Review grant", exact: true }).click();
  check(
    (await text("#grant-error")).includes("not a valid policy name"),
    "Invalid policy name is refused",
  );
  await page.locator("#other-policies").fill("");
  await page.locator('[data-grant="policies"][value="*"]').check();
  check(
    await page
      .locator('[data-grant="policies"][value="shared-key"]')
      .isDisabled(),
    "All policies disables named selections",
  );
  await page.getByRole("button", { name: "Reset demo" }).click();
  await page
    .getByRole("link", { name: "Edit grant", exact: true })
    .first()
    .click();
  // Follow the primary editing path with keyboard-only activation.
  await page.locator('[data-grant="policies"][value="bob-secrets"]').focus();
  await page.keyboard.press("Space");
  await page.getByRole("button", { name: "Review grant", exact: true }).focus();
  await page.keyboard.press("Enter");
  await page.getByRole("heading", { name: "Confirm grant changes" }).waitFor();
  await page.getByRole("link", { name: "Cancel", exact: true }).focus();
  await page.keyboard.press("Enter");
  check(
    await page.locator("#grant-form").isVisible(),
    "Keyboard selection, review and cancel work",
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
  await shot("07-phone-edit");
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
  await shot("08-phone-policy");
  await route("edit/menagerie");
  await page.locator('[data-grant="policies"][value="bob-secrets"]').check();
  await page.getByRole("button", { name: "Review grant", exact: true }).click();
  await page.getByRole("heading", { name: "Confirm grant changes" }).waitFor();
  check(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
    "No page overflow: confirmation at 390px",
  );
  await shot("09-phone-confirm");
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.evaluate(() => {
    const sizes = [...document.querySelectorAll("body *")].map((el) => [
      el,
      parseFloat(getComputedStyle(el).fontSize),
    ]);
    for (const [el, size] of sizes) el.style.fontSize = `${size * 2}px`;
  });
  await route("edit/menagerie");
  check(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
    "No page overflow at 200% text",
  );
  check(failures.length === 0, "No browser errors or network requests");
  await writeFile(
    path.join(output, "result.json"),
    JSON.stringify(
      { passed: true, checks, screenshots, failures, accessibility },
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
