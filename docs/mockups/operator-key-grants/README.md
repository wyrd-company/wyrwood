# Editable operator key grants mockup

Revision 2 for [Wyrwood #157](https://github.com/wyrd-company/wyrwood/issues/157),
epic task 8. The operator rejected revision 1 on 2026-11-17 and
[approved this revision](https://github.com/wyrd-company/wyrwood/pull/164#issuecomment-6948997455)
the same day.

Open [index.html](index.html) directly in a browser. It has fictional data and
needs no server, credentials or network. Reload or **Reset demo** resets it.

## Walkthrough

1. On **Operator keys**, open **Edit grant** for `menagerie`.
2. Change Agents, Policies or actions. **What this key can do** updates live.
3. **Validate** checks the draft without saving. **Save** applies it directly.
4. On a policy's **Operator keys** tab, check or clear a key. Its enabled actions
   appear under its name. **Validate** and **Save** are the only form actions.
5. **Create policy** uses the same key list. Save creates the fixture policy and
   updates the selected keys' Policies lists.
6. **Events** shows who changed each grant, when, and its complete old and new
   values. Before any save, it shows a marked example.

## Revision 2

The operator's feedback was relayed by the epic planner on 2026-11-17:

- Removed the unchanged-key/client-restart explanation and other repeated copy.
- Replaced policy-side key details with one checkbox per existing key and its
  enabled actions. Keys without Bind can be selected; actions are unchanged.
- Removed policy-side permission badges, fingerprints and the yellow warning.
- Removed separate review/confirmation pages and Cancel controls. Save applies
  edits directly; Validate checks without applying them.

The revision keeps Wyrwood's existing palette, sidebar, panels, policy tabs and
key grant preview. Reference screens: [Operator
keys](../../user/assets/web-operator-keys.png), [Policy
editor](../../user/assets/web-policy.png), and
[Events](../../user/assets/web-events.png).

## Implementation notes for task 10

Both editing paths change the same Policies list. A key's existing Read, Bind
and Policy write actions apply to that list; selecting a policy never adds an
action. Each changed key gets an event with the full old and new grant.

Wildcard assumption in this prototype: clearing a policy from an All policies
key replaces `*` with the other currently stored policy names. Future policies
are then outside that grant. The old and new values appear in Events. No one
approved this narrowing, and the product does not build it: on a policy's tab, a
key with All policies is checked and disabled, and only its grant editor
narrows it. Epic task 10 put this choice to the operator.

Only the mockup files change. The application, screenshot source inputs and
existing screenshots stay untouched. HCL editing, persistence, authentication,
concurrent edits, request failures and existing binding behavior are outside
this fixture. Event naming is proposed.

## Verification

The [browser walkthrough](verify.mjs) checks direct saves, validation without
saving, the shared key/policy grant, event detail, invalid inputs, wildcard
removal, keyboard use and phone layouts. It writes screenshots and a JSON
report outside the repository. The report starts as failed and records the
commit and HTML hash on completion.

```sh
node docs/mockups/operator-key-grants/verify.mjs /absolute/evidence-directory
```

Use an existing Playwright installation outside the repository. Optional
`PLAYWRIGHT_MODULE` selects its module and `PLAYWRIGHT_CHROMIUM_EXECUTABLE` its
browser. `PLAYWRIGHT_BROWSERS_PATH` selects a browser cache. Optional `AXE_SCRIPT`
selects a local axe-core script for WCAG A/AA scans at phone and desktop widths.
