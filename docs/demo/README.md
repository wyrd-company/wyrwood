---
relationships:
  references:
    - overview
    - web-interface
    - Taskfile
---

# Screenshot maintenance

Run `task docs:screenshots` from the repository root to rebuild the controller
and record the real web UI against the existing isolated demo stack. This
refreshes every `web-*.png` in `docs/user/assets` and writes a source and image
hash receipt in `docs/demo/screenshots.json`. It uses real OpenBao, a mock OIDC
identity provider with a generic operator, and a real agent with three
throwaway workloads on a separate Docker Engine. No application responses
are mocked. `task demo` also records the CLI with VHS and rebuilds `demo.gif`.

The recording is also the browser test of the web interface. After the
walk-through at 1280 by 800 pixels, `web.sh` runs `phone.sh` at 390 by 844
pixels. It checks that the page heading, the primary action, and the tab list
of the policy editor and the binding editor start in the first screen, and
that the **Menu** control opens and closes with pointer, Enter, Space, and
Escape. It prints each position, and the recording fails when a check fails.
`phone.sh` also runs alone against a demo site that `web.sh` has walked
through.

Requirements: Linux, Docker Engine, passwordless sudo, Go, Task, Corepack,
Node.js, curl, jq, iproute2, and agent-browser with its browser installed.
The full GIF also needs VHS, ffmpeg, and gifsicle. Run on a development host
without an installed Wyrwood agent: the stack refuses existing agent state.
It uses ports 18088, 18090, 18200 and 12222, fixed demo container names, and
`/tmp/wyrwood-demo`. Run only one recorder on a host at a time. The wrapper
cleans up the site on success or failure. Do not run it against a live site.

## Change and review loop

1. Change the UI or a documented flow.
2. Extend `web.sh` for new pages. Navigate through the real UI, wait for the
   expected state, and call `shot web-<name>`. Select a screen's tab with
   `tab "<name>"` before a step that uses its content, and use `expect_page` for
   browser behavior a Go or Vitest test cannot observe. Capture useful state,
   with no real user data. Keep fixtures in `stack.sh` generic.
3. Run `task docs:screenshots`. For animation changes, run `task demo` instead.
4. Open each changed PNG and check legibility, selected state, and agreement
   with the guide. Check the GIF when it changes. Capture authentic UI; do not
   paint over the image or fabricate a page.
5. Add new images to `docs/user/docs.yml` and link them from the user guide.
   Run `task docs:check` and commit the images and receipt with the change.

`task docs:media:check` runs without Docker or a browser and is included in
`task docs:check` and CI. It checks local user-guide links and anchors,
publishing asset references, PNG signatures, and the recorded hashes. Changes
to production UI sources, web handlers, recorder scripts, or screenshot bytes
require a fresh recording. Test files, Vitest setup, and the Go-test SSR entry
point are excluded; shared production components remain inputs. Added and
removed inputs also invalidate the receipt. This is a conservative refresh
signal, not a pixel comparison or proof that prose is correct. Review images
after capture; do not update hashes to bypass it.
The CLI animation is outside this receipt and needs review when commands change.

For recording failures, keep the terminal error and inspect the demo logs
before cleanup, or run `stack.sh up`, `web.sh`, and `stack.sh down` manually.
The browser session closes even when `web.sh` fails. Always stop your demo
stack when done. The helper scripts are for disposable local fixtures only.
