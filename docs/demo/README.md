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
   expected state, and call `shot web-<name>`. Capture useful state, with no
   real user data. Keep fixtures in `stack.sh` generic.
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
