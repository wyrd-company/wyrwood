# Spike: FUSE-served secret files for devcontainers

Task 847. Branch `847/secret-file-gate-spike`. Spike code under `spike/`:
`secretfs` (go-fuse loopback daemon with mount-namespace origin detection,
`/proc/<pid>/exe` allowlist, redacted reads, denied writes, direct IO, and
fd-handoff re-exec), `runbook/q1..q6`, and two helpers. Experiments ran on the
user's Linux host (CachyOS, kernel 7.2.2, Docker 29.7.2, fusermount3 3.18.2,
`user_allow_other` off, `/` and `/home` mounted `shared`, Yama
`ptrace_scope=1`). Host-side execution was performed by a peer session with
host access; every verdict below quotes its output.

## Inventory: secret-bearing mounts in `common-feature` 10.3.0

Observed in a running devcontainer built from the feature. "Rewrites" means the
CLI writes the file itself (login, refresh, logout). "Prints" means a normal
subcommand emits the secret on stdout. "Reader" is the process that opens the
file, after any wrapper scripts.

| Host source (under `~/Code/devcontainers/`) | Container path | Secret field(s) | Rewrites | Prints | Reader binary |
| --- | --- | --- | --- | --- | --- |
| `gh/config` | `~/.config/gh/hosts.yml` | `oauth_token` | yes: login, logout, refresh; the `gh` wrapper script also re-authenticates as the bot | yes: `gh auth token`, `gh auth git-credential get` | native Go `gh` (wrapper is bash, execs real binary) |
| `codex` | `~/.codex/auth.json` | `OPENAI_API_KEY`, `tokens.access_token`, `id_token`, `refresh_token` | yes: login, token refresh | no default subcommand | native Rust `codex` (npm `codex.js` launcher spawns `vendor/x86_64-unknown-linux-musl/bin/codex`) |
| `claude` | `~/.claude/.credentials.json` | `claudeAiOauth.accessToken`, `refreshToken`, `mcpOAuth.*` | yes: login, refresh | no | native (bun-compiled) `claude` at `~/.local/share/claude/versions/<v>` |
| `claude` | `~/.claude/github.pem` | RSA private key (GitHub App) | no | no | native Go `gh` via `gh token generate` |
| `.claude.json` | `~/.claude.json` | none observed (usage counters, project state) | yes | n/a | `claude` |
| `cursor/config` | `~/.config/cursor/auth.json` | access/refresh tokens | yes | no | `cursor-agent` shell script that runs a vendored `node` on a bundled script: interpreted |
| `.npmrc` (ro) | `~/.npmrc` | `_authToken` | no (read-only mount) | yes: `npm config get` | `npm` on `node`: interpreted |
| `opencode` | `~/.local/share/opencode/auth.json` | `key` | yes | no | native (bun-compiled) `opencode` |
| `pi` | `~/.pi/agent/auth.json` | `key` | yes | no | `pi` on `node`: interpreted |
| `seek.json` (ro) | `~/.config/seek/config.json` | `*_API_KEY` for six providers | no | no | native (bun-compiled) `seek` |
| `ssh/default` | `~/.ssh` | `id_github` private key | no | no | native `ssh`, `git`; agent proxy already covers signing |
| `gnupg` (ro) | `~/.gnupg` | `pubring.kbx`, `trustdb.gpg`; no private keys, agent socket served | no | n/a | native `gpg` |
| `password-store` (ro) | `~/.password-store` | gpg-encrypted entries | no | yes by design: `pass show` | `pass` is bash, decrypts through `gpg` |
| `docker` | `~/.docker/config.json` | `auths` when populated (empty today) | yes: `docker login` | no | native `docker` |
| `openobserve` (ro), `lore.yml`, `gh-claim-issue-config.yml` (ro) | various | service tokens where configured | no | no | native or interpreted per tool |

Native readers with rewrite paths: `gh`, `codex`, `claude`, `opencode`,
`docker`. Interpreted readers: `cursor-agent`, `npm`, `pi`. Read-only
mounts with no rewrite: `.npmrc`, `seek`, `gnupg`, `password-store`,
`ssh`.
