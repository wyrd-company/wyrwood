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

## Environment note

Host runs failed before any container started: dockerd runs as root and
`stat`s the bind source, and a user FUSE mount without `allow_other` denies
root (`invalid mount config for type "bind": stat .../mnt/gh: permission
denied`; confirmed with `nsenter -t 1 -m stat` as root). `allow_other` needs
`user_allow_other` in `/etc/fuse.conf`, a one-line root change the host session
could not make non-interactively. The experiments therefore ran inside the
tools devcontainer, which has its own root dockerd (docker-in-docker), sudo,
`/dev/fuse`, fuse3 3.14 with a setuid `fusermount3`, and `user_allow_other`
enabled for the spike. The kernel is the host kernel. Differences from the
host: the devcontainer root is a `private` mount (the host's `/home` is
`shared`), so case B of question 1 needed a shared bind of the spike directory.

After `user_allow_other` was enabled on the host, questions 1, 2, and 3
were re-run there with the same scripts. Every case matched the
devcontainer result: A and B strand the container, B2 recovers (the parent
bind is the btrfs `/home` subvolume, `shared:205`; the FUSE mount
propagates as `0:198` under it), C panics with `unknown node 2`, path
allowlist admitted the attacker image, hashes identical, root opaque,
node identity is `node`. Host evidence: `~/Code/spikes/847/q1.out`,
`q2.out`, `identity.log`.

## Q1 Restart under a running container: fails-with-mitigation

| Case | Setup | After daemon kill and remount |
| --- | --- | --- |
| A | container binds `mnt/gh` (rprivate) | `Transport endpoint is not connected` forever; the container holds the dead mount |
| B | container binds `mnt/gh` with `bind-propagation=rshared` | same as A: the new mount at `mnt` is a new mount on the parent, and the container holds a bind of the old FUSE mount's subtree, which is not a peer of the parent |
| B2 | container binds the parent directory of the mountpoint with `bind-propagation=rshared`; daemon mounts at `parent/mnt` | new mount propagates into the running container: reads recover, `mountinfo` shows the new `fuse.secretfs` mount, and the gate still redacts for `cat` |
| C | daemon re-execs itself on SIGUSR1, passing the `/dev/fuse` fd, new process serves `/dev/fd/3` | kernel keeps its node table; the new server panics with `unknown node 2` on the first GETATTR and readers get `Input/output error` |

Evidence: `q1.out`. B2 is the mitigation: mount the FUSE directory beneath a
directory that the feature bind mounts rshared, and keep the served files one
level down. Docker requires the bind source to sit inside a `shared` mount;
the host's `/home` already is. The hard requirement this adds to the design:
every consumer must bind the parent directory, not the served subpath, and
resolve the per-CLI path inside it (symlink or CLI config variable). C is
possible only with full state transfer (kernel node ids, open handles), which
go-fuse does not support; not worth building when B2 exists.

Downtime behaviour: while the daemon is down every read returns `ENOTCONN`;
the mount fails closed.

## Q2 Executable identity from the host: holds, with a required identity choice

FUSE delivers the requester PID translated into the daemon's PID namespace.
For same-UID container processes the daemon reads `/proc/<pid>/exe`,
`cmdline`, `comm`, `ns/mnt`, and can hash the exe. Origin detection by
comparing `ns/mnt` with the daemon's own works. Evidence: `q2.out`,
`identity.log`.

| Identity | Observation | Reliable? |
| --- | --- | --- |
| exe path (`/usr/bin/cat`) | an attacker image that copies `head` over `/usr/bin/cat` was admitted as `real` | no |
| exe dev/inode | overlay device differs per container (`195` vs `177` for the same image); inode is the lower-layer inode and changes when the file is replaced | no: not stable across containers |
| exe sha256 | identical across containers and copies (`/tmp/cat2` hashes equal to `/usr/bin/cat`), differs for the spoof | yes; cost is one hash per open, cacheable by (dev, ino, mtime) per container |
| cmdline, comm | fully caller-controlled (`exec -a`, `process.title`) | no |

Root inside the container (uid 0, `docker exec -u 0`) is opaque to the uid
1000 daemon: `readlink /proc/<pid>/exe: permission denied`. Those requests
fall to `redacted`, so the gate fails closed for root and root-run CLIs
cannot be allowlisted. Same for root on the host: with `allow_other`, host
root processes are also unidentifiable and get the redacted copy. Host
origin detection must therefore also check `uid == daemon uid`, which the
spike does implicitly.

Direct IO is load-bearing: with `FOPEN_DIRECT_IO` on every open, an
allowlisted `cat` reading real bytes did not leave real bytes in the page
cache for a following non-allowlisted `head` (it read `REDACTED`). Getattr
size is per-requester (150 redacted bytes vs 214 real).

Writes from non-allowlisted container processes are refused with `EACCES`
on open-for-write, create, rename, unlink, and setattr.

## Q3 Interpreted CLIs: fails

For a node-based CLI, `exe` is the node binary in every case; the only
thing that names the script is `cmdline`, which the caller sets
(`exec -a /usr/local/bin/gh node /tmp/gh` logged `cmdline` `/usr/local/bin/gh
/tmp/gh`; `process.title` rewrote both `cmdline` and `comm`). A vendored node
copy, the `cursor-agent` shape, hashes identically to the system node, so
allowlisting it by hash admits every script run by any copy of that node.
Interpreted CLIs cannot be allowlisted by executable identity. Affected in
the inventory: `cursor-agent`, `npm` (`.npmrc`), `pi`. Remaining routes for
them: a native shim that owns the file read, or leaving them on the
harness-hook layer.

## Q4 Write path: holds

Allowlisted `tmpwriter` (temp file plus rename): rename landed in the
backing directory; a non-allowlisted `cat` immediately saw the new file
redacted; an identical binary at a different path was denied on the temp
file create; `rm` was denied. Real `gh` (native, allowlisted): `gh auth
status` read the real token, `gh auth logout` rewrote `hosts.yml` in place
(open, setattr truncate, write) and created `config.yml`, `gh config set`
wrote `config.yml`; all landed in the backing directory. `gh auth login
--with-token` with a fake token validated against the API first and wrote
nothing. Evidence: `q4.out`.

## Q5 Failure behaviour: holds

With the daemon killed (mount dangling) every CLI failed loudly and wrote
nothing: `gh` `failed to read configuration: ... transport endpoint is not
connected`; `codex` `failed to read CODEX_HOME ... Socket not connected`;
`gh auth login --with-token` refused before writing. `claude auth status`
reported `loggedIn: false` in every state including daemon-up with a
redacted credentials file, so Claude Code treats an unreadable or redacted
credential as absent; a later interactive login would try to write a fresh
`.credentials.json`, which the gate denies for a non-allowlisted writer and
passes for an allowlisted one. `npm` refuses to print `_authToken` by policy
and did not error on the unreadable `.npmrc`. Lazy unmount on the host did
not change what the running container saw (still the dead mount, per Q1
A). Evidence: `q5.out`.

## Q6 Sudo removal and ptrace: holds

Part A, plain Ubuntu container, default Docker profile, Yama
`ptrace_scope=1`, container user `vscode` uid 1000 with and without
passwordless sudo: `PTRACE_ATTACH` on a same-uid non-descendant returned
`operation not permitted`, `/proc/<pid>/mem` `permission denied`, `environ`
likewise. `--cap-add SYS_PTRACE` did not change the result for the
unprivileged user because the capability lands only in the bounding set.
Root in the container (via sudo, bounding set without `SYS_PTRACE`) could
not read another uid's `environ` either. So the ptrace path is closed for
the user, and sudo removal matters for the root path: `sudo su vscode -c
<allowlisted cli>` or reading `/proc/<pid>/fd` as root remains open while
passwordless sudo exists. Evidence: `q6.out`.

Part B, on the host: a throwaway devcontainer built from a copy of the
common feature (mounts and customizations removed) on
`ghcr.io/wyrd-company/devcontainers/base:resolute`, `postCreateCommand`
run, then `/etc/sudoers.d/*` removed and `NOPASSWD` stripped from
`/etc/sudoers`. `sudo -n true` went from exit 0 to `a password is
required`. Without sudo: `brew install jq`, `npm i -g cowsay`, `chown -R`
of already-owned trees, `task`, `gh`, `claude`, `codex`, `cursor-agent`
all worked; only `apt-get install` broke (dpkg lock, `are you root?`).
The feature's only sudo callers are the `own-*` post-create chowns, each
wrapped in `|| true`. No script under `~/.local/bin` or the CLI bin dirs
calls sudo. Verdict: holds; revoking passwordless sudo after post-create
costs apt only, and a root-owned late-arriving mount.

Side findings from the build: common-feature 10.3.0 depended on
`ghcr.io/wyrd-company/devcontainers/cursor-cli:1`, which was never
published (the feature is `cursor-agent-cli`; the user approved the fix on
the host); the caddy feature refuses non-s6 base images; `npm` 11 blocks
the `agent-browser` postinstall script, so that post-create step fails on
current npm regardless of mounts.

## Accepted assumptions

- "Docker on Linux can bind mount a subpath of a FUSE mount and the daemon
  can tell container from host requesters by mount namespace": validated
  with two amendments. The mount needs `allow_other` (so `user_allow_other`
  on the host), and the subpath bind must be of the parent directory for
  restart survival (Q1 B2).
- "FUSE reports the requester PID in the daemon's namespace so exe lookup
  works from the host": validated for same-uid processes; falsified for
  root processes (host or container), which are unreadable and must fail
  closed.

## Recommendation

Superseded by review round 1 below: a second spike round must close the
containment gaps before the design is written. Original constraints:

1. `user_allow_other` is a host prerequisite; `allow_other` plus explicit
   uid checks on both origins.
2. Consumers bind the parent of the mountpoint rshared; the daemon mounts
   beneath it; served paths are one level down.
3. Allowlist by executable content hash, cached per (container mount
   namespace, dev, inode, mtime); never by path or cmdline.
4. Direct IO on every open; per-requester size in getattr.
5. Interpreted CLIs (`cursor-agent`, `npm`, `pi`) stay outside the gate or
   get a native shim.
6. Root in the container is always redacted; passwordless sudo removal
   after post-create is part of the deployment and costs only apt.

## Independent review round 1 (Codex gpt-6-astra, low)

An independent reviewer read the findings, the spike code, and the raw
outputs and returned reject. The findings are largely valid and are
themselves spike learning. Dispositions:

1. Redaction leaks (P1, accepted). The placeholder regex left
   `access_token` in `codex/auth.json` (`"tokens": REDACTED "eyFAKE..."`)
   and produced invalid JSON. It does not cover bare `key` fields or PEM
   keys. The spike's redaction was a stand-in, but the Q2/Q5 "redacted
   baseline" is contaminated. A real gate needs format-aware redaction that
   refuses unsupported content. Q2's cache-leak result (direct IO) still
   holds; the redaction *content* does not.
2. B2 exposes the backing files (P1, accepted; corrects Q1). The B2 script
   bound all of `$SPIKE_ROOT`, which also holds `backing/`, so the container
   could read the real files at `/secrets/backing/...` without FUSE. Mount
   propagation still works, but the tested topology is not a safe layout.
   Corrected constraint: the exported parent must contain only the
   mountpoint, backing storage lives outside it, and direct-backing denial
   must be tested.
3. Q6 process-access not fully closed (P1, accepted). `ptracetest` returns
   after the `mem` failure, so it never tested `environ` independently, and
   the sibling setup never exercised Yama scope 1's ancestor-tracing
   allowance. An attacker who launches an allowlisted CLI as its own child
   can trace it. Q6 verdict narrows to: same-UID non-descendant ptrace is
   blocked; parent-child tracing and `/proc/<pid>/fd` are untested.
4. Hash identity is not trusted execution (P1, accepted; changes the
   recommendation). Hashing `/proc/<pid>/exe` ignores shared libraries,
   `LD_PRELOAD`, and plugins, so a dynamically linked allowlisted CLI can
   keep its approved hash while running attacker code, with no sudo or
   ptrace. "Native CLIs" is not by itself a security boundary; the design
   must separate self-contained readers from those with attacker-controlled
   code-loading, and constrain the loader environment.
5. Authorization is at open, not per read (P1, accepted). An allowed open
   returns a plain loopback handle; an inherited or `SCM_RIGHTS`-passed fd
   keeps access after the process changes exe or hands it to a
   non-allowlisted process. The design must decide whether it gates opens or
   every read; fd passing needs a test.
6. Inherited loopback mutations bypass the write gate (P1, accepted;
   narrows Q4). `Symlink`, `Link`, `Rmdir`, `Mknod`, and xattr ops are not
   wrapped in `check()`, so a same-UID caller can hardlink a credential out
   before a rewrite or plant a symlink. Q4 proved only open/create/rename/
   unlink/setattr; the gate needs an operation-by-operation policy.
7. Q5 used the rejected topology (P1, accepted). Q5 bound FUSE subpaths, so
   post-unmount it only re-observed the dead mount; it never tested B2's
   underlying directory between unmount and remount, nor successful
   login/refresh writes, nor every inventoried CLI. Q5 narrows to: while the
   daemon is down under a subpath bind, reads fail closed and the sampled
   CLIs wrote nothing.
8. Hash enforcement never exercised (P2, accepted). The runs used path
   allowlists; `-allow-sha256` was logged but never the deciding factor, and
   the mtime cache is unbuilt. Hash enforcement, copy/replacement, and
   metadata restoration need a dedicated experiment.
9. Evidence hygiene (P2, accepted). The saved `q2.out`/`q6.out` do not
   contain the `process.title`, vendored-node, or Q6 part B transcripts even
   though those runs happened in-session. The raw transcripts should be
   attached to the spike record.

Revised recommendation: do not write the technical design yet. Run a second
spike round that closes findings 1-8 first: safe export topology with
direct-backing denial, per-operation write policy with link tests,
open-versus-read authorization and fd-passing, the code-loading boundary for
dynamically linked readers, real hash enforcement with the cache, and the
parent-child ptrace and `/proc/<pid>/fd` paths. The mechanism (FUSE origin
detection, redaction, fail-closed, restart survival via parent-dir
propagation) is sound enough to continue; the gate is not yet proven
containing.
