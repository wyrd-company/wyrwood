# Task 847 spike: FUSE-served secret files

Throwaway code. `secretfs/` is a go-fuse loopback daemon that redacts secret
fields for container requesters that are not allowlisted. `runbook/` holds the
host-side experiments, one per question. Findings live in
`docs/spikes/secret-file-gate.md`.

## Q6 part B: real devcontainer

Build a throwaway devcontainer from a copy of the common feature (never the
user's live one): a folder with `.devcontainer/devcontainer.json` that
references `./common-feature` as a local feature. After `postCreateCommand`
finishes, run `sudo rm /etc/sudoers.d/*` (or equivalent) inside it and then
exercise the day-to-day commands: `brew install`, `npm i -g`, `docker ps`,
`apt-get install`, `chown` of a freshly mounted cache, `task`, `gh`. Record
which ones fail. Do not run this in a devcontainer the user is working in.
