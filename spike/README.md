# Task 847 spike: FUSE-served secret files

Throwaway code. `secretfs/` is a go-fuse loopback daemon that redacts secret
fields for container requesters that are not allowlisted. `runbook/` holds the
host-side experiments, one per question. Findings live in
`docs/spikes/secret-file-gate.md`.
