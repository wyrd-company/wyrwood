---
title: Configuration and policy
order: 4
docs: true
relationships:
  references:
    - configuration
    - command-line-interface
---

The per-user YAML file is Wyrwood's durable source of truth. On Linux it is
`$XDG_CONFIG_HOME/wyrwood/config.yml`, or `~/.config/wyrwood/config.yml` when
`XDG_CONFIG_HOME` is unset.

```yaml
upstream: /run/user/1000/example-agent.sock
consumers:
  - name: teal
    socket: /run/user/1000/teal/agent.sock
    fingerprints:
      - SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
timeouts:
  connect: 5s
  list: 5s
  replay: 5s
  sign: 2m
```

Examples use placeholder paths and fingerprints. Select exact fingerprints from
`wyrwood keys` before applying a real configuration.

## Managed changes

`configuration show` returns the complete editable model and a revision derived
from the exact persisted bytes. Mutations require that revision and fail on a
stale value instead of overwriting another edit.

```bash
wyrwood configuration show
revision=$(wyrwood configuration show --output json |
  jq -r '.result.revision')
wyrwood configuration set-upstream --revision "$revision" \
  --socket /run/user/1000/example-agent.sock

revision=$(wyrwood configuration show --output json |
  jq -r '.result.revision')
wyrwood configuration set-timeouts --revision "$revision" \
  --connect 5s --list 5s --replay 5s --sign 2m
```

`consumer put` replaces the complete consumer value and fingerprint allowlist.
Omit `--id` to create one; supply the opaque identifier returned by
`configuration show` to replace one. Retire an existing consumer with its
identifier:

```bash
wyrwood consumer retire --revision "$revision" --id "$consumer_id"
```

Set `revision` and `consumer_id` from the current `configuration show --output
json` result before running the command.

Managed writes serialize canonical YAML and do not preserve comments or custom
formatting. Direct file edits remain supported, but they also change the
revision. Both paths require a separate `wyrwood apply` before the runtime
policy changes.

## Consumer filesystem access

Without `access-group`, Wyrwood gives the consumer directory mode `0700` and the
socket mode `0600`. Set a numeric supplementary group when the container must
reach the endpoint through group access:

```bash
wyrwood consumer put --revision "$revision" --id "$consumer_id" \
  --name teal --socket /run/user/1000/teal/agent.sock \
  --access-group 1001 --fingerprint "$fingerprint"
```

The group must belong to the daemon user. A socket-path change creates a new
consumer security principal and a new opaque identifier.

## Timeouts

Connect, identity-list, and session-binding replay timeouts accept Go duration
syntax from `100ms` through `30s`. Signing accepts `1s` through `10m`, allowing
time for confirmation in the upstream agent without permitting an unbounded
request.
