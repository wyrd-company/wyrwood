# Spike: per-binding values through OpenBao identity templating

Question: can OpenBao give one policy a different path for each binding, with no
new controller permission? Run on OpenBao 2.7.2, a dev server, in namespace
`wyrwood`, with a controller token that held only its bounded policy.

## Results

The carrier is AppRole SecretID `metadata`. Login copies it to the metadata of the
entity alias named by the `role_id`, and a template reads that metadata on each
request. The template was
`kv/data/app/keys/{{identity.entity.aliases.<accessor>.metadata.slug}}`.

| Case | Result |
| --- | --- |
| Role with `slug=alpha` | `alpha` 200, `beta` 403 |
| Role with `slug=beta` | `alpha` 403, `beta` 200 |
| Role with no value | templated path 403, `lookup-self` 200 |
| Token policies | exactly the named policy; `identity_policies` null |
| Controller reads `sys/auth` | denied |
| Controller reads `sys/internal/ui/mounts/auth/approle` | returns the accessor |
| Same read with no token | denied |
| Value `*`, `al*`, `+`, `x/y`, `../beta` | every request of that token answers 400; log says `template substitution contains forbidden value` |
| Value `al.pha`, `a b`, `{{identity.entity.name}}` | literal text; `alpha` and `beta` 403 |
| Later login with another value | new token follows; the older token of that role follows too |
| Later login with no metadata | both tokens lose the path |
| Token renewal | value kept |
| Role deleted and recreated | new `role_id`; no value carried |
| `{{binding.slug}}` published with no compilation | accepted; path 403 |
| `{{identity.entity.bogus}}` | accepted; path 403 |

## What this means for the design

- A template that cannot resolve drops its stanza and OpenBao accepts it at write,
  so a placeholder that is not compiled is silent. Wyrwood must refuse a malformed
  one when a policy is saved.
- A login writes the alias, so the order of logins matters. A stale SecretID used
  after a change would put old values under the new token, and renewal never
  corrects it. Deleting the role voids outstanding SecretIDs.
- AppRole writes `role_name` to the same metadata, so value keys need a prefix.

## Not tested

- OpenBao on persistent storage across a restart. The identity store persists alias
  metadata by design; the dev server keeps it in memory.
- Placeholder use in parameter constraints. The controller refuses it.
