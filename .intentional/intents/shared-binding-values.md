---
wyrwood: minor
wyrwood-docs: patch
---

One policy can now apply to many bindings with a different path for each. Write `{{binding.name}}` in a path stanza, for example `path "kv/data/sample/{{binding.slug}}"`, and each binding sets its own value on the binding screen. The preview shows the path with the value. A value holds only letters, digits, underscores, and hyphens, so it cannot reach another binding's path. A binding with no value for a placeholder is refused when you save it, and so is a policy edit that would leave one without a value. OpenBao evaluates these paths through identity templating, so this needs no new OpenBao policy for each container and no new controller permission.
