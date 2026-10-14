# Changelog

## 0.2.0

### Features

- Split Wyrwood into a controller and an agent. The controller owns policy, serves a web interface that operators sign in to through OpenID Connect with group-based admission, and manages OpenBao policies and AppRoles. The agent watches Docker Engine, binds containers to policy, and publishes a per-container vault socket and ssh-agent socket. Keys and secrets live in OpenBao; the host SSH-agent upstream, fingerprint allowlists, and terminal interface are removed.
