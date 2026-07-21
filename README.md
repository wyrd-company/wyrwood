# Wyrwood

Designed to proxy between a password manager like Bitwarden and provide
a stable SSH_AUTH_SOCK socket to consumers in a container while filtering
based on access policies.

- Written in Go
- Runs as a service in linux/mac/windows
  - kardianos/service
  - https://pkg.go.dev/golang.org/x/crypto/ssh/agent
- A TUI mode for configuration/inspection
  - Uses bubbletea, huh?
  - Select and connect to the local ssh agent socket from Bitwarden/1password/Keep
    - keeps a connection, even if the upstream ssh-agent resets
  - List created consumer sockets
    - Records last activity
  - Edit/Create a consumer socket
    - Select keys
    - Only serves those keys on that socket