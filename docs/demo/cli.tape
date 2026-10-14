# ---
# relationships:
#   demonstrates: overview
#   references:
#     - command-line-interface
#     - container-contract
# ---

# Records the command-line half of the demo against the site
# docs/demo/stack.sh started, after docs/demo/web.sh bound teal-api.
# Run it from the repository root through docs/demo/record.sh.

Output "/tmp/wyrwood-demo/cli.mp4"

Require bash
Require docker
Require sudo

Set Shell "bash"
Set FontSize 18
Set Width 1280
Set Height 800
Set Theme "Catppuccin Mocha"
Set Padding 24
Set TypingSpeed 35ms

Hide
Type "export PATH=/tmp/wyrwood-demo/bin:$PATH" Enter
Type 'export PS1="host$ "' Enter
Type "alias sudo='sudo env PATH=$PATH'" Enter
Type 'alias docker="sudo docker -H unix:///tmp/wyrwood-demo/engine/docker.sock"' Enter
Type "clear" Enter
Show

Sleep 500ms
Type "sudo wyrwood agent login ssh://127.0.0.1:12222" Enter
Sleep 3s
Type "sudo wyrwood agent status" Enter
Sleep 3s
Type "sudo wyrwood agent containers" Enter
Sleep 4s

Ctrl+L
Sleep 300ms
Type "sudo wyrwood agent events --limit 6" Enter
Sleep 5s

Ctrl+L
Sleep 300ms
Type "docker exec teal-api ls /run/wyrwood" Enter
Sleep 2s
Type "docker exec teal-api bao kv get kv/teams/teal/example" Enter
Sleep 4s

Ctrl+L
Sleep 300ms
Type "docker exec teal-api ssh-add -l" Enter
Sleep 3s
Type "docker exec amber-worker ls /run/wyrwood" Enter
Sleep 4s
