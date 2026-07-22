# ---
# relationships:
#   demonstrates: overview
#   references:
#     - command-line-interface
#     - terminal-interface
# ---

Output docs/assets/demo.gif

Require bash
Require jq
Require ssh-add
Require ssh-agent
Require ssh-keygen
Require wyrwood

Set Shell "bash"
Set FontSize 20
Set Width 1400
Set Height 900
Set Theme "Catppuccin Mocha"
Set Padding 24
Set Margin 12
Set MarginFill "#11111b"
Set BorderRadius 8
Set WindowBar "Colorful"
Set TypingSpeed 28ms

Hide
Type "export PATH=$PWD:$PATH" Enter
Type 'export PS1="demo> "' Enter
Type 'WYRWOOD_DEMO_ROOT=$(mktemp -d /tmp/wyrwood-vhs-demo.XXXXXX)' Enter
Type 'mkdir -p "$WYRWOOD_DEMO_ROOT/runtime" "$WYRWOOD_DEMO_ROOT/state" "$WYRWOOD_DEMO_ROOT/consumer"' Enter
Type 'ssh-keygen -q -t ed25519 -N "" -C "teal key" -f "$WYRWOOD_DEMO_ROOT/teal"' Enter
Type 'ssh-keygen -q -t ed25519 -N "" -C "amber key" -f "$WYRWOOD_DEMO_ROOT/amber"' Enter
Type 'ssh-agent -D -a "$WYRWOOD_DEMO_ROOT/upstream.sock" >"$WYRWOOD_DEMO_ROOT/agent.log" 2>&1 & export WYRWOOD_DEMO_AGENT_PID=$!' Enter
Type 'until [ -S "$WYRWOOD_DEMO_ROOT/upstream.sock" ]; do sleep 0.05; done' Enter
Type 'export SSH_AUTH_SOCK="$WYRWOOD_DEMO_ROOT/upstream.sock"' Enter
Type 'ssh-add "$WYRWOOD_DEMO_ROOT/teal" "$WYRWOOD_DEMO_ROOT/amber" >/dev/null 2>&1' Enter
Type 'export XDG_CONFIG_HOME="$WYRWOOD_DEMO_ROOT/config"' Enter
Type 'export XDG_RUNTIME_DIR="$WYRWOOD_DEMO_ROOT/runtime"' Enter
Type 'export XDG_STATE_HOME="$WYRWOOD_DEMO_ROOT/state"' Enter
Type 'consumer_socket="$WYRWOOD_DEMO_ROOT/consumer/agent.sock"' Enter
Type 'fingerprint=$(ssh-keygen -lf "$WYRWOOD_DEMO_ROOT/teal.pub" | cut -d " " -f 2)' Enter
Type "clear" Enter
Show

Sleep 500ms
Type 'wyrwood init | sed "s#$WYRWOOD_DEMO_ROOT#/tmp/wyrwood-demo#g"' Enter
Sleep 2s

Hide
Type 'wyrwood daemon >"$WYRWOOD_DEMO_ROOT/daemon.log" 2>&1 & export WYRWOOD_DEMO_DAEMON_PID=$!' Enter
Type 'until [ -S "$XDG_RUNTIME_DIR/wyrwood/control.sock" ]; do sleep 0.05; done' Enter
Ctrl+L
Show

Type "wyrwood status" Enter
Sleep 3s
Type "wyrwood keys" Enter
Sleep 4s

Hide
Type 'revision=$(wyrwood configuration show --output json | jq -r ".result.revision")' Enter
Ctrl+L
Show

Type 'wyrwood consumer put --revision "$revision" --name teal --socket "$consumer_socket" --fingerprint "$fingerprint"' Enter
Sleep 3s
Type "wyrwood apply" Enter
Sleep 3s

Ctrl+L
Sleep 500ms
Type "wyrwood tui" Enter
Sleep 6s
Type "?"
Sleep 4s
Type "q"
Sleep 2s

Ctrl+L
Sleep 500ms
Type 'SSH_AUTH_SOCK="$consumer_socket" ssh-add -l' Enter
Sleep 5s

Hide
Type 'kill "$WYRWOOD_DEMO_DAEMON_PID" "$WYRWOOD_DEMO_AGENT_PID" 2>/dev/null || true' Enter
Type 'wait "$WYRWOOD_DEMO_DAEMON_PID" "$WYRWOOD_DEMO_AGENT_PID" 2>/dev/null || true' Enter
Type 'case "$WYRWOOD_DEMO_ROOT" in /tmp/wyrwood-vhs-demo.*) rm -r -- "$WYRWOOD_DEMO_ROOT" ;; esac' Enter
