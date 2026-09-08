#!/usr/bin/env bash
# Runs inside the devcontainer via: devcontainer exec -- bash -lc 'bash /workspaces/847-devcontainer/probe.sh'
# For each command: print command, exit code, and first 3 lines of output.
run() {
  local cmd="$1"
  local out
  out=$(bash -lc "$cmd" 2>&1 </dev/null); local rc=$?
  printf '\n$ %s\nexit=%s\n' "$cmd" "$rc"
  printf '%s\n' "$out" | head -3 | cut -c1-300
}
run 'brew install jq'
run 'npm i -g cowsay'
run 'docker ps'
run 'apt-get install -y jq'
run 'mkdir -p /tmp/x && chown -R vscode:vscode /tmp/x'
run 'chown -R vscode:vscode /home/vscode/.local/share'
run 'task --version'
run 'gh --version'
run 'claude --version'
run 'codex --version'
run 'cursor-agent --version'
run 'pip3 install --user requests'
run 'cat /etc/sudoers.d/* 2>&1'
run 'id'
printf '\n$ grep -rl sudo /home/vscode/.local/bin /home/vscode/.claude/*.sh 2>/dev/null | head\n'
grep -rl sudo /home/vscode/.local/bin /home/vscode/.claude/*.sh 2>/dev/null | head
