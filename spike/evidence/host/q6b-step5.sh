#!/usr/bin/env bash
cd ~/Code/spikes/847-devcontainer
X() { devcontainer exec --workspace-folder . -- bash -lc "$1" 2>&1; echo "  [exit=$?]"; }
echo "-- probe visible / id / sudoers.d before:"
X 'ls /workspaces/847-devcontainer/probe.sh; id; grep -hv "^#" /etc/sudoers.d/* 2>/dev/null | grep -v "^$"'
echo "-- sudo -n true BEFORE revoke:"
X 'sudo -n true && echo SUDO_OK'
echo "-- revoke:"
X "sudo bash -c 'rm -f /etc/sudoers.d/*; sed -i \"/NOPASSWD/d\" /etc/sudoers'"
echo "-- sudo -n true AFTER revoke:"
X 'sudo -n true && echo SUDO_OK'
echo "-- sudoers.d after / sudo -l:"
X 'ls -la /etc/sudoers.d/; sudo -n -l 2>&1 | head -3'
