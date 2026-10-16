#!/bin/sh
# ---
# relationships:
#   implements: linux-service
# ---
set -eu

# Debian uses "remove", RPM uses 0; upgrades keep boot enablement intact.
case "$1" in
remove | 0)
 if [ -d /run/systemd/system ]; then
  systemctl disable --now wyrwood-agent.service
  systemctl stop wyrwood-engine-proxy.service
 fi
 ;;
esac
