#!/bin/sh
# ---
# relationships:
#   implements: linux-service
# ---
set -e

# Debian passes "remove" and RPM passes 0 when the package is removed rather
# than upgraded.
case "$1" in
remove | 0)
	if [ -d /run/systemd/system ]; then
		systemctl disable --now wyrwood-agent.service >/dev/null 2>&1 || true
	fi
	;;
esac
