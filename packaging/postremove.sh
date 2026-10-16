#!/bin/sh
# ---
# relationships:
#   implements: linux-service
# ---
set -eu

case "${1:-}" in
remove | purge | 0)
 rm -f /etc/systemd/system/wyrwood-agent.service.d/10-wyrwood-engine-proxy.conf
 ;;
esac
if [ -d /run/systemd/system ]; then
 systemctl daemon-reload
fi
