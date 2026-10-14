#!/bin/sh
# ---
# relationships:
#   implements: linux-service
# ---
set -e

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
fi
