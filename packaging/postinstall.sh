#!/bin/sh
# ---
# relationships:
#   implements: linux-service
# ---
set -e

if ! getent passwd wyrwood >/dev/null 2>&1; then
	useradd --system --user-group --home-dir /var/lib/wyrwood --no-create-home --shell /usr/sbin/nologin wyrwood
fi
if getent group docker >/dev/null 2>&1; then
	usermod --append --groups docker wyrwood
fi
install -d -m 0755 -o root -g root /etc/wyrwood
install -d -m 0700 -o wyrwood -g wyrwood /var/lib/wyrwood
if command -v systemd-tmpfiles >/dev/null 2>&1; then
	systemd-tmpfiles --create /usr/lib/tmpfiles.d/wyrwood.conf || true
fi
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
fi
