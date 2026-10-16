#!/bin/sh
# ---
# relationships:
#   implements:
#     - linux-service
#     - engine-proxy
# ---
set -eu

# Stop the old cgroup before replacing files; its supplementary groups are
# process credentials and survive account database changes.
if [ -d /run/systemd/system ] && { [ -e /usr/lib/systemd/system/wyrwood-agent.service ] || [ -e /etc/systemd/system/wyrwood-agent.service ]; }; then
 install -d -m 0700 -o root -g root /run/wyrwood-upgrade
 properties=$(systemctl show --property=LoadState,ActiveState wyrwood-agent.service)
 case "$properties" in
 *ActiveState=active*|*ActiveState=reloading*|*ActiveState=activating*)
  : > /run/wyrwood-upgrade/active
  ;;
 esac
 systemctl stop wyrwood-agent.service
fi
