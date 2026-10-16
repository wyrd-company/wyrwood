#!/bin/sh
# ---
# relationships:
#   implements:
#     - linux-service
#     - engine-proxy
# ---
set -eu

# The same root-run account/unit transition serves package and archive installs.
/usr/bin/wyrwood agent service package-install
