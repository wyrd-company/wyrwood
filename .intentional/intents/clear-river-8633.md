---
wyrwood: minor
wyrwood-docs: patch
---

The agent now starts a bound container after a host reboot, once its sockets are ready. Docker's own start fails on the missing consumer directory and does not retry. The agent acts only on an exited container with a restart policy whose recorded error names that directory as missing. The Engine proxy now permits container start on every host, so a compromised agent can start any stopped container. Stop, remove, and create still need `allow-recreate`. A `-v` bind does not get this recovery; use `--mount type=bind`.
