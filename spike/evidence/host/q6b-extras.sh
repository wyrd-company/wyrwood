echo "-- did brew jq actually install?"; which jq; jq --version 2>&1
echo "-- cowsay installed where?"; which cowsay
echo "-- /home/vscode/.local/bin contents:"; ls /home/vscode/.local/bin 2>&1 | head
echo "-- scripts calling sudo (feature-installed, /usr/local/bin + wrappers):"; grep -rls "sudo" /usr/local/bin /home/vscode/.local/bin /usr/local/share/*/bin 2>/dev/null | head
echo "-- /etc/sudoers NOPASSWD remaining:"; grep -c NOPASSWD /etc/sudoers 2>&1
echo "-- s6 / init:"; ps -p 1 -o comm=
