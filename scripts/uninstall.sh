#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Run as root.' >&2; exit 1; }
# Uninstall is explicit and disconnects remaining gate clients: migrate first.
/usr/local/sbin/xddp-rollback
systemctl disable --now xddp-gate.service xddp-controller.service
rm -f /etc/systemd/system/xddp-gate.service /etc/systemd/system/xddp-controller.service
rm -f /usr/local/bin/xddp-gate /usr/local/sbin/ddosctl /usr/local/sbin/xddp-rollback
rm -f /usr/local/libexec/xddp-loader /usr/local/libexec/xddp-preflight /usr/local/libexec/ddosctl /usr/local/libexec/preflight.sh
rm -f /usr/local/lib/xddp/controller/core.py /usr/local/lib/xddp/controller/ddosctl.py
rm -f /usr/local/lib/xddp/xdp_ddos.bpf.o /usr/local/lib/xddp/xdp_pass.bpf.o
systemctl daemon-reload
echo 'Configuration, xddp user, logs and bpffs generation pins retained for recovery.'
echo 'Delete individual unreferenced generation pins only after verifying no attachment uses them.'
