#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Run as root.' >&2; exit 1; }
# Uninstall is explicit and disconnects remaining gate clients: migrate first.
/usr/local/sbin/xddp-rollback
if [ -f /etc/systemd/system/xddp-deployment-check.timer ]; then
    systemctl disable --now xddp-deployment-check.timer
fi
if [ -f /etc/systemd/system/xddp-deployment-check.service ]; then
    systemctl stop xddp-deployment-check.service
fi
rm -f /etc/systemd/system/xddp-deployment-check.service /etc/systemd/system/xddp-deployment-check.timer
rm -f /usr/local/libexec/xddp-deployment-check /var/lib/prometheus/node-exporter/xddp-deployment.prom
systemctl disable --now xddp-gate.service xddp-controller.service
systemctl stop xddp-bpffs.service 2>/dev/null || true
rm -f /etc/systemd/system/xddp-gate.service /etc/systemd/system/xddp-controller.service /etc/systemd/system/xddp-bpffs.service
rm -f /usr/local/bin/xddp-gate /usr/local/sbin/ddosctl /usr/local/sbin/xddp-rollback
rm -f /usr/local/libexec/xddp-loader /usr/local/libexec/xddp-preflight /usr/local/libexec/xddp-prepare-bpffs /usr/local/libexec/ddosctl /usr/local/libexec/preflight.sh
rm -f /usr/local/lib/xddp/controller/core.py /usr/local/lib/xddp/controller/ddosctl.py /usr/local/lib/xddp/controller/history.py
rm -f /usr/local/lib/xddp/xdp_ddos.bpf.o /usr/local/lib/xddp/xdp_pass.bpf.o
systemctl daemon-reload
echo 'Configuration, telemetry archive, xddp user, logs and bpffs generation pins retained for recovery.'
echo 'Delete individual unreferenced generation pins only after verifying no attachment uses them.'
