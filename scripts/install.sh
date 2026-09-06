#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
[ "$(id -u)" -eq 0 ] || { echo 'Run as root after make all and tests.' >&2; exit 1; }
for file in build/xddp-loader build/xdp_ddos.bpf.o gate/target/release/xddp-gate; do
    [ -f "$file" ] || { echo "Missing $file; build first." >&2; exit 1; }
done
mountpoint -q /sys/fs/bpf || { echo 'Mount bpffs at /sys/fs/bpf before installation.' >&2; exit 1; }
[ "$(stat -f -c %T /sys/fs/bpf)" = bpf_fs ] || { echo '/sys/fs/bpf is not bpffs.' >&2; exit 1; }
getent passwd xddp >/dev/null || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin xddp
install -d -m 0755 /usr/local/lib/xddp/controller /usr/local/libexec /usr/local/sbin /usr/local/bin /sys/fs/bpf/xddp /etc/xddp
install -m 0755 build/xddp-loader /usr/local/libexec/xddp-loader
install -m 0644 build/xdp_ddos.bpf.o build/xdp_pass.bpf.o /usr/local/lib/xddp/
install -m 0755 gate/target/release/xddp-gate /usr/local/bin/xddp-gate
install -m 0644 controller/core.py controller/ddosctl.py /usr/local/lib/xddp/controller/
install -m 0755 scripts/ddosctl scripts/preflight.sh /usr/local/libexec/
install -m 0755 scripts/ddosctl /usr/local/sbin/ddosctl
install -m 0755 scripts/preflight.sh /usr/local/libexec/xddp-preflight
install -m 0755 scripts/rollback.py /usr/local/sbin/xddp-rollback
for name in controller gate; do
    if [ ! -e "/etc/xddp/$name.json" ]; then
        install -m 0644 "config/$name.json" "/etc/xddp/$name.json"
    fi
done
install -m 0644 systemd/*.service /etc/systemd/system/
systemctl daemon-reload
echo 'Installed files only. No services started/enabled, no XDP attached, no ports/firewall changed.'
echo 'Review /etc/xddp/*.json and docs/DEPLOYMENT.md before starting services.'
