#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
# DESTDIR is for package staging and CI: it never modifies users, mounts or units.
dest=${DESTDIR:-}
if [ -n "$dest" ]; then
    case "$dest" in /*) ;; *) echo 'DESTDIR must be absolute.' >&2; exit 1 ;; esac
    [ -d "$dest" ] || { echo 'Create DESTDIR before staging.' >&2; exit 1; }
    dest=$(CDPATH= cd -- "$dest" && pwd -P)
    [ "$dest" != / ] || { echo 'DESTDIR must not resolve to /.' >&2; exit 1; }
else
    [ "$(id -u)" -eq 0 ] || { echo 'Run as root after make all and tests.' >&2; exit 1; }
    if systemctl is-active --quiet xddp-gate.service xddp-controller.service; then
        echo 'Refusing to replace running XDDP binaries; stop services in a planned upgrade first.' >&2; exit 1
    fi
fi
for file in build/xddp-loader build/xdp_ddos.bpf.o build/xdp_pass.bpf.o gate/target/release/xddp-gate; do
    [ -f "$file" ] || { echo "Missing $file; build first." >&2; exit 1; }
done
if [ -z "$dest" ]; then
    mountpoint -q /sys/fs/bpf || { echo 'Mount bpffs at /sys/fs/bpf before installation, or use scripts/setup.sh.' >&2; exit 1; }
    [ "$(stat -f -c %T /sys/fs/bpf)" = bpf_fs ] || { echo '/sys/fs/bpf is not bpffs.' >&2; exit 1; }
    getent passwd xddp >/dev/null || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin xddp
    install -d -m 0755 /sys/fs/bpf/xddp
fi
install -d -m 0755 "$dest/usr/local/lib/xddp/controller" "$dest/usr/local/libexec" "$dest/usr/local/sbin" "$dest/usr/local/bin" "$dest/etc/xddp" "$dest/etc/systemd/system"
install -m 0755 build/xddp-loader "$dest/usr/local/libexec/xddp-loader"
install -m 0644 build/xdp_ddos.bpf.o build/xdp_pass.bpf.o "$dest/usr/local/lib/xddp/"
install -m 0755 gate/target/release/xddp-gate "$dest/usr/local/bin/xddp-gate"
install -m 0644 controller/core.py controller/ddosctl.py "$dest/usr/local/lib/xddp/controller/"
install -m 0755 scripts/ddosctl "$dest/usr/local/sbin/ddosctl"
install -m 0755 scripts/preflight.sh "$dest/usr/local/libexec/xddp-preflight"
install -m 0755 scripts/rollback.py "$dest/usr/local/sbin/xddp-rollback"
for name in controller gate; do
    if [ ! -e "$dest/etc/xddp/$name.json" ] && [ ! -L "$dest/etc/xddp/$name.json" ]; then
        install -m 0644 "config/$name.json" "$dest/etc/xddp/$name.json"
    fi
done
install -m 0644 systemd/*.service "$dest/etc/systemd/system/"
if [ -z "$dest" ]; then systemctl daemon-reload; fi
echo 'Installed files only. No services started/enabled, no XDP attached, no ports/firewall changed.'
echo 'Review /etc/xddp/*.json and docs/DEPLOYMENT.md before starting services.'
