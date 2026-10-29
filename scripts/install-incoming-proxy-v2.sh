#!/bin/sh
# Controlled XDDP Gate-only deployment for TCPShield PROXY protocol v2.
# Does not change XDP/controller, Leaf config, DNS, or firewall.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "Run as root" >&2; exit 1; }
export PATH="/root/.cargo/bin:$PATH"
for bin in git cargo python3 curl systemctl; do
    command -v "$bin" >/dev/null 2>&1 || { echo "Missing dependency: $bin" >&2; exit 1; }
done
GATE_CONFIG=/etc/xddp/gate.json
GATE_BIN=/usr/local/bin/xddp-gate
[ -f "$GATE_CONFIG" ] && [ -x "$GATE_BIN" ] || { echo "XDDP Gate not installed" >&2; exit 1; }
# Avoid modifying the gate until Leaf is ready for PROXY v2 input.
if [ "${LEAF_PROXY_READY:-}" != YES ]; then
    echo 'STOP: enable PROXY protocol on private Leaf/Paper listener first.'
    echo 'Then execute: sudo env LEAF_PROXY_READY=YES sh /tmp/xddp-install-proxy-v2.sh'
    exit 2
fi
work=$(mktemp -d /tmp/xddp-proxy-build.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
backup=$(mktemp -d /root/xddp-proxy-backup.XXXXXX)
chmod 700 "$backup"
cp -p "$GATE_CONFIG" "$backup/gate.json"
cp -p "$GATE_BIN" "$backup/xddp-gate"
echo "Backups: $backup"
git clone --depth 1 --branch feature/trusted-inbound-proxy-v2-20261029 \
    https://github.com/Pma10/XDDP.git "$work/source"
cargo build --release --locked --manifest-path "$work/source/gate/Cargo.toml"
cargo test --locked --manifest-path "$work/source/gate/Cargo.toml" incoming_proxy
python3 - "$GATE_CONFIG" "$work/gate.json" <<'PY'
import ipaddress, json, sys, urllib.request
from pathlib import Path
feeds = ("https://tcpshield.com/v4/", "https://tcpshield.com/v4-cf/")
networks = set()
for url in feeds:
    req = urllib.request.Request(url, headers={"User-Agent": "XDDP-proxy-v2-setup/1"})
    with urllib.request.urlopen(req, timeout=12) as response:
        data = response.read(65537)
    if len(data) > 65536:
        raise SystemExit("CIDR feed exceeds limit")
    found = []
    for line in data.decode("ascii").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        network = ipaddress.ip_network(line, strict=True)
        if network.version != 4 or network.prefixlen == 0:
            raise SystemExit(f"Unexpected CIDR from {url}: {network}")
        found.append(str(network))
    if not found:
        raise SystemExit(f"Empty trusted proxy feed: {url}")
    networks.update(found)
if not 1 <= len(networks) <= 512:
    raise SystemExit("Invalid number of proxy CIDRs")
cfg = json.loads(Path(sys.argv[1]).read_text())
cfg["incoming_proxy_v2"] = {"enabled": True, "trusted_proxies": sorted(networks)}
cfg["proxy_v2"] = True
cfg["allow_backend_identity_loss"] = False
Path(sys.argv[2]).write_text(json.dumps(cfg, indent=2) + "\n")
print("Trusted TCPShield ranges:", len(networks))
PY
"$work/source/gate/target/release/xddp-gate" "$work/gate.json" --check
newbin="/usr/local/bin/.xddp-gate-new-$$"
newcfg="/etc/xddp/.gate.json-new-$$"
install -m 0755 "$work/source/gate/target/release/xddp-gate" "$newbin"
cp "$work/gate.json" "$newcfg"
chown --reference="$GATE_CONFIG" "$newcfg"
chmod --reference="$GATE_CONFIG" "$newcfg"
restore() {
    echo "Gate deployment failed; restoring backup..."
    cp "$backup/gate.json" "$newcfg"
    chown --reference="$GATE_CONFIG" "$newcfg"
    chmod --reference="$GATE_CONFIG" "$newcfg"
    mv -f "$newcfg" "$GATE_CONFIG"
    cp "$backup/xddp-gate" "$newbin"
    chmod 755 "$newbin"
    mv -f "$newbin" "$GATE_BIN"
    systemctl restart xddp-gate || true
}
mv -f "$newbin" "$GATE_BIN"
mv -f "$newcfg" "$GATE_CONFIG"
if ! "$GATE_BIN" "$GATE_CONFIG" --check ||
   ! systemctl restart xddp-gate ||
   ! systemctl is-active --quiet xddp-gate; then
    restore
    exit 1
fi
echo "XDDP Gate is running with trusted incoming PROXY v2."
echo "Verify joins, Leaf real IP and Gate metrics. Rollback: $backup"
systemctl status xddp-gate --no-pager -l | head -n 20
