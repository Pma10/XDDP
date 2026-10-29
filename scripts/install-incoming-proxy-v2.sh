#!/bin/sh
# Gate-only TCPShield PROXY v2 migration. Does not touch XDP/controller/Leaf/firewall.
set -eu

die() { echo "ERROR: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "Run as root"
[ "\${LEAF_PROXY_READY:-}" = YES ] || die "First enable PROXY protocol on the Leaf/private backend, then set LEAF_PROXY_READY=YES"
command -v git >/dev/null 2>&1 || die "git is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
command -v systemctl >/dev/null 2>&1 || die "systemctl is required"
command -v curl >/dev/null 2>&1 || die "curl is required"

GATE_CONFIG=/etc/xddp/gate.json
GATE_BIN=/usr/local/bin/xddp-gate
[ -f "$GATE_CONFIG" ] && [ -x "$GATE_BIN" ] || die "Existing XDDP Gate not installed"

# Prefer the existing Rust toolchain. The host may have XDDP installed without Cargo.
export PATH="/root/.cargo/bin:/var/cache/xddp/cargo/bin:$PATH"
if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
    command -v apt-get >/dev/null 2>&1 || die "Install Rust >= 1.85 manually (apt-get unavailable)"
    echo "[1/6] Installing missing Rust toolchain dependencies"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential pkg-config ca-certificates curl git
    export RUSTUP_HOME=/var/cache/xddp/rustup CARGO_HOME=/var/cache/xddp/cargo
    install -d -m 0700 "$RUSTUP_HOME" "$CARGO_HOME"
    installer=$(mktemp /tmp/xddp-rustup-init.XXXXXX)
    curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o "$installer"
    sh "$installer" -y --no-modify-path --profile minimal --default-toolchain 1.85.0
    rm -f "$installer"
    export PATH="$CARGO_HOME/bin:$PATH" RUSTUP_TOOLCHAIN=1.85.0
fi
rustc --version
cargo --version

work=$(mktemp -d /tmp/xddp-proxy-build.XXXXXX)
backup=$(mktemp -d /root/xddp-proxy-backup.XXXXXX)
chmod 700 "$backup"
cp -p "$GATE_CONFIG" "$backup/gate.json"
cp -p "$GATE_BIN" "$backup/xddp-gate"
echo "Backup directory: $backup"

deploy_started=0
deployed=0
cleanup() {
    rc=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ "$deploy_started" -eq 1 ] && [ "$deployed" -eq 0 ]; then
        echo "Installation failed; restoring previous Gate binary and config..." >&2
        cp -p "$backup/xddp-gate" "$GATE_BIN"
        cp -p "$backup/gate.json" "$GATE_CONFIG"
        systemctl restart xddp-gate
    fi
    rm -rf "$work"
    exit "$rc"
}
trap 'cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

echo "[2/6] Fetching patch and building"
git clone --depth 1 --branch feature/trusted-inbound-proxy-v2-20261029 \
    https://github.com/Pma10/XDDP.git "$work/source"
cargo build --release --locked --manifest-path "$work/source/gate/Cargo.toml"
cargo test --locked --manifest-path "$work/source/gate/Cargo.toml"
python3 "$work/source/tests/gate_proxy_ingress_integration.py" \
    --binary "$work/source/gate/target/release/xddp-gate"

echo "[3/6] Preparing configuration (preserving existing trusted proxies)"
python3 - "$GATE_CONFIG" "$work/gate.json" <<'PY'
import ipaddress, json, sys, urllib.request
from pathlib import Path

source = Path(sys.argv[1])
config = json.loads(source.read_text())
existing = config.get("incoming_proxy_v2", {}).get("trusted_proxies", [])
if existing:
    ranges = existing
    print("Preserving", len(ranges), "existing trusted CIDRs")
else:
    ranges = []
    for url in ("https://tcpshield.com/v4/", "https://tcpshield.com/v4-cf/"):
        req = urllib.request.Request(url, headers={"User-Agent": "XDDP-gate/1"})
        with urllib.request.urlopen(req, timeout=12) as response:
            data = response.read(65537)
        if len(data) > 65536:
            raise SystemExit("TCPShield CIDR feed too large")
        parsed = []
        for raw in data.decode("ascii").splitlines():
            cidr = raw.strip()
            if not cidr or cidr.startswith("#"):
                continue
            net = ipaddress.ip_network(cidr, strict=True)
            if net.version != 4 or net.prefixlen == 0:
                raise SystemExit("Unsupported trusted CIDR: " + cidr)
            parsed.append(str(net))
        if not parsed:
            raise SystemExit("Empty TCPShield CIDR feed: " + url)
        ranges.extend(parsed)
    ranges = sorted(set(ranges))
if not 1 <= len(ranges) <= 512:
    raise SystemExit("Invalid trusted CIDR count")
if "0.0.0.0/1" in ranges or "128.0.0.0/1" in ranges:
    print("WARNING: broad trust enables client IP spoofing without an origin firewall")
config["incoming_proxy_v2"] = {"enabled": True, "trusted_proxies": ranges}
config["proxy_v2"] = True
config["allow_backend_identity_loss"] = False
Path(sys.argv[2]).write_text(json.dumps(config, indent=2) + "\n")
PY

echo "[4/6] Validating new Gate and configuration"
newgate="$work/source/gate/target/release/xddp-gate"
"$newgate" "$work/gate.json" --check
echo "[5/6] Updating Gate (player connections may disconnect)"
# No deployment step occurs until build, tests and config validation pass.
deploy_started=1
install -m 0755 "$newgate" "$GATE_BIN.new"
cp -p "$work/gate.json" "$GATE_CONFIG.new"
chown --reference="$GATE_CONFIG" "$GATE_CONFIG.new"
chmod --reference="$GATE_CONFIG" "$GATE_CONFIG.new"
mv -f "$GATE_BIN.new" "$GATE_BIN"
mv -f "$GATE_CONFIG.new" "$GATE_CONFIG"
systemctl restart xddp-gate
systemctl is-active --quiet xddp-gate || die "Gate failed to start"
deployed=1

echo "[6/6] Gate ready. Run a real TCPShield Minecraft join test."
echo "Backup: $backup"
echo "XDP and controller were not restarted."
systemctl --no-pager --full status xddp-gate | head -n 18
