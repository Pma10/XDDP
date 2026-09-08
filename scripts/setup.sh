#!/bin/sh
# Debian 12 / Ubuntu 24.04 source installer. Does not start a service or attach XDP.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
case "${1:-}" in
    --help|-h)
        cat <<'EOF'
Usage: sudo sh scripts/setup.sh
       sh scripts/setup.sh --help

Installs apt dependencies, prepares Rust >=1.85, builds and tests XDDP,
mounts bpffs if needed, and installs binaries, systemd units and sample config.
Existing config is preserved. Running XDDP services must be stopped explicitly
before an upgrade. No service start/enable, XDP attach, firewall or port changes.
Supported automatic setup: Debian 12/13 and Ubuntu 24.04, with systemd.
EOF
        exit 0 ;;
    '') [ "$#" -eq 0 ] || { echo 'Unexpected arguments; use --help.' >&2; exit 2; } ;;
    *) echo 'Unknown option; use --help.' >&2; exit 2 ;;
esac
[ "$(id -u)" -eq 0 ] || { echo 'Run: sudo sh scripts/setup.sh' >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo 'Run this installer on the Linux server.' >&2; exit 1; }
[ -f /etc/os-release ] || { echo 'Missing /etc/os-release.' >&2; exit 1; }
. /etc/os-release
case "$ID:${VERSION_ID:-}" in
    debian:12|debian:13|ubuntu:24.04) ;;
    *) echo 'Automatic setup supports Debian 12/13 or Ubuntu 24.04. See README for manual builds.' >&2; exit 1 ;;
esac
command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || {
    echo 'This installer requires a Linux host booted with systemd, not a build container.' >&2; exit 1;
}
if systemctl is-active --quiet xddp-gate.service xddp-controller.service; then
    echo 'XDDP is running. Schedule an upgrade and stop its services explicitly first; active players will disconnect if the gate is stopped.' >&2
    exit 1
fi
echo '[1/5] Installing build dependencies'
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl clang llvm gcc make pkg-config libbpf-dev libelf-dev \
    zlib1g-dev python3 iproute2 iputils-ping util-linux passwd
pkg-config --atleast-version=1.1 libbpf || { echo 'libbpf >=1.1 is required.' >&2; exit 1; }
echo '[2/5] Checking Rust toolchain'
rust_version=$(rustc --version 2>/dev/null | awk '{print $2}' | cut -d- -f1) || rust_version=''
if ! command -v cargo >/dev/null 2>&1 || [ -z "$rust_version" ] || ! dpkg --compare-versions "$rust_version" ge 1.85.0; then
    # Keep the installer toolchain separate from the operator's default Rust.
    export RUSTUP_HOME=/var/cache/xddp/rustup CARGO_HOME=/var/cache/xddp/cargo
    install -d -m 0700 /var/cache/xddp "$RUSTUP_HOME" "$CARGO_HOME"
    installer=$(mktemp /var/cache/xddp/rustup-init.XXXXXX)
    trap 'rm -f -- "$installer"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o "$installer"
    sh "$installer" -y --no-modify-path --profile minimal --default-toolchain 1.85.0
    export PATH="$CARGO_HOME/bin:$PATH" RUSTUP_TOOLCHAIN=1.85.0
fi
rustc --version
cargo --version
echo '[3/5] Building locked sources and running tests'
make all
make test
python3 tests/gate_integration.py --binary gate/target/release/xddp-gate
python3 tests/gate_integration.py --binary gate/target/release/xddp-gate --proxy-v2
python3 tests/gate_abuse_integration.py --binary gate/target/release/xddp-gate
python3 tests/gate_fairness_integration.py --binary gate/target/release/xddp-gate
python3 tests/gate_resilience_integration.py --binary gate/target/release/xddp-gate
echo '[4/5] Preparing bpffs (no XDP attachment)'
if ! mountpoint -q /sys/fs/bpf; then
    mount -t bpf bpf /sys/fs/bpf
fi
[ "$(stat -f -c %T /sys/fs/bpf)" = bpf_fs ] || { echo '/sys/fs/bpf is mounted with an unexpected filesystem.' >&2; exit 1; }
echo '[5/5] Installing files'
sh scripts/install.sh
printf '\nInstallation complete. Next: read docs/QUICKSTART.ko.md and edit /etc/xddp/*.json.\n'
printf 'Validate: sudo ddosctl --check && sudo xddp-gate /etc/xddp/gate.json --check\n'
printf 'Services remain stopped. Installation does not put traffic through XDDP.\n'
