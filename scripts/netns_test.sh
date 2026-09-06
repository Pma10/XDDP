#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
[ "$(id -u)" -eq 0 ] || { echo 'Root and disposable Linux host required.' >&2; exit 1; }
suffix=$$
client="xddp-c-$suffix"
server="xddp-s-$suffix"
left="xdc$suffix"
right="xds$suffix"
pin="/sys/fs/bpf/xddp-netns-$suffix"
cleanup() {
    ip netns del "$client" 2>/dev/null || true
    ip netns del "$server" 2>/dev/null || true
    ip link del "$left" 2>/dev/null || true
    if [ -d "$pin" ]; then
        find "$pin" -maxdepth 2 -type f -delete
        rmdir "$pin/passgen" 2>/dev/null || true
        rmdir "$pin"
    fi
}
[ ! -e "$pin" ] || { echo 'Test generation already exists.' >&2; exit 1; }
trap cleanup EXIT INT TERM
ip netns add "$client"
ip netns add "$server"
ip link add "$left" type veth peer name "$right"
ip link set "$left" netns "$client"
ip link set "$right" netns "$server"
ip -n "$client" link set lo up
ip -n "$server" link set lo up
ip -n "$client" addr add 192.0.2.2/30 dev "$left"
ip -n "$server" addr add 192.0.2.1/30 dev "$right"
ip -n "$client" link set "$left" mtu 1400 up
ip -n "$server" link set "$right" mtu 1400 up
mkdir "$pin"
build/xddp-loader load build/xdp_ddos.bpf.o "$pin"
build/xddp-loader prefix "$pin" owned add 192.0.2.1/32 1
build/xddp-loader port "$pin" 25565 1
deadline=$(python3 -c 'import time; print(time.monotonic_ns()+60_000_000_000)')
build/xddp-loader config "$pin" "$deadline" 0 0 0 0 0 0 1
nsenter --net="/run/netns/$server" -- "$(pwd)/build/xddp-loader" attach "$right" "$pin" driver confirmed
ip netns exec "$client" ping -c 3 -W 1 -M do -s 1372 192.0.2.1
nsenter --net="/run/netns/$server" -- "$(pwd)/build/xddp-loader" status "$right" driver
build/xddp-loader stats "$pin"
old_id=$(build/xddp-loader id "$pin" | python3 -c 'import json,sys; print(json.load(sys.stdin)["program_id"])')
mkdir "$pin/passgen"
build/xddp-loader load build/xdp_pass.bpf.o "$pin/passgen"
nsenter --net="/run/netns/$server" -- "$(pwd)/build/xddp-loader" attach "$right" "$pin/passgen" driver confirmed "$old_id"
if nsenter --net="/run/netns/$server" -- "$(pwd)/build/xddp-loader" attach "$right" "$pin" driver confirmed "$old_id"; then
    echo 'Stale expected-ID replacement unexpectedly succeeded.' >&2
    exit 1
fi
new_id=$(build/xddp-loader id "$pin/passgen" | python3 -c 'import json,sys; print(json.load(sys.stdin)["program_id"])')
nsenter --net="/run/netns/$server" -- "$(pwd)/build/xddp-loader" detach "$right" driver "$new_id"
ip netns exec "$client" ping -c 1 -W 1 192.0.2.1
echo 'PASS: native veth attach, MTU 1400 ICMP, atomic replacement, stale-ID rejection and detach. Production eth0 was not changed.'
