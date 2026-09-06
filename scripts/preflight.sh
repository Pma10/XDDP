#!/bin/sh
set -eu
[ -d /sys/class/net/eth0 ] || { echo 'eth0 missing' >&2; exit 1; }
[ "$(stat -f -c %T /sys/fs/bpf)" = bpf_fs ] || { echo 'bpffs not mounted' >&2; exit 1; }
test -r /sys/kernel/btf/vmlinux
/usr/local/sbin/ddosctl --check
echo "Kernel $(uname -r); eth0 MTU $(cat /sys/class/net/eth0/mtu). No network settings changed."
