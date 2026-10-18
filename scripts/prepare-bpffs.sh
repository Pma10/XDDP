#!/bin/sh
set -eu
[ "$(stat -f -c %T /sys/fs/bpf)" = bpf_fs ] || { echo 'bpffs is not mounted' >&2; exit 1; }
install -d -m 0755 /sys/fs/bpf/xddp
