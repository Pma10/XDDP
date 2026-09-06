#ifndef XDDP_SHARED_H
#define XDDP_SHARED_H
#include <linux/types.h>

#define XDDP_ABI 1
#define PORT_PROTECT_TCP 1
#define PORT_DROP_TCP 2
#define PORT_DROP_UDP 4
#define PREFIX_CAP 4096

enum reason {
    R_NONE, R_MALFORMED_L2, R_MALFORMED_IPV4, R_INVALID_TCP,
    R_BLOCKED_PORT, R_BOGON, R_FRAGMENT, R_SYN_RATE, R_SOURCE_RATE,
    R_PREFIX_RATE, R_GLOBAL_RATE, R_MANUAL_BLOCK, R_OTHER, R_COUNT
};

/* Explicit sizes/ordering are mirrored by controller and checked by loader. */
struct config {
    __u64 lease_ns;
    __u32 abi;
    __u32 observe;
    __u32 mode;
    __u32 ipv6;
    __u32 drop_tcp_fragments;
    __u32 syn_rate;
    __u32 syn_burst;
    __u32 pad;
};

struct prefix_key {
    __u32 prefixlen;
    __u32 family;
    __u8 addr[16];
};

struct stats {
    __u64 rx_packets, rx_bytes, pass_packets, drop_packets;
    __u64 syn_packets, udp_packets, icmp_packets, ipv6_deferred;
    __u64 reasons[R_COUNT];
};

struct bucket {
    __u64 last_ns;
    __u64 credit_ns;
    __u32 rate, burst;
};
#endif
