#ifndef XDDP_PARSE_H
#define XDDP_PARSE_H
#include "shared.h"
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

struct packet {
    struct prefix_key src, dst;
    __u32 l4;
    __u32 ip_end;
    __u16 port;
    __u8 proto, flags, fragment, deferred;
};

static __always_inline __u16 be16(const __u8 *p)
{
    return ((__u16)p[0] << 8) | p[1];
}

/* Returns 0 for parsed IP, 1 for delegated traffic, negative drop reason.
 * All offsets and loops are bounded; Ethernet padding is excluded by ip_end. */
static __always_inline int parse_ip(const __u8 *d, const __u8 *end,
                                  struct packet *p)
{
    if (d + 14 > end) return -R_MALFORMED_L2;
    __u16 type = be16(d + 12);
    __u32 off = 14;
    for (int i = 0; i < 2; i++) {
        if (type != 0x8100 && type != 0x88a8) break;
        if (d + off + 4 > end) return -R_MALFORMED_L2;
        type = be16(d + off + 2);
        off += 4;
    }
    if (type == 0x0800) {
        if (d + off + 20 > end) return -R_MALFORMED_IPV4;
        const __u8 *ip = d + off;
        __u32 ihl = (ip[0] & 15) * 4;
        __u32 len = be16(ip + 2);
        if ((ip[0] >> 4) != 4 || ihl < 20 || len < ihl ||
            d + off + ihl > end || d + off + len > end)
            return -R_MALFORMED_IPV4;
        p->src.family = p->dst.family = 4;
        p->src.prefixlen = p->dst.prefixlen = 64;
        __builtin_memcpy(p->src.addr, ip + 12, 4);
        __builtin_memcpy(p->dst.addr, ip + 16, 4);
        p->proto = ip[9];
        p->fragment = (be16(ip + 6) & 0x3fff) != 0;
        p->l4 = off + ihl;
        p->ip_end = off + len;
    } else if (type == 0x86dd) {
        if (d + off + 40 > end) return -R_OTHER;
        const __u8 *ip = d + off;
        __u32 len = be16(ip + 4);
        if ((ip[0] >> 4) != 6 || d + off + 40 + len > end)
            return -R_OTHER;
        p->src.family = p->dst.family = 6;
        p->src.prefixlen = p->dst.prefixlen = 160;
        __builtin_memcpy(p->src.addr, ip + 8, 16);
        __builtin_memcpy(p->dst.addr, ip + 24, 16);
        p->proto = ip[6];
        p->l4 = off + 40;
        p->ip_end = off + 40 + len;
        /* Extension chains, jumbograms and fragments remain kernel policy. */
        if (!len || (p->proto != 6 && p->proto != 17 && p->proto != 58))
            p->deferred = 1;
    } else return 1;
    return 0;
}

static __always_inline int parse_transport(const __u8 *d, const __u8 *end,
                                         struct packet *p)
{
    if (p->fragment || p->deferred) return 1;
    __u32 off = p->l4;
    if (off > 65535 || off > p->ip_end) return -R_OTHER;
    const __u8 *t = d + off;
    if (p->proto == 6) {
        if (t + 20 > end || off + 20 > p->ip_end) return -R_INVALID_TCP;
        /* Read only fields covered by the fixed header check before doing any
         * variable-length arithmetic. This keeps the packet range proof
         * explicit on older 6.1 verifier paths. */
        p->port = be16(t + 2);
        p->flags = t[13];
        __u32 len = (t[12] >> 4) * 4;
        if (len < 20 || off + len > p->ip_end || t + len > end)
            return -R_INVALID_TCP;
        if (((p->flags & 2) && (p->flags & 5)) ||
            ((p->flags & 5) == 5)) return -R_INVALID_TCP;
    } else if (p->proto == 17) {
        if (t + 8 > end || off + 8 > p->ip_end) return -R_OTHER;
        /* Same ordering for UDP: the fixed eight-byte check covers both
         * length and destination-port reads. */
        p->port = be16(t + 2);
        __u32 len = be16(t + 4);
        if (len < 8 || off + len > p->ip_end || t + len > end)
            return -R_OTHER;
    }
    return 0;
}
#endif
