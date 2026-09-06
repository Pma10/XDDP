#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "parse.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} configuration SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct bucket);
} syn_budget SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} ports SEC(".maps");

#define PREFIX_MAP(name) struct { \
    __uint(type, BPF_MAP_TYPE_LPM_TRIE); \
    __uint(max_entries, PREFIX_CAP); \
    __uint(map_flags, BPF_F_NO_PREALLOC); \
    __type(key, struct prefix_key); \
    __type(value, __u32); \
} name SEC(".maps")
PREFIX_MAP(owned);
PREFIX_MAP(allow);
PREFIX_MAP(block);

static __always_inline int result(struct stats *s, struct config *c,
                                  int why, __u64 now)
{
    if (why > 0 && why < R_COUNT) {
        s->reasons[why]++;
        if (c && c->abi == XDDP_ABI && !c->observe && now < c->lease_ns) {
            s->drop_packets++;
            return XDP_DROP;
        }
    }
    s->pass_packets++;
    return XDP_PASS;
}

static __always_inline int syn_allowed(struct config *c, __u64 now)
{
    if (!c->syn_rate || !c->syn_burst) return 1;
    __u32 zero = 0;
    struct bucket *b = bpf_map_lookup_elem(&syn_budget, &zero);
    if (!b) return 1;
    /* Rate bounds validated by controller; cap protects direct map writes. */
    __u32 rate = c->syn_rate > 1000000000U ? 1000000000U : c->syn_rate;
    __u32 burst = c->syn_burst > 1000000U ? 1000000U : c->syn_burst;
    __u64 cost = 1000000000ULL / rate;
    __u64 cap = cost * burst;
    if (!b->last_ns || b->rate != rate || b->burst != burst) {
        b->credit_ns = cap;
        b->rate = rate;
        b->burst = burst;
    } else {
        __u64 dt = now - b->last_ns;
        if (dt > cap) dt = cap;
        b->credit_ns = b->credit_ns > cap - dt ? cap : b->credit_ns + dt;
    }
    b->last_ns = now;
    if (b->credit_ns < cost) return 0;
    b->credit_ns -= cost;
    return 1;
}

SEC("xdp")
int xddp(struct xdp_md *ctx)
{
    const __u8 *d = (void *)(long)ctx->data;
    const __u8 *end = (void *)(long)ctx->data_end;
    __u32 zero = 0;
    struct stats *s = bpf_map_lookup_elem(&counters, &zero);
    struct config *c = bpf_map_lookup_elem(&configuration, &zero);
    if (!s) return XDP_PASS;
    s->rx_packets++;
    s->rx_bytes += end - d;
    __u64 now = bpf_ktime_get_ns();
    struct packet p = {};
    int r = parse_ip(d, end, &p);
    if (r) return result(s, c, r < 0 ? -r : 0, now);
    if (p.proto == 1 || p.proto == 58) {
        s->icmp_packets++;
        return result(s, c, 0, now);
    }
    if (p.proto == 17) s->udp_packets++;
    if (p.deferred) s->ipv6_deferred++;
    if (!c || (p.dst.family == 6 && !c->ipv6) ||
        !bpf_map_lookup_elem(&owned, &p.dst)) return result(s, c, 0, now);
    if (p.fragment) {
        return result(s, c, p.proto == 6 && c->drop_tcp_fragments ? R_FRAGMENT : 0, now);
    }
    r = parse_transport(d, end, &p);
    if (r) return result(s, c, r < 0 ? -r : 0, now);
    __u32 port = p.port;
    __u32 *policy = bpf_map_lookup_elem(&ports, &port);
    if (!policy) return result(s, c, 0, now);
    if ((p.proto == 6 && (*policy & PORT_DROP_TCP)) ||
        (p.proto == 17 && (*policy & PORT_DROP_UDP)))
        return result(s, c, R_BLOCKED_PORT, now);
    if (p.proto != 6 || !(*policy & PORT_PROTECT_TCP)) return result(s, c, 0, now);
    int syn = (p.flags & 0x12) == 0x02;
    if (syn) s->syn_packets++;
    if (bpf_map_lookup_elem(&allow, &p.src)) return result(s, c, 0, now);
    __u32 *deny = bpf_map_lookup_elem(&block, &p.src);
    if (deny) return result(s, c, *deny == R_BOGON ? R_BOGON : R_MANUAL_BLOCK, now);
    if (syn && !syn_allowed(c, now)) return result(s, c, R_SYN_RATE, now);
    return result(s, c, 0, now);
}

char LICENSE[] SEC("license") = "GPL";
