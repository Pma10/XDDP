#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include "shared.h"

_Static_assert(sizeof(struct config) == 40, "config ABI");
_Static_assert(sizeof(struct prefix_key) == 24, "prefix ABI");
_Static_assert(sizeof(struct stats) == 168, "stats ABI");

static void die(const char *s) { perror(s); exit(1); }
static void require(int ok, const char *s) {
    if (!ok) { fprintf(stderr, "%s\n", s); exit(2); }
}
static uint64_t number(const char *s, uint64_t max) {
    char *end;
    errno = 0;
    unsigned long long n = strtoull(s, &end, 10);
    require(*s && *s != '-' && !errno && !*end && n <= max, "invalid number");
    return n;
}
struct map_schema {
    const char *name;
    __u32 type, key_size, value_size, max_entries, flags;
};
static const struct map_schema schemas[] = {
    {"configuration", BPF_MAP_TYPE_ARRAY, 4, sizeof(struct config), 1, 0},
    {"counters", BPF_MAP_TYPE_PERCPU_ARRAY, 4, sizeof(struct stats), 1, 0},
    {"syn_budget", BPF_MAP_TYPE_PERCPU_ARRAY, 4, sizeof(struct bucket), 1, 0},
    {"ports", BPF_MAP_TYPE_ARRAY, 4, 4, 65536, 0},
    {"owned", BPF_MAP_TYPE_LPM_TRIE, sizeof(struct prefix_key), 4, PREFIX_CAP, BPF_F_NO_PREALLOC},
    {"allow", BPF_MAP_TYPE_LPM_TRIE, sizeof(struct prefix_key), 4, PREFIX_CAP, BPF_F_NO_PREALLOC},
    {"block", BPF_MAP_TYPE_LPM_TRIE, sizeof(struct prefix_key), 4, PREFIX_CAP, BPF_F_NO_PREALLOC},
};
static void check_map(int fd, const char *name) {
    struct bpf_map_info info = {};
    __u32 len = sizeof(info);
    if (bpf_obj_get_info_by_fd(fd, &info, &len)) die("map info");
    for (size_t i = 0; i < sizeof(schemas)/sizeof(schemas[0]); i++) {
        const struct map_schema *s = &schemas[i];
        if (strcmp(name, s->name)) continue;
        if (info.type != s->type || info.key_size != s->key_size ||
            info.value_size != s->value_size || info.max_entries != s->max_entries ||
            info.map_flags != s->flags) {
            fprintf(stderr, "incompatible pinned map %s: type=%u key=%u value=%u entries=%u flags=%u; use a fresh generation\n",
                    name, info.type, info.key_size, info.value_size, info.max_entries, info.map_flags);
            exit(2);
        }
        return;
    }
    require(0, "unknown map schema");
}
static int pinned(const char *dir, const char *name) {
    char path[PATH_MAX];
    require(snprintf(path, sizeof(path), "%s/%s", dir, name) < (int)sizeof(path), "path too long");
    int fd = bpf_obj_get(path);
    if (fd < 0) die(path);
    if (strcmp(name,"program")) check_map(fd,name);
    else {
        struct bpf_prog_info info = {};
        __u32 len = sizeof(info);
        if (bpf_obj_get_info_by_fd(fd,&info,&len)) die("program info");
        require(info.type == BPF_PROG_TYPE_XDP,"pinned program is not XDP");
    }
    return fd;
}
static void validate_generation(const char *dir) {
    int fd = pinned(dir,"program");
    __u32 ids[64] = {};
    struct bpf_prog_info prog = {.nr_map_ids=64, .map_ids=(uintptr_t)ids};
    __u32 len = sizeof(prog);
    if (bpf_obj_get_info_by_fd(fd,&prog,&len)) die("program map IDs");
    require(prog.nr_map_ids <= 64,"unexpected program map count");
    for (size_t i = 0; i < sizeof(schemas)/sizeof(schemas[0]); i++) {
        int map_fd = pinned(dir,schemas[i].name);
        struct bpf_map_info map = {};
        len = sizeof(map);
        if (bpf_obj_get_info_by_fd(map_fd,&map,&len)) die("map ID");
        int found = 0;
        for (__u32 j = 0; j < prog.nr_map_ids; j++) if (ids[j] == map.id) found = 1;
        if (!found) {
            fprintf(stderr,"pinned map %s does not belong to this program; use a complete generation\n",schemas[i].name);
            exit(2);
        }
        close(map_fd);
    }
    close(fd);
    puts("{\"valid\":true}");
}
static __u32 flags(const char *s) {
    if (!strcmp(s, "driver")) return XDP_FLAGS_DRV_MODE;
    if (!strcmp(s, "skb")) return XDP_FLAGS_SKB_MODE;
    require(0, "mode must be driver or skb (no automatic fallback)");
    return 0;
}
static unsigned iface(const char *s) {
    unsigned i = if_nametoindex(s);
    if (!i) die("if_nametoindex");
    return i;
}
static void load(const char *objpath, const char *dir) {
    struct rlimit lim = {RLIM_INFINITY, RLIM_INFINITY};
    /* Linux 6.1 normally charges BPF memory to memcg; older setups may need this. */
    (void)setrlimit(RLIMIT_MEMLOCK, &lim);
    struct bpf_object *obj = bpf_object__open_file(objpath, NULL);
    if (libbpf_get_error(obj)) die("bpf_object__open_file");
    if (bpf_object__load(obj)) die("BPF verifier/load (see libbpf log)");
    if (bpf_object__pin_maps(obj, dir)) die("pin maps: use a fresh generation directory");
    struct bpf_program *prog = bpf_object__next_program(obj, NULL);
    require(prog != NULL, "no BPF program");
    char path[PATH_MAX];
    require(snprintf(path, sizeof(path), "%s/program", dir) < (int)sizeof(path), "path too long");
    if (bpf_program__pin(prog, path)) die("pin program");
    bpf_object__close(obj);
}
static void attach(int argc, char **v) {
    require(argc == 6 || argc == 7, "attach IFACE PIN_DIR driver|skb [EXPECTED_ID]");
    unsigned index = iface(v[2]);
    __u32 f = flags(v[4]), old_id = 0;
    require(!strcmp(v[5], "confirmed"), "attach requires literal confirmed");
    if (bpf_xdp_query_id(index, f, &old_id)) die("query XDP");
    __u32 expected = argc == 7 ? number(v[6], UINT32_MAX) : 0;
    require(old_id == expected, "attachment changed or belongs to another program");
    int fd = pinned(v[3], "program"), old_fd = -1;
    LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
    if (old_id) {
        old_fd = bpf_prog_get_fd_by_id(old_id);
        if (old_fd < 0) die("old program fd");
        opts.old_prog_fd = old_fd;
        f |= XDP_FLAGS_REPLACE;
    } else f |= XDP_FLAGS_UPDATE_IF_NOEXIST;
    if (bpf_xdp_attach(index, fd, f, &opts)) die("attach (mode not changed)");
    close(fd);
    if (old_fd >= 0) close(old_fd);
}
static void detach(char **v) {
    unsigned index = iface(v[2]);
    __u32 f = flags(v[3]), current = 0;
    __u32 expected = number(v[4], UINT32_MAX);
    require(expected != 0, "expected program id must be nonzero");
    if (bpf_xdp_query_id(index, f, &current)) die("query XDP");
    require(current == expected, "refusing to detach a different program");
    int old_fd = bpf_prog_get_fd_by_id(current);
    if (old_fd < 0) die("old program fd");
    LIBBPF_OPTS(bpf_xdp_attach_opts, opts, .old_prog_fd = old_fd);
    if (bpf_xdp_detach(index, f, &opts)) die("detach");
    close(old_fd);
}
static void prefix(char **v) {
    require(!strcmp(v[3], "owned") || !strcmp(v[3], "allow") || !strcmp(v[3], "block"), "invalid prefix map");
    int fd = pinned(v[2], v[3]);
    char text[128];
    require(strlen(v[5]) < sizeof(text), "CIDR too long");
    strcpy(text, v[5]);
    char *slash = strchr(text, '/');
    struct prefix_key k = {};
    k.family = strchr(text, ':') ? 6 : 4;
    unsigned bits = k.family == 4 ? 32 : 128;
    if (slash) { *slash++ = 0; bits = number(slash, bits); }
    require(inet_pton(k.family == 4 ? AF_INET : AF_INET6, text, k.addr) == 1, "invalid address");
    k.prefixlen = 32 + bits;
    for (unsigned i = bits; i < (k.family == 4 ? 32U : 128U); i++)
        k.addr[i / 8] &= ~(1U << (7 - i % 8));
    if (!strcmp(v[4], "add")) {
        __u32 val = number(v[6], R_COUNT - 1);
        if (bpf_map_update_elem(fd, &k, &val, BPF_ANY)) die("prefix update");
    } else {
        require(!strcmp(v[4], "del"), "expected add or del");
        if (bpf_map_delete_elem(fd, &k) && errno != ENOENT) die("prefix delete");
    }
    close(fd);
}
static const char *reasons[R_COUNT] = {
    "none", "malformed_l2", "malformed_ipv4", "invalid_tcp", "blocked_port",
    "bogon", "fragment", "syn_rate", "source_rate", "prefix_rate",
    "global_rate", "manual_block", "other"
};
static void clear_map(const char *dir, const char *name) {
    require(!strcmp(name,"ports") || !strcmp(name,"owned") || !strcmp(name,"allow") || !strcmp(name,"block"), "cannot clear this map");
    int fd = pinned(dir,name);
    if (!strcmp(name,"ports")) {
        __u32 value = 0;
        for (__u32 k = 0; k < 65536; k++)
            if (bpf_map_update_elem(fd,&k,&value,BPF_ANY)) die("clear ports");
    } else {
        struct prefix_key k;
        for (int n = 0; n <= PREFIX_CAP; n++) {
            if (bpf_map_get_next_key(fd,NULL,&k)) {
                if (errno != ENOENT) die("next prefix");
                break;
            }
            if (bpf_map_delete_elem(fd,&k)) die("clear prefix");
        }
    }
    close(fd);
}
static void stats(const char *dir) {
    int fd = pinned(dir, "counters"), n = libbpf_num_possible_cpus();
    require(n > 0, "cannot enumerate possible CPUs");
    struct stats *all = calloc(n, sizeof(*all)), sum = {};
    if (!all) die("calloc");
    __u32 k = 0;
    if (bpf_map_lookup_elem(fd, &k, all)) die("stats lookup");
    for (int i = 0; i < n; i++) {
        sum.rx_packets += all[i].rx_packets; sum.rx_bytes += all[i].rx_bytes;
        sum.pass_packets += all[i].pass_packets; sum.drop_packets += all[i].drop_packets;
        sum.syn_packets += all[i].syn_packets; sum.udp_packets += all[i].udp_packets;
        sum.icmp_packets += all[i].icmp_packets; sum.ipv6_deferred += all[i].ipv6_deferred;
        for (int r = 0; r < R_COUNT; r++) sum.reasons[r] += all[i].reasons[r];
    }
    printf("{\"rx_packets\":%llu,\"rx_bytes\":%llu,\"pass_packets\":%llu,\"drop_packets\":%llu,"
           "\"syn_packets\":%llu,\"udp_packets\":%llu,\"icmp_packets\":%llu,\"ipv6_deferred\":%llu,\"possible_cpus\":%d,\"candidate_reasons\":{",
           (unsigned long long)sum.rx_packets, (unsigned long long)sum.rx_bytes,
           (unsigned long long)sum.pass_packets, (unsigned long long)sum.drop_packets,
           (unsigned long long)sum.syn_packets, (unsigned long long)sum.udp_packets,
           (unsigned long long)sum.icmp_packets, (unsigned long long)sum.ipv6_deferred, n);
    for (int r = 1; r < R_COUNT; r++) printf("%s\"%s\":%llu", r == 1 ? "" : ",", reasons[r], (unsigned long long)sum.reasons[r]);
    puts("}}");
    free(all); close(fd);
}
static void test_run(const char *dir, const char *path) {
    unsigned char data[131072];
    FILE *file = fopen(path,"rb");
    if (!file) die("packet file");
    size_t n = fread(data,1,sizeof(data),file);
    require(!ferror(file) && n < sizeof(data),"packet file too large or read failed");
    fclose(file);
    int fd = pinned(dir,"program");
    LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in=data, .data_size_in=n, .repeat=1);
    if (bpf_prog_test_run_opts(fd,&opts)) die("BPF_PROG_TEST_RUN");
    printf("{\"retval\":%u,\"duration_ns\":%u}\n",opts.retval,opts.duration);
    close(fd);
}
int main(int argc, char **v) {
    require(argc >= 2, "load|attach|detach|config|port|prefix|stats|status");
    if (!strcmp(v[1], "load") && argc == 4) load(v[2], v[3]);
    else if (!strcmp(v[1], "validate") && argc == 3) validate_generation(v[2]);
    else if (!strcmp(v[1], "attach")) attach(argc, v);
    else if (!strcmp(v[1], "detach") && argc == 5) detach(v);
    else if (!strcmp(v[1], "config") && argc == 11) {
        int fd = pinned(v[2], "configuration");
        __u32 k = 0;
        struct config c = {.abi = XDDP_ABI,
            .lease_ns = number(v[3], UINT64_MAX), .observe = number(v[4], 1),
            .mode = number(v[5], 3), .ipv6 = number(v[6], 1),
            .drop_tcp_fragments = number(v[7], 1), .syn_rate = number(v[8], 1000000000),
            .syn_burst = number(v[9], 1000000)};
        require(number(v[10], UINT32_MAX) == XDDP_ABI, "ABI mismatch");
        require((c.syn_rate == 0) == (c.syn_burst == 0), "rate and burst must both be zero or positive");
        if (bpf_map_update_elem(fd, &k, &c, BPF_ANY)) die("config update");
        close(fd);
    } else if (!strcmp(v[1], "port") && argc == 5) {
        int fd = pinned(v[2], "ports");
        __u32 k = number(v[3], 65535), val = number(v[4], 7);
        require(k != 0 && (val & 3) != 3, "invalid/conflicting port policy");
        if (bpf_map_update_elem(fd, &k, &val, BPF_ANY)) die("port update");
        close(fd);
    } else if (!strcmp(v[1], "prefix") && argc == 7) prefix(v);
    else if (!strcmp(v[1], "clear") && argc == 4) clear_map(v[2],v[3]);
    else if (!strcmp(v[1], "test") && argc == 4) test_run(v[2],v[3]);
    else if (!strcmp(v[1], "id") && argc == 3) {
        int fd = pinned(v[2],"program");
        struct bpf_prog_info info = {};
        __u32 len = sizeof(info);
        if (bpf_obj_get_info_by_fd(fd,&info,&len)) die("program info");
        printf("{\"program_id\":%u}\n",info.id);
        close(fd);
    }
    else if (!strcmp(v[1], "stats") && argc == 3) stats(v[2]);
    else if (!strcmp(v[1], "status") && argc == 4) {
        __u32 id = 0;
        if (bpf_xdp_query_id(iface(v[2]), flags(v[3]), &id)) die("query XDP");
        printf("{\"program_id\":%u,\"mode\":\"%s\"}\n", id, v[3]);
    } else require(0, "invalid command/arguments; see README and controller CLI");
    return 0;
}
