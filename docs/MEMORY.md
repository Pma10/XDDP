# Maps, state and memory planning

All figures are planning estimates unless explicitly labelled as binary layout.
Kernel slab, hash buckets, allocation rounding, memcg accounting, runtime tasks
and socket buffers add overhead. Inspect `bpftool map show`, `/proc/PID/status`
and cgroup memory on the target; map `memlock` output is not total system cost.

## Actual XDP maps (ABI 1)

| Map | Kind | Key bytes | Value bytes | max_entries |
| --- | --- | ---: | ---: | ---: |
| configuration | ARRAY | 4 | 40 | 1 |
| counters | PERCPU_ARRAY | 4 | 168 | 1 |
| syn_budget | PERCPU_ARRAY | 4 | 24 | 1 |
| ports | ARRAY | 4 | 4 (array slot rounded to 8) | 65,536 |
| owned | LPM_TRIE | 24 | 4 | 4,096 |
| allow | LPM_TRIE | 24 | 4 | 4,096 |
| block | LPM_TRIE | 24 | 4 | 4,096 |

Prefix key: native-endian prefix length + native-endian family (4 or 6) + 16
network-order address bytes. Trie length is 32 + actual IP prefix length, so
IPv4/IPv6 cannot cross-match. IPv4 trailing bytes are zero. Port keys and flags
are host endian; packet port decoding is big endian. Shared structs have C
static size assertions. Prefix insertion rejects capacity overflow.

With six **possible** CPUs, counter values occupy 1,008 bytes and SYN buckets 144
bytes before map/per-CPU allocation overhead. Ports need about 512 KiB of array
storage. Three fully populated prefix tries conservatively budget about 3 MiB
at 256 bytes per logical entry, allowing internal branch nodes and slab overhead.
Actual trie cost depends on prefix overlap and allocation. Initial tries are empty.

There is **no dynamic XDP source/LRU map**, and no XDP per-flow state. These maps
do not grow with 100k/500k/1M spoofed addresses. Only administrative prefix updates
allocate trie nodes. XDP work does not duplicate per-source state across RX CPUs.

## Explicit hypothetical dynamic-map comparison

For evaluation of a future source-state design (not allocated by this release),
assume IPv4 key=4, value=32, approximately 68 bytes shared bookkeeping/rounding.
LRU_HASH budget is 104 bytes/entry; LRU_PERCPU_HASH is 72 + 32 × possible CPUs.
These are conservative model inputs, not exact kernel ABI sizes.

| Entries | LRU_HASH estimate | LRU_PERCPU_HASH, six possible CPUs |
| ---: | ---: | ---: |
| 100,000 | 9.92 MiB | 25.18 MiB |
| 500,000 | 49.59 MiB | 125.89 MiB |
| 1,000,000 | 99.18 MiB | 251.77 MiB |

Map buckets and additional allocator overhead can increase these estimates.
Use `scripts/memory_estimate.py --cpus N` to calculate alternatives. Possible CPUs,
not just two active RX paths, determine PERCPU value duplication.

## Actual gate state

Each IP and prefix entry stores active and pending counts, last activity, four token buckets,
decaying churn score, score time and penalty deadline. Each accepted client owns
one RAII ticket accounting for both scopes until connection closure. After
admission no per-packet table access occurs. Randomized hashing distributes
accepted identities over 64 shards. Default caps: 65,536 IP and 16,384 prefix
entries; no multiplication by worker/CPU count.

Get exact compiled layouts with:

```sh
gate/target/release/xddp-gate --state-sizes
python3 scripts/memory_estimate.py --gate-binary gate/target/release/xddp-gate --cpus 6
```

The [Debian CI binary for `b768a19`](https://github.com/Pma10/XDDP/actions/runs/34138498680)
reported key=17 bytes, entry=232 bytes and connection ticket=48 bytes. These are
Rust `size_of` values, not heap/RSS measurements. Table tuple alignment, allocator
rounding and hash-table spare capacity still apply; the conservative planning
table below deliberately retains larger layout assumptions.

Before binary measurement, budget key 24 bytes/value 256 bytes and nine bytes per
slot for control/padding. Round each shard to a power-of-two table capacity at
87.5% occupancy. Approximate table storage under that model:

| Requested entries | Rounded gate table estimate |
| ---: | ---: |
| 100,000 | 36.13 MiB |
| 500,000 | 289.00 MiB |
| 1,000,000 | 578.00 MiB |

These estimates intentionally include hash capacity jumps; they are not RSS
measurements. Defaults for both tables are roughly 45 MiB combined under the
same conservative capacity model. Empty tables allocate incrementally.

Pre-login framing stores each frame once, with the parsed body borrowing a slice
of the original wire buffer. Payload storage is bounded by the 32 KiB initial
wire budget per client: conservatively 16 MiB at 512 prelogin slots, plus futures,
tickets, semaphores and task/allocator overhead. Phase-specific length checks
usually impose a smaller bound and reject impossible lengths before allocation.
Status slots are a subset of prelogin slots, not an additional socket pool.
Relay buffers are 8 KiB per direction: approximately 64 MiB at 4,096 admitted
clients. Cache is one bounded response plus bounded parsing/fallback buffers.
Application memory remains bounded, but these values exclude kernel TCP buffers.
The optional upload guard uses a fixed-size per-connection token bucket and shares
the existing relay buffers. It creates no queue, per-packet allocation or IP map.

The configured 10,000 socket budget is independent of systemd's 524,288 FD ceiling.
Admission/default backend/prelogin caps jointly stay below the budget. Leave
additional descriptor and memory headroom for metrics, listeners, kernel autotuning,
Java, conntrack, filesystem cache and the operating system. Capacity and cap tuning
require measured process RSS/kernel socket memory at representative concurrency.
