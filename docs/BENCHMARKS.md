# Benchmark methodology and baseline collection

No throughput, p99 latency, jitter or real Minecraft authentication/gameplay
benchmark number is supplied by this project. Those are **MEASUREMENT REQUIRED**.
CI timing is a correctness smoke test and cannot stand in for the actual NIC,
vCPU scheduling, upstream path, player mix or Java workload.

## Comparison matrix

| Label | Configuration |
| --- | --- |
| BASELINE | No XDP, clients reach original proxy/backend |
| A | Minimal `xdp_pass.bpf.o`, same listener path |
| B | Production XDP, NORMAL; record observe/enforce and every budget |
| C | Production XDP, ATTACK; same player load and measured attack workload |
| D | XDP + gate + same backend, same player workload |

Run repetitions with the same owned clients, workload, CPU/IRQ placement,
offloads, MTU, connection reuse and background load. Randomize test order when
possible; separate warm-up from samples and record exact commit/config hashes.
Capture uncontended and peak legitimate NAT/reconnect bursts, then controlled
residual load. Keep established PvP clients active during every phase. Do not
send floods to third-party infrastructure or production without a test window.

## Read-only host sampling

```sh
python3 scripts/benchmark.py --label B --seconds 300 --pid 1234 --pid 5678 --output artifacts/B-host.jsonl
```

Use the actual gate and Java/Velocity PIDs; the numbers above are examples.
Create the output directory beforehand. The script refuses to overwrite output.
It samples per-CPU `/proc/stat`, NET_RX softirqs, interface RX/TX counters,
softnet drops/time-squeeze, TCP netstat counters, process CPU/RSS/I/O and gate/XDP
metrics once per second. Calculate interval deltas; do not compare cumulative
snapshots as if they were rates. Counters can reset after a restart. Record the
two RX paths independently and CPU steal time on virtual machines.

Inputs to observe: PPS, BPS, initial protected SYN/s, accepted connections/s,
handshakes/s, status/s, login starts/s, churn/s, active prelogin/admitted/backend,
scope rejection counts, unique identities/prefixes, and legitimate burst sizes.
The gate's new-entry counters are not unique identities per second.

For exact per-second identities in a **bounded operator-approved capture**, use
`identity_baseline.py`. For example, capture only SYN headers on the owned test
host using tcpdump packet/count/size/time bounds, keep the PCAP local under ignored
`artifacts/`, then:

```sh
python3 scripts/identity_baseline.py artifacts/syn-baseline.pcap --max-packets 200000 --output artifacts/identities.jsonl
```

This requires tshark; it does not perform live capture itself. It counts IPv4
/24 and IPv6 /64 prefixes from packet source addresses. Spoofed sources may be
present. Capture loss, sampling and count/time truncation limit coverage; the
output labels that scope and must not be extrapolated as exact whole-host PPS.
Do not publish PCAPs or real client address data with benchmark reports.

## External latency probes

Run from an owned external client, over the same scrubbed route as players:

```sh
python3 scripts/latency_probe.py --owned-test-endpoint --host YOUR_TEST_ADDRESS --virtual-host YOUR_GAME_HOST --count 300 --interval 1 --output artifacts/B-latency.json
```

The probe uses a low, explicitly bounded rate. It measures TCP connect, complete
status response and Minecraft status ping round-trip time, reports p50/p95/p99 and
adjacent absolute jitter, and records failures. It does **not** authenticate a
Minecraft player and does not measure gameplay responsiveness. Status may be
faster with the cache while gameplay is slower: do not confuse those paths.

Measure authenticated login and gameplay with the real owned clients/mods:
timestamp login completion, movement update arrival, PvP action/knockback responses,
application ping and server tick timings. Correlate with Java/Velocity CPU, GC,
socket queues, packet loss/retransmission and gate CPU/RSS. Keep client/server
timestamps synchronized when doing one-way latency; otherwise use RTT metrics.
Report distributions, not only means. Allocation profiling can use heaptrack or
an approved Rust allocator profiler in a separate run; label its overhead.

## Acceptance record

For every matrix row, record:

- CPU per RX/NAPI path and gate worker; NET_RX rate and CPU steal.
- Input/drop PPS and BPS; kernel/netfilter drops/retransmits and failed joins.
- Connection/status/authenticated-login latency p50/p95/p99, RTT/jitter, PvP
  movement/hit/knockback responsiveness with the same active player cohort.
- Java/Velocity CPU/GC; gate RSS, kernel socket memory, map memory and allocations
  where actually profiled.
- Configuration, commit, MTU, native attach mode, client versions, workload and
  duration. Record max false-positive/reconnect behavior for a large shared NAT.

Acceptance tolerances are **MEASUREMENT REQUIRED** and must be chosen by the
operator before comparing results. The priority is stable normal latency/jitter,
not maximum synthetic packet throughput. An unverified or regressed normal row
blocks enforcement rollout, regardless of attack drop rate.

RPS, CPUMAP, io_uring, worker pinning or NIC tuning is not enabled by this release.
Any experiment involving them must be a separate measured variant with rollback.
