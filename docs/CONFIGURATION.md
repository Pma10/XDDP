# Configuration and metrics

Both JSON schemas reject unknown fields. Startup validation fails for conflicting
ports, invalid CIDRs, unsupported schema names, zero phase deadlines, NaN/negative
rates, oversized buffers, impossible resource budgets and non-loopback metrics.
Rate pair `per_second=0, burst=0` disables that bucket. Nonzero buckets require
a positive finite rate and burst >=1. SYN budgets use integer rate/burst.

## Observation and modes

XDP observation passes candidate drops, including malformed headers. Counters
still record the candidate reason. Linux/nftables remains responsible for its
usual validation. Global RX/bytes/pass/drop counters cover the attached surface;
SYN counters cover initial SYNs on explicitly owned protected services. UDP and
ICMP counts cover parsed IP traffic. Per-CPU snapshots are approximate under
concurrent traffic, not transactional or suitable for billing.

Gate observation records rate/score violations without enforcing them. It still
enforces frame validation, deadlines, socket/memory bounds and configured
concurrency caps: observation does not mean forwarding malformed streams to Java.
No logging is performed per rejected packet or client.

NORMAL/ELEVATED/ATTACK select configured SYN budgets and admission multipliers.
Rate reductions affect connect/handshake/status/login, never relays. In enforced
EMERGENCY no new client is admitted, including an allow-listed client. Prefix
allow-listing exempts source/prefix rate/penalty/deny policy, not hard caps or
global rate limits. Empty/zero rate configuration stays disabled in every mode.
The sample nonzero multipliers only scale operator-configured rates; they are
not production thresholds. All actual rates/transition thresholds require data.

An adaptive threshold entry has `enter` and lower `exit` values. Any available
signal crossing `enter` selects the corresponding severity. Escalation requires
consecutive samples and cooldown. De-escalation requires every signal configured
for the current mode to be present and below `exit`, consecutive samples and
cooldown, then decreases one mode. Missing telemetry cannot itself escalate or
justify recovery. Empty bands never trigger a mode. Samples reset after counter
restart; negative deltas are discarded.

Controller leases use CLOCK_MONOTONIC-compatible nanoseconds for XDP. Gate state
combines a short wall-clock expiry with a local monotonic receipt deadline and a
changing generation. Unchanged files do not renew leases. With a nonempty
`runtime_file`, missing/stale controller state means NORMAL/observation; set
`runtime_file=""` only for standalone gate operation governed by `observe`.

## Admission bounds

`total_sockets` bounds gate-owned player/cache TCP sockets. The sum of `prelogin`,
`admitted` and `backend` must fit inside it. One backend slot is reserved for the
single cache task. Metrics has a separate fixed eight-client limit; allow FD
headroom for listeners, metrics, epoll, files and runtime infrastructure.
Backend counters include connecting/reserved attempts. Kernel socket memory is
additional to Rust buffers and depends on kernel autotuning.

IP/prefix connection caps of zero disable those caps, leaving global resource
caps. This is the CGNAT-friendly default. Other caps apply even with observation
or source allow-listing. Source tables have 64 randomly hashed shards; capacities
must be multiples of 64. Saturated shards reject new identities until entries
expire. Active entries are never evicted. A sweep visits one shard per 100 ms;
an idle entry may outlive `idle_entry_seconds` by approximately 6.4 seconds.

`status_connections` caps simultaneous sessions identified by a valid status
handshake, including those waiting to send the request or ping. They still count
toward `prelogin` and all socket/source caps. The example allows 128 status
sessions inside 512 prelogin slots, leaving space for login and unclassified
handshakes. This is a staging resource allocation, not a measured production
threshold. Missing/zero keeps the previous shared-cap behavior; a nonzero value
must not exceed `prelogin`. At the cap, excess status clients are closed without
waiting in a queue or accruing churn. Monitor `active_status` and
`status_capacity_limited` when sizing for legitimate browser/monitor bursts.
This does not reserve bandwidth or global connect/handshake tokens, and clients
that have not supplied a valid handshake still share the initial prelogin cap.

`prelogin_ip` and `prelogin_prefix` separately cap incomplete connections per
identity. Zero disables the respective cap; nonzero values must be <= `prelogin`.
Admission frees these pending counts while retaining total connection counts.
They apply in observation and to allowed sources, like other resource caps.
Size shared-NAT limits from legitimate simultaneous joins, not player counts.

Churn includes incomplete pre-admission disconnects. Successful status clients
and all admitted relays are exempt: a backend/BotSentry close is not evidence of
client fault. `churn_window_seconds` is retained for old configurations but no
longer scores short relay lifetimes. An incomplete handshake contributes 1, other incomplete sessions
0.25; the score decays with the configured half-life. A nonzero threshold gives
a temporary penalty. All penalty thresholds start disabled. Neither a score
nor any single behavior permanently blocks an IP or prefix. One IP is not one
player. Set rates and bursts from measured large NAT joins and reconnects.
`churn_score_threshold` controls IP penalties. The separate optional
`churn_prefix_score_threshold` defaults to zero, even with IP penalties enabled;
a single source should not implicitly activate a shared-NAT penalty.
Gate-initiated policy/cap rejection and backend connection/write failure before
relay do not accrue churn: an unavailable server must not penalize retrying
players or their shared NAT. Malformed or incomplete client input still counts.

Handshake/status/login tokens are charged only after IP, prefix and global policy
accepts the event. An enforced source rejection cannot spend a shared prefix or
global event budget. Source-exempt clients spend only the global event budget.
Connect IP/prefix tokens likewise commit together; the separate global accept
guard still counts incoming accepts before allocating identity state, including
clients later rejected by source policy. Observation records candidates and
charges available buckets without creating token debt.

## Minecraft compatibility

Frame length checks also use the current phase's accepted wire layout before
allocating or reading the body: status request is up to five bytes, ping up to thirteen bytes,
handshake is bounded by the configured host limit, and Login Start by its selected
schema. Signed-key schemas retain their full permitted blob lengths; custom
version mappings use the same schema bounds. Global frame/initial-byte limits
still apply. Valid frames keep their original bytes in one buffer, with parsers
borrowing a body slice; split/coalesced delivery requires no extra client exchange.
Canonical status/ping bodies remain one/nine bytes. Bounded padded VarInts are
also accepted, matching compatible protocol decoders: frame length is <=3 bytes,
field VarInts <=5 bytes. Overflow, nontermination, invalid IDs and trailing bytes
are still rejected. Schema bounds include padded field lengths.

## Optional per-connection upload budget

`upload` is optional and defaults to `bytes_per_second=0, burst_bytes=0,
enforce=false`. Zero/zero retains the existing relay implementation. A positive
rate/burst enables byte accounting and a private token bucket for each relay.
With `enforce=false`, over-budget connections are counted but forwarded normally.
With `enforce=true`, the gate discards the chunk exceeding the available budget
and closes that connection. It neither queues/throttles chunks nor blocks the
client's IP/prefix. Download traffic is not rate-limited. Half-close is preserved.

This is a static resource policy, independent of adaptive modes, source allow
lists and the controller's `observe` switch. Start with upload `enforce=false`
and measured positive values; enabling enforcement requires a controlled gate
restart. Values are bytes/sec and bytes, both <=1e9. Include legitimate mod/plugin
uploads, receive batching and scheduling delay when choosing the burst allowance.
No production upload thresholds are supplied.

The budget starts after validated Login Start reaches the backend, before any
claim of authentication or BotSentry approval. It counts opaque TCP payload, not
Minecraft packets or NIC PPS. It cannot prevent receive-link/kernel overload or
a distributed attack staying below every connection's budget; retain aggregate
admission/resource limits and upstream mitigation.

`upload_budget_exceeded_connections` counts at most one violation per monitored
connection. `monitored_upload_bytes` includes bytes read and rejected at the
guard; `monitored_download_bytes` counts successful writes to the client socket.
Both byte counters cover monitored relays only and exclude prelogin/cache traffic.
Budgets use no shared mutex and introduce no extra relay buffer.

## Policy publication checks

The controller verifies that both its saved configuration and runtime document
fit the gate's 256 KiB limit before modifying maps or leases. The gate reads at
most limit+1 bytes rather than trusting a prior file-size check. An explicit new
expired generation takes effect when read; stale unchanged files never renew it.
`runtime_generation` is the active applied generation, or zero on stale/missing
policy. `runtime_rejected_reads` counts failed/invalid reads. `ddosctl status`
exposes the published and last observed gate generation without losing integer
precision. Normal polling introduces lag; alert on sustained stale/zero values,
not a momentary difference. Lease expiry still fails to observation by design.

Handshake accepts status nextState=1 and login nextState=2. Zero ports, invalid
UTF-8, empty/control-character base host, unsupported state and trailing bytes
are rejected. NUL-delimited host suffixes are preserved by default. Set
`allowed_hosts` and `allowed_ports` for a specific public service if appropriate.
`allow_host_suffix=false` is an explicit stricter compatibility policy.

Login Start built-in layouts:

| Protocol IDs | Layout |
| --- | --- |
| 4–758 | Name only (pre-1.19 layout) |
| 759 | Name, optional timestamp/key/signature |
| 760 | Same plus optional UUID |
| 761–763 | Name, optional UUID |
| 764–775 | Name, required UUID (verified through 26.1 layout) |

These ranges select a structural layout; they are not proof that every integer
is a released version. Newer/snapshot/custom versions require a `login_schemas`
mapping to `legacy`, `signed`, `signed_uuid`, `optional_uuid` or `uuid` after
checking the actual wire layout. No unchecked trailing-byte escape hatch exists.
Status permits protocol -1 discovery. Legacy pre-Netty `0xFE` status ping and
the separate transfer handshake nextState=3 are not implemented. A compatibility
audit must include the real client/proxy/mod mix. Protocol 776 and later requires
an explicit verified schema mapping; version metadata alone does not prove a
Login Start wire layout.

The gate validates public-key blob lengths, not signatures or player identity.
Backend online-mode/Velocity handles authentication and subsequent state.
After Login Start, all stream bytes are opaque, including encryption and plugin
negotiation. A syntactically valid client can still consume an admitted slot;
use measured login budgets and backend authentication timeouts.

The cache polls one configured host/version. Multi-host MOTDs or protocol-specific
status responses need separate gate instances/configurations. Cache TTL expiry
uses configured fallback JSON rather than unbounded stale data or client-triggered
refresh. The refresh timeout, response limit and JSON recursion bound apply.

## Metrics

Gate Prometheus: `http://127.0.0.1:9109/metrics`; fixed metric names and no client
IP labels. Counters include accepts, successful/invalid handshakes, status/login,
VarInt/size/schema/timeouts, slow/early closes, scope-limited rates, saturation,
backend errors, churn, cache refresh/fallback and relay errors. Gauges include
active sockets/prelogin/backend/admitted, identity table occupancy, mode and
observation. Prelogin sum/count in microseconds and an average in seconds are
exported. Percentiles require external probe/histogram instrumentation; averages
must not be used to claim unchanged jitter.

`new_ip_entries` and `new_prefix_entries` count new table insertions, **not exact
unique identities per second**. Use the bounded offline PCAP baseline tool for
per-second source/prefix counts, including spoofed SYN observations. See
[benchmark methodology](BENCHMARKS.md).

XDP textfile: `/run/xddp/xdp.prom`; configure a node_exporter textfile collector
directory or copy it through an operator-managed collector. `ddosctl stats`
returns raw machine-readable totals. `candidate_drop{reason=...}` records proposed
drops in both modes, while `drop_packets` counts actual enforcement. Reserved
`source_rate`, `prefix_rate` and `global_rate` reasons stay zero: those policies
are implemented at L7 and total PPS is observation, not blanket gameplay shaping.
Alarm on stale `xddp_controller_last_update_unix`, controller restart loops,
backend failures, sustained cap rejection and unexpected IPv6 deferral.
