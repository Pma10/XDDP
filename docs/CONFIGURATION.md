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
signal crossing `enter` selects the corresponding severity unless that mode has
an `adaptive.required_signals` list: every listed signal must also be present and
at/above its own enter threshold. Names must refer to thresholds configured for
that mode. This permits traffic plus resource-pressure corroboration, rather than
using raw interface PPS alone. Missing required signals prevent escalation.
`adaptive.allow_emergency` defaults to **false**, including when omitted from old
configurations: automatic escalation stops at ATTACK unless explicitly enabled.
Manual EMERGENCY remains available. Escalation requires
consecutive samples and cooldown. De-escalation requires every signal configured
for the current mode to be present and below `exit`, consecutive samples and
cooldown, then decreases one mode. Missing telemetry cannot itself escalate or
justify recovery. Empty bands never trigger a mode. Samples reset after counter
restart; negative deltas are discarded.

Additional pressure signals are `active_status`, `backend_connections`,
`backend_failures_per_second`, `resource_limited_per_second`, and
`conntrack_percent`. The latter reads count/max from procfs with bounded reads;
if conntrack is unavailable/invalid the signal is absent, not zero. It does not
change conntrack/sysctl/firewall configuration. A backend outage alone is not
proof of an attacker; prefer the backend circuit below before broad denial.

For example, a mode with thresholds for `pps` and `active_prelogin` can use
`"required_signals": {"attack": ["pps", "active_prelogin"]}` to require both.
An empty map retains any-signal behavior for non-emergency modes. No new
production thresholds are provided.

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

`status_ip` optionally caps status handshakes from one source IP. It is zero by
default and cannot exceed the effective status capacity. A source rejection is
closed immediately and does not consume the global status bucket. With
`separate_status_budget=true`, the status handshake is charged once before the
request body, so withholding that body cannot bypass the status limit. The
sample enables this separation.

`preserve_burst=true` keeps the configured burst size during an elevated mode
while still scaling refill speed. This preserves a short legitimate shared-NAT
join burst after escalation without relaxing the sustained rate. It has no
effect while all rate buckets are disabled.

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

`protocol.min_protocol` and `protocol.max_protocol` are inclusive Login
protocol-ID bounds. The sample defaults to `757` through `776`, covering Java
1.18 through 26.2. Set the maximum to a measured ceiling when the backend must
reject versions above it, or raise it deliberately for a newer release; IDs
outside the range close before backend dialing. Status discovery is separate
and still permits protocol `-1`.

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

## Relay progress and backend outage protection

`timeouts.relay_stall_ms` and `timeouts.half_close_ms` are optional, default 0
(disabled), and bounded at 3,600,000 ms. Nonzero values are hard per-connection
resource deadlines, independent of controller observation, modes and allow lists.

- `relay_stall_ms` starts only when a write/flush/shutdown is pending, separately
  for each direction. A successful operation clears the timer. Healthy idle
  connections do not start timers. Kernel-buffered data may delay detection of a
  peer that stops reading; this is application write progress, not proof of TCP
  acknowledgments or a TCP_USER_TIMEOUT implementation. A peer that continues to
  make small write progress can evade a no-progress timeout.
- `half_close_ms` limits the remaining lifetime after the relay observes either
  read EOF. Reverse data remains allowed during this absolute drain window and
  cannot extend it. It can truncate a legitimate unusually long half-close reply,
  so size from real traffic. Enable the stall guard too for blocked buffered writes
  that prevent the relay reaching EOF.
- `relay_stall_timeouts` and `half_close_timeouts` count closes; neither generates
  an IP/prefix penalty. Normal FIN/half-close handling is preserved within the window.

Optional `backend_protection` has `max_connecting`, `failure_threshold`,
`cooldown_ms` and an `attempts` rate/burst, all default 0. `max_connecting` bounds player backend connect plus
initial writes (not established relays); zero uses the existing backend slot cap.
`failure_threshold` consecutive connect/initial-write failures open a circuit for
`cooldown_ms`, after which exactly one player attempt probes recovery. A success
resets it; a failure waits again. Completions from an older failure wave cannot
clear the circuit. Cancelled unfinished attempts count as failures and release slots.
Threshold and cooldown must both be zero or positive, at most 10,000 and 120,000 ms.
When `attempts` is enabled, it limits all player backend dial attempts after
admission, including successful connect/close loops. Size its burst for shared-NAT
reconnects; it is gate-wide rather than per IP.

This is an opt-in hard resource policy, including during observation. Rejected
attempts close without queuing, backend dials or churn penalties. Status polling
keeps its one independently bounded task, so the cache can recover during a player
outage. Existing relays continue. Metrics are `backend_protection_rejected` and
`backend_circuit_opened`. Backend/BotSentry closes **after** successful initial
writes do not trip the circuit: use existing global login rate/burst and backend
authentication timeouts to bound syntactically valid connect/close loops.

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
| 764–776 | Name, required UUID (verified through 26.2 layout) |

These ranges select a structural layout; they are not proof that every integer
is a released version. Exact newer/snapshot/custom versions can use a
`login_schemas` mapping to `legacy`, `signed`, `signed_uuid`, `optional_uuid`,
`uuid` or `backend` after checking the actual wire layout. Status permits protocol -1
discovery. Legacy pre-Netty `0xFE` status ping and the separate transfer
handshake nextState=3 are not implemented. A compatibility audit must include
the real client/proxy/mod mix.

For protocol IDs 777 and later, `protocol.future_login_schema` defaults to
`uuid`, which covers current ViaVersion-compatible Login Start frames. Set it to
`backend` when the backend proxy owns future protocol decoding: XDDP validates
the frame, packet id, size and phase deadline, then relays the opaque Login Start
payload. Set it to `disabled` to retain strict rejection. Exact
`login_schemas` entries override this fallback. `backend` is bounded
compatibility, not unchecked TCP pass-through.

The gate validates public-key blob lengths, not signatures or player identity.
Backend online-mode/Velocity handles authentication and subsequent state.
After Login Start, all stream bytes are opaque, including encryption and plugin
negotiation. A syntactically valid client can still consume an admitted slot;
use measured login budgets and backend authentication timeouts.

The cache polls one configured virtual host/port/version. `cache.host` and
`cache.port` are the hostname and public port sent inside the backend status
handshake; they should match the address players use when a proxy selects MOTDs
by host/port. They are not the gate's backend socket address/port (`backend`).
For a public gate on `:25565` forwarding to a Java/Velocity listener on
`:25566`, `cache.port` normally remains `25565`. `cache.protocol` is the
canonical client protocol used for that one poll. For ViaVersion or
MiniMessage/component MOTDs,
use the current modern protocol used by the public server (for example `774`
for a 1.21.11 endpoint), rather than the legacy `47` protocol. A legacy poll
can make the proxy serialize a reduced 1.8-compatible description before XDDP
ever sees it, and no response-side rewrite can restore those lost components.

Cached status JSON is bounded and, when it contains a `version.protocol` field,
the gate rewrites that field to the requesting status handshake protocol. This
keeps ViaVersion-compatible clients from seeing a false red-X protocol mismatch
while sharing one canonical MOTD/player cache. Protocol -1 discovery preserves
the backend value. Multi-host MOTDs or status responses whose compatibility
depends on more than the protocol field need separate gate instances/configurations.
Cache TTL expiry uses configured fallback JSON rather than unbounded stale data or
client-triggered refresh. The refresh timeout, response limit and JSON recursion
bound apply.

JSON serialization is now performed on refresh. The cache stores a canonical
wire response and a prepared prefix/suffix; each client response only inserts
the decimal protocol number and copies bounded bytes. Client-controlled protocol
numbers cannot create cache entries or trigger backend polls. RGB components,
custom fields and favicon are preserved as JSON values. The maximum response
limit reserves space for any nonnegative i32 protocol before publishing a refresh.

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
