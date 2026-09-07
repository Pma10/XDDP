# Defensive review

This is a source-and-test-backed engineering review, not independent penetration
testing or a production capacity certification. Verify execution status in
[VALIDATION](VALIDATION.md); production benchmarks and target-driver rollout are
separate acceptance gates.

## Attack/work assessment

| Threat | Implemented defense | Residual/compatibility boundary |
| --- | --- | --- |
| Spoofed random-source floods | No dynamic XDP inserts; stateless parsing, explicit closed-port policy, per-CPU SYN bucket | RX/uplink saturation remains upstream responsibility |
| LRU/map exhaustion | No XDP LRU; administrative tries capped; L7 sharded table caps after TCP acceptance | Active/full shards can deny new identities until capacity recovers |
| IPv4/IPv6 rotation | Prefix and exact global L7 event buckets, hard resource bounds | Large distributed valid botnets need backend/upstream controls |
| SYN flood | Configured per-CPU SYN budget, kernel SYN cookies remain available | No exact cross-CPU SYN cap or XDP SYN proxy; budgets need RX-path measurements |
| ACK/RST/high PPS | Structural validation; existing kernel TCP state remains authoritative | No unsafe blanket ACK/RST shaping; spoofed valid headers can reach Linux |
| Fragments | Opt-in IPv4 TCP fragment drop for owned destinations | Applies to all fragmented TCP on that address, including non-game TCP; default pass; IPv6 fragments deferred |
| Malformed headers | Bounded Ethernet/two-VLAN/IP/TCP/UDP parsing, correct IP-declared bounds | IP/TCP checksums and TCP option semantics delegated to Linux |
| Tiny packets/repeated size/PSH | Never used as independent drop criteria | Valid-looking tiny traffic still costs kernel processing |
| TCP option abuse | Header extent/data-offset validation before kernel | No hand-written TCP option negotiation or stream state in XDP |
| Connection churn | Decaying IP/prefix scores for incomplete admissions; independently enabled temporary penalties | Successful status, server rejection and all admitted relays exempt to avoid backend/BotSentry false positives |
| Slowloris | First-progress, read-progress and absolute per-phase deadlines | Valid Login Start reaches opaque relay; backend must time out incomplete authentication |
| FD exhaustion | Total/prelogin/admitted/backend semaphores, fixed metrics cap, explicit systemd FD ceiling | Kernel/system descriptors need headroom; caps cause intentional new-client refusal |
| Memory exhaustion | Validate frame length before allocation, bounded initial bytes/cache/table/task/relay count | Kernel socket autotuning and Java memory are additional; measure RSS/socket memory |
| Status floods | Separate IP/prefix/global status budget; one timer-driven cache poll | Cache is single-host/version; status clients occupy bounded prelogin slots until close/deadline |
| Login floods | Complete handshake/Login Start first; distinct scope/global login budget and backend cap | Syntactically valid logins are not authenticated players |
| Malformed Minecraft | Strict frame/VarInt/UTF-8/state/structure/trailing-byte checks | Signatures, auth, compression/encryption and later protocol belong to backend |
| Partial/overlong VarInt | Frame length <=3 bytes, fields <=5, bounded padded encodings accepted; overflow/nontermination rejected | Frame/schema/total-byte bounds still apply |
| Single large uploader | Optional connection-local upload byte budget; monitor before enforcement; excess connection closes | Disabled by default; no NIC PPS/receive-link protection, no aggregate bot classification |
| Huge declared lengths | Phase/schema bounds before heap allocation; total wire budget across phases; one wire buffer | Accepted bounded frames and kernel receive queues still consume memory |
| Backend exhaustion | No per-player backend before admission, finite connect/write deadline, backend semaphore | Existing admitted sockets can persist; backend auth/idle controls remain necessary |
| Log I/O DoS | Fixed counters, no per-packet/client rejection logs | Startup/fatal service failures still log and have restart backoff |
| Lock contention | Per-CPU XDP mutation, random sharded L7 mutexes only during admission/close | Hot legitimate NAT/prefix admissions can contend; benchmark before tuning |
| Arithmetic/endian bugs | Unsigned bounded fields, saturating elapsed handling, validated finite rates, explicit wire endian, static ABI sizes | Kernel counters eventually wrap; controller discards reset/negative deltas |
| Races | Single-writer control lock, atomic JSON rename, leased updates, expected-ID XDP replacement, RAII client cleanup | XDP/gate policy publication is not a cross-process transaction; short fail-open transitions are deliberate |
| Mode flapping | Enter/exit bands, consecutive samples, cooldown, one-step recovery | Badly calibrated bands can still overreact; start in observation |
| CGNAT false positives | Disabled source caps/rates by default, burst buckets, prefix/global scopes, temporary scores | Source limits cannot infer player count; measure peak shared-NAT joins |
| MTU/PMTU | No MTU constant in datapath, no packet rewrite, ICMP/ICMPv6 passed | Exact virtio driver behavior and real scrubbed PMTU path need target test |
| Tailscale/Docker/DHCP/routing | Owned-destination scoping; required UDP and other L3 protocols pass; no firewall/sysctl changes | Misconfigured broad owned CIDRs/closed ports/fragment policy can affect services |
| PvP latency/jitter | No gameplay inspection/rate locks after admission, TCP_NODELAY, bounded relay buffers | Extra TCP hop/copy/scheduling exists; unchanged latency is NOT established by unit tests |

## Review-driven corrections

- XDP per-CPU rate arithmetic rounds token time upward to avoid exceeding the
  configured rate through integer division at high rates.
- Short admitted-login closures no longer accrue churn because backend/BotSentry
  closes cannot identify client fault. Prefix penalties require separate opt-in.
- Gate runtime policy requires fresh changing generations and both wall/monotonic
  expiry; a stale file cannot indefinitely preserve EMERGENCY or manual blocks.
- Accepted resources are owned by RAII permits/tickets/gauges. Early return,
  parse error, connect failure, task abort and relay close release accounting.
- Source tables cannot evict active entries and do not allocate on rejected
  random spoofed packets. Capacity is enforced independently of observation.
- Backend stream writes preserve exact handshake/Login Start framing. Coalesced
  subsequent bytes stay in the TCP receive buffer and are copied exactly once.
- Configuration update failures leave the XDP lease expired and stop the
  controller instead of renewing partially applied policy.
- Expected-ID attach/detach refuses concurrent/unrelated program replacement;
  the emergency detach command is documented separately as an operator override.
- Handshake/status/login admission commits source, prefix and global tokens only
  after policy accepts. Rejected sources cannot exhaust wider event budgets, and
  allow-listed sources do not spend prefix tokens. The pre-state global connect
  guard remains an incoming-accept work bound.
- Pinned map access verifies geometry before passing C buffers to the kernel.
  Controller startup/attachment also checks that all map IDs belong to the pinned
  program, rejecting mixed generations before policy or attachment changes.
- Publication and lease failures stop further controller renewal; cleanup still
  attempts kernel expiry and socket removal if runtime publication fails.
- Status sessions can be capped within the prelogin pool so waiting status pings
  cannot occupy every login slot. This does not classify silent handshakes or
  protect the global accept budget from an overwhelming connection flood.
- Server-side admission rejection and backend failure before relay do not add
  source/prefix churn penalties. Resource accounting is still released normally.
- Initial frames use one allocation and phase/schema length bounds before body
  reads. Valid status/login flows need no artificial delay or challenge exchange.
- Incomplete source connection counts are separate from existing relays and are
  released on admission/close. A held initial handshake cannot consume unlimited
  source slots when the operator enables this cap.
- Serialized policy/config sizes are validated before state changes. Gate policy
  generations and rejected reads are observable, including explicit expiry.

## Explicit scope decisions

Linux SYN cookies remain enabled according to the operator's existing configuration;
the project does not change sysctls. Availability of raw BPF syncookie helpers
does not make a partial SYN proxy safe. TCP option negotiation, SYNPROXY integration,
retransmission and fallback would need their own implementation and benchmarks.

Unused UDP ports are dropped statelessly only after configuration. Required UDP
services are delegated to their existing firewall/service policy; no broad UDP
rate cap is invented. Similarly, unsupported L3 and IPv6 extension traffic is
passed rather than guessing that it is unwanted. A strict allow-list policy for
an entire host is outside this service-scoped default.

The gate is an admission proxy, not full Minecraft authentication or a transparent
TCP splice. It cannot preserve established relay sockets across a gate process
crash. Enforced EMERGENCY prefers backend survival and stops new clients. Resource
caps and initial buffering/extra copy impose measurable costs; no synthetic claim
replaces the required real PvP benchmark.

## Source references

The implementation uses stable libbpf/XDP interfaces and Tokio's TCP/relay APIs.
See [kernel BPF execution documentation](https://www.kernel.org/doc/html/latest/bpf/bpf_prog_run.html)
and [Tokio TcpStream](https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html).

Login Start schema distinctions were checked against the protocol library's
published data: [1.19](https://github.com/PrismarineJS/minecraft-data/blob/master/data/pc/1.19/protocol.json),
[1.19.2](https://github.com/PrismarineJS/minecraft-data/blob/master/data/pc/1.19.2/protocol.json)
and [1.20.2](https://github.com/PrismarineJS/minecraft-data/blob/master/data/pc/1.20.2/protocol.json).
The required-UUID layout was also checked against
[1.21.11](https://github.com/PrismarineJS/minecraft-data/blob/master/data/pc/1.21.11/protocol.json)
and [26.1](https://github.com/PrismarineJS/minecraft-data/blob/master/data/pc/26.1/protocol.json).
These are moving upstream references; the gate's finite schema ranges are explicit
and do not automatically accept future versions.

Velocity documents `haproxy-protocol` as the PROXY protocol receiver setting in
[its configuration reference](https://docs.papermc.io/velocity/configuration/).
Only a trusted private backend listener should accept those headers.
