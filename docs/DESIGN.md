# XDDP design and threat model

## Environment facts

Compatibility target: Debian 12, Linux 6.1, libbpf 1.1, bpftool 7.1,
BTF/JIT and native XDP support. Detailed operator-supplied production facts
are kept in an ignored local environment document. The development workspace
is Windows; Linux verification is separately recorded.
No CPUMAP, AF_XDP, NIC, IRQ, offload, RPS or sysctl tuning is performed.
Verify that upstream scrubbing preserves original source addresses before
using source-based admission. Inventory listeners and firewall rules before
configuring unused-port drops. Tailscale, Docker, DHCP, routing and ICMP/PMTU
must remain functional. No fixed Ethernet MTU is assumed.

## Threat model

Upstream absorbs volumetric saturation. An attacker can spoof network packets,
rotate IPv4/IPv6 sources, share a CGNAT with players, finish TCP handshakes,
send arbitrary stream fragments, hold sockets, poll status and reconnect.
Protect host processing, bounded gate resources, Java connection creation,
and responsiveness of already admitted players. This cannot prevent saturation
of the uplink, RX queues or host before XDP; it is not player authentication,
a replacement for online-mode/Velocity forwarding, or proof against valid bots.
Local root, a compromised backend and a compromised upstream are outside scope.

## Packet flow

Internet -> upstream scrubber -> eth0 native XDP -> nftables/Linux TCP ->
Rust Tokio admission gate -> loopback/private Velocity -> Paper.

Only explicitly configured destination addresses belong to the XDP policy.
Unrelated addresses, ARP, ICMP, required UDP and unsupported L3 protocols pass
to the existing firewall. IPv6 mitigation is explicit; default IPv6 is pass.
The gate validates a complete framed handshake and complete Login Start before
opening any player backend socket. Status is answered from a bounded cache;
one background poll refreshes it. Admission does not mean authenticated login.
After admission all bytes, including compression/encryption, are relayed without
inspection using bounded buffers and TCP_NODELAY. Added proxy hops can affect
latency: equivalence must be measured, never presumed.

## XDP decision path

Count -> bounded Ethernet/VLAN/IP parsing -> owned destination -> protocol and
port selection -> header sanity -> prefix ACL -> SYN-only aggregate budget ->
PASS. Explicit unused UDP/TCP port drops do not allocate source state.
ACK, PSH, FIN, RST and established small payloads have no PPS/size heuristic.
No XDP connection tracking, dynamic source insertion, ring buffer or per-packet
userspace notification exists. Random-source packets cannot churn an LRU.
IPv6 extension headers are deliberately delegated to the kernel; fragment
drops are opt-in and limited to TCP fragments for owned destinations.

Budget counters live in per-CPU arrays. SYN rates are configured per processing
CPU, not represented as exact global limits. Multiply by the number of active
RX CPUs to estimate the effective budget; affinity changes can increase it.
The gate has exact process-wide admission buckets. Aggregate PPS/BPS anomalies
drive mode selection but never impose a blind established-traffic PPS ceiling.

Observe mode counts candidate drops while passing packets. A monotonic lease
expires to pass if the controller stops. Manual ACLs also expire with this
lease. NORMAL/ELEVATED/ATTACK/EMERGENCY only change new-admission policy.
Allow prefixes bypass SYN shaping and deny prefixes, never structural checks
or explicit closed ports. Source CIDRs are empty by default; no risky bogon
list is shipped. Kernel SYN cookies remain the SYN-cookie mechanism. Raw XDP
SYN proxy is deliberately not enabled: correct TCP option negotiation and
kernel SYNPROXY integration need a separately benchmarked rollout.

## L7 design

Tokio is selected for mature bounded asynchronous I/O and maintainability.
No unmeasured claim is made that Tokio beats mio, io_uring or C. One pre-login
task per bounded client; exact reads prevent loss of coalesced stream data.
Frames validate VarInts/lengths before allocation. Absolute phase deadlines and
per-read progress deadlines prevent byte drips from extending a phase forever.
Login Start schemas cover legacy, 1.19 signed-key, optional UUID and required
UUID layouts. Unknown login versions require explicit schema configuration.
Host suffixes (including NUL mod markers) are preserved by default; this does
not authorize client-supplied Bungee forwarding identity.

Sharded bounded IP/prefix tables are populated only after a real TCP accept.
An entry with active clients is never evicted. Idle entries expire by bounded
maintenance. Full tables reject new identities and count saturation; memory
cannot grow with source rotation. IP and prefix concurrency, connection,
handshake, status, login and global admission controls are separate. A decaying
early-close score adds a short penalty only when configured; no permanent bans.
Observe mode bypasses rate/score enforcement but retains protocol, memory, FD,
deadline and concurrency safety caps. Cache keys use a configured canonical
virtual host, and only configured host names may use that single cache when a
multi-host service requires isolation.

The gate connects with the real client IP encoded in optional PROXY v2. This
requires a trusted-only Velocity listener with PROXY support enabled. The gate
does not inject insecure Bungee forwarding data or implement transparent TCP.
Without PROXY v2 the backend sees the gate address, which must be accepted
explicitly before production rollout. Never expose the backend publicly.

## Measurement and rollout

Rate defaults are disabled: MEASUREMENT REQUIRED. Resource caps are engineering
safety bounds, not inferred player capacity. Gather PPS/BPS/SYN, accepts,
handshakes/status/logins, identity estimates, churn, pre-login concurrency and
legitimate join bursts before setting rates or adaptive thresholds. Distinct
source estimates at L7 exclude spoofed SYN sources and are labelled accordingly.
Mode transitions require consecutive samples and cooldown; missing metrics
cannot escalate. Gate mode files expire to NORMAL/observation on controller
failure. Existing relays do not consult mode or rate tables.

Deploy XDP observation first without moving Java. Validate pass behavior and
lease failure. Test a staging gate and backend, measure the A/B/C/D matrix,
then explicitly migrate the public listener during a maintenance window.
This repository never moves production listeners, changes nftables, or connects
to the production server automatically.
