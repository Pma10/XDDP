# Validation record

Execution evidence is kept distinct from design intent. A skipped kernel test on
Windows is not a successful kernel test. The implementation was built remotely
by the repository's GitHub Actions using the user's local Git authentication.

## Recorded runs

- [Upload and false-positive hardening](https://github.com/Pma10/XDDP/actions/runs/34138498680)
  for commit `b768a19`: **PASS** in both jobs. Twenty-seven Rust tests, sixteen
  Python controller tests and ten privileged XDP tests passed. Both PROXY v2
  integration modes include padded VarInt compatibility. Three additional
  loopback scenarios exercise disabled, monitoring and enforced upload budgets:
  a large uploader, another same-IP healthy relay, pending-slot caps, slot release
  and reconnect. Unit coverage includes independent prefix penalties, backend
  close exemptions, half-close/unlimited download, byte-bucket refill, overflow
  validation, explicit runtime expiry and oversized policy rejection before mutation.
  Full-precision policy-generation metrics passed. Installer staging and reinstall
  preserved operator config contents/permissions; shell syntax and help passed.
  C ASan/UBSan and native veth PMTU/replacement/detach also passed. State layouts
  are identity key 17 bytes, entry 232 bytes, ticket 48 bytes.
  Full apt/rustup installation on an operator host and production attack/PvP
  capacity tests were not executed; staging does not exercise host package setup.
- [Status isolation and admission efficiency](https://github.com/Pma10/XDDP/actions/runs/34038734710)
  for commit `6b18ee9`: **PASS** in both jobs. Twenty Rust tests, fourteen
  Python controller tests and ten privileged XDP tests passed. Both PROXY v2
  integration modes verified that held status sessions at their cap leave room
  for a new same-IP login while an existing relay continues transferring bytes.
  Capacity rejection and backend connection failure did not add churn; impossible
  phase lengths were rejected without a body. Unit tests retained maximum signed
  schema blobs, Unicode names and custom mappings, exact split/coalesced framing,
  and backward-compatible configuration. C ASan/UBSan checks and native veth
  attach/PMTU/replacement/detach also passed. State layouts remain 17/224/64 bytes.
  These are bounded functional scenarios, not throughput, RSS or PvP measurements.
- [Admission and generation hardening](https://github.com/Pma10/XDDP/actions/runs/34037555184)
  for commit `28d428d`: **PASS** in both jobs. Sixteen Rust tests and fourteen
  Python controller tests passed on Debian; ten XDP tests passed in the privileged
  kernel job. New regressions cover shared-budget preservation, exempt clients,
  backward timestamps, failed publication/lease updates, independent cleanup,
  incompatible map geometry and same-layout pins from another program generation.
  Both PROXY v2 integration modes, C ASan/UBSan checks, native veth attachment,
  MTU 1400 ICMP, atomic replacement, stale-ID rejection and detach passed.
  Binary state sizes remain 17/224/64 bytes for identity key/value/ticket.
- [Final implementation validation](https://github.com/Pma10/XDDP/actions/runs/34028321516)
  for commit `7db2ef0`: **PASS** in both jobs. Debian used libbpf 1.1.2 and
  clang 14. Twelve Rust tests and nine Python controller tests passed; eight
  BPF tests were intentionally skipped in the unprivileged Debian container and
  then passed in the separate privileged kernel job. Both gate integration runs
  (`proxy_v2=false` and `proxy_v2=true`) passed, including original client port
  forwarding. Shell/Python syntax checks, C ASan/UBSan sweep, native veth attach,
  MTU 1400 ICMP, expected-ID replacement, stale-ID rejection and detach passed.
  Binary layout: identity key 17 bytes, value 224 bytes, connection ticket 64 bytes.
- [Complete passing build and network run](https://github.com/Pma10/XDDP/actions/runs/34028056432)
  for commit `6001650`: both Debian and kernel jobs passed, including eight XDP
  test cases, twelve Rust tests, nine Python controller tests, ASan/UBSan parser
  sweep, gate integration and native netns attach/replacement/detach with MTU 1400.
- [Initial Debian build and tests](https://github.com/Pma10/XDDP/actions/runs/34026874890):
  Debian 12/libbpf 1.1 compiled the XDP objects, loader and release Rust gate.
  Rust/Python/native ASan+UBSan tests and gate integration passed. The separate
  Ubuntu 22.04 job failed because its libbpf predates the required API; the job
  image was corrected, not the supported Debian floor.
- [Direct kernel fixture run](https://github.com/Pma10/XDDP/actions/runs/34027452043):
  Debian tests passed; XDP verifier/load and six kernel packet test cases passed
  through libbpf BPF_PROG_TEST_RUN. Netns attachment exposed that `ip netns exec`
  remounts `/sys` and hides host bpffs pins. The test was corrected to use
  network-only `nsenter`, keeping pin access in the original mount namespace.

## Test surfaces

- Rust: bounded VarInts including padded encodings, signed values, packet/schema validation,
  split/coalesced reads, progress/absolute deadlines, token refill/bursts,
  IPv4-mapped identity/prefix normalization, concurrency cleanup, table saturation,
  churn/status distinction, runtime expiry/allow precedence, PROXY v2 wire layout.
- Python: configuration validation, enter/exit hysteresis, cooldown, missing
  telemetry and counter-reset behavior; Linux controller persistence/map-failure
  behavior.
- C ASan/UBSan: header boundary fixtures and deterministic mutation/truncation
  sweep over the same header parser used by the BPF object.
- Kernel: real BPF verifier and fixture execution, malformed/normal IP/TCP,
  fragments, UDP/ICMP, small gameplay ACK/PSH, prefix ACL precedence, lease expiry,
  VLAN/options/IPv6 and SYN-budget exemption of established-style packets.
- Owned loopback gate integration: no backend before validation, opaque relay,
  half-close, cached status/ping without per-client backend polls, invalid lengths
  and state transitions, idle/partial timeout, prelogin capacity and reconnect
  cleanup.
  The PROXY v2 run also validates the on-wire header and original client port;
  it does not claim a real Velocity/Paper installation was exercised.
- Isolated netns/veth: native driver attach, MTU 1400 ICMP, expected-ID atomic
  replacement, rejection of stale IDs and clean detach.

## Not executed on production

- Exact operator Linux kernel/virtio eth0 verifier and full program attachment:
  **NOT EXECUTED**. Hosted-runner kernels differ from the target.
- Tailscale/Docker/DHCP/routed traffic and upstream real PMTU integration:
  **NOT EXECUTED** on the target.
- Real Velocity/Paper/client/mod compatibility, original IP reporting and online
  authentication: **NOT EXECUTED**; loopback fixtures exercise wire transport only.
- BASELINE/A/B/C/D throughput, normal PvP latency/jitter, hit/knockback response,
  Java CPU, high-concurrency RSS and allocations: **NOT EXECUTED**.
- Production deployment/listener migration and production rollback drill:
  **NOT EXECUTED**.

No successful production tests or benchmark figures are implied. Follow
[deployment](DEPLOYMENT.md) and [benchmark methodology](BENCHMARKS.md) to resolve
these environment-specific acceptance gates before enforcement.
## 2026-09-08 resilience changes: local verification

Rust 1.85.0 (`x86_64-pc-windows-gnu`) compiled the changed gate with the locked
dependencies. All 38 Rust unit tests passed, including stalled writes, healthy
idle, absolute half-close drain, circuit recovery/late completions, configuration
compatibility and prepared status JSON preservation. Controller policy tests:
10 passed; 10 Linux-only controller I/O tests skipped on Windows.

Loopback TCP integration passed: base gate with and without PROXY v2, status/login
fairness, upload disabled/monitor/enforce, and the new outage/backoff/recovery
scenario. The existing refused-connect fixture now waits for the configured
backend deadline rather than assuming an immediate OS refusal. Python compilation
and `git diff --check` passed. Setup and CI include the new resilience integration.

These are local functional results, not Linux deployment, NIC/kernel capacity,
real Minecraft/BotSentry compatibility or live-server attack tests. Linux CI and
production configuration activation remain separate. No new CI result is claimed.

### Minecraft scenario boundary audit

A further bounded loopback audit used an echo backend (no authentication or
BotSentry), four prelogin slots, two status slots, enabled relay/circuit guards,
and disabled rate buckets. It confirmed:

- Two classified status holders fill their cap; an extra status holder is rejected
  while a valid Login Start still reaches the backend.
- Four silent TCP peers fill the shared prelogin pool. A new connection is refused
  while an already admitted echo session remains usable. Deadlines reclaim all
  held slots and subsequent login succeeds. This is resource protection, not
  guaranteed admission fairness during sustained distributed replenishment.
- Valid Handshake + Login Start + arbitrary trailing bytes in one write forwards
  those trailing bytes to the backend, by the opaque-relay design. After admission,
  idle connections also survive a configured write-stall timeout. Backend protocol
  validation/authentication deadlines remain necessary.
- Ten sequential valid login/connect-close cycles all reach a healthy backend
  without opening the outage circuit. The circuit is not a login rate limiter.

Local audit evidence: `artifacts/minecraft-scenario-audit.json` (ignored local
artifact). These scenarios establish behavior boundaries, not an attack PPS/bps
capacity claim or validation of the deployed Linux configuration.
