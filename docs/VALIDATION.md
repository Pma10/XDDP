# Validation record

Execution evidence is kept distinct from design intent. A skipped kernel test on
Windows is not a successful kernel test. The implementation was built remotely
by the repository's GitHub Actions using the user's local Git authentication.

## Recorded runs

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

- Rust: bounded canonical VarInts, signed values, packet/schema validation,
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
