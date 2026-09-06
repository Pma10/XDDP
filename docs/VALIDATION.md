# Validation record

Execution evidence is kept distinct from design intent. A skipped kernel test on
Windows is not a successful kernel test. The implementation was built remotely
by the repository's GitHub Actions using the user's local Git authentication.

## Recorded runs

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
