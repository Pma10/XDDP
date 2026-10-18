# XDDP

Residual DDoS mitigation for an upstream-scrubbed Minecraft Java server:
native XDP on eth0, a bounded Rust admission gate, and a leased adaptive controller.

**An observation-first release candidate, not a claim of production latency or
attack-capacity certification.** Read [validation evidence](docs/VALIDATION.md)
and [deployment gates](docs/DEPLOYMENT.md) before enabling enforcement.
Production thresholds and PvP latency/jitter budgets are **MEASUREMENT REQUIRED**.

## Behavior

- In leased, enforced EMERGENCY, XDP freezes new SYNs only for explicitly owned
  protected TCP services (including allowlisted sources), while leaving existing
  ACK/PSH/FIN and SYN-ACK packets untouched. The emergency reason is separately
  counted; observation and controller lease expiry still fail open.
- XDP validates Ethernet/VLAN/IP/TCP bounds, explicit service ports and prefix
  policy, and optionally shapes SYNs per processing CPU. No source-state
  insertion, connection tracking, CPUMAP, AF_XDP or Minecraft parsing in XDP.
- ICMP/PMTU, unowned destinations and unconfigured services pass to Linux and
  the existing firewall. Unused-port lists and source ACLs start empty.
- Gameplay ACK/PSH, small packets and bursts are never rejected by size or
  established-traffic PPS heuristics. Controller failure expires XDP to PASS.
- Rust/Tokio validates framed Handshake and Login Start before creating a
  player backend connection. Absolute/progress deadlines and hard capacity
  caps apply even in observation mode. After admission, bounded bidirectional
  copying relays opaque traffic with TCP_NODELAY and half-close propagation.
- A single background status poll feeds a TTL cache. Status floods cannot
  directly trigger backend polls. Cache failure returns configured fallback JSON.
- Bounded sharded IP/prefix state, distinct event token buckets, temporary
  churn penalties, global admission controls and four adaptive modes are included.
- Prometheus, systemd units, controlled attach/replacement/detach, rollback,
  Linux tests and read-only benchmark collection are included.
- Optional per-source incomplete-connection caps and a per-connection upload
  budget cover held handshakes and sustained uploads. Upload monitoring precedes
  explicit enforcement; all new budgets default disabled. See
  [configuration and scope](docs/CONFIGURATION.md).

## Build (Debian 12)

### 간편 설치

Debian 12/13 또는 Ubuntu 24.04 systemd 서버에서는 다음 한 명령으로 의존성 설치,
빌드, 테스트와 파일 설치를 수행할 수 있습니다. 기존 설정은 보존되며 서비스나
XDP는 자동으로 시작되지 않습니다. 상세 순서는 [간편 설치 안내](docs/QUICKSTART.ko.md)를
참조하십시오.

```sh
git clone https://github.com/Pma10/XDDP.git
cd XDDP
sudo sh scripts/setup.sh
```

Install Rust >=1.85 with Cargo through your approved toolchain process, then:

```sh
sudo apt-get update
sudo apt-get install clang llvm gcc make libbpf-dev libelf-dev zlib1g-dev python3 iproute2 iputils-ping bpftool
make all
make test
python3 tests/gate_integration.py --binary gate/target/release/xddp-gate
sudo env XDDP_BPF_TEST=1 python3 -m unittest discover -s tests -p test_xdp.py -v
sudo sh scripts/netns_test.sh
```

`Cargo.lock` is committed; builds use `--locked`. XDP is built with BPF ISA v2,
libbpf map BTF and stable packet wire layouts. No kernel structure offsets are
used, so a generated `vmlinux.h` and CO-RE relocations are unnecessary here.
The XDP emergency SYN-freeze change uses ABI v2. Existing deployments must
migrate to a fresh pin generation such as `/sys/fs/bpf/xddp/v2`; installation
does not overwrite existing controller configurations or attach automatically.
The libbpf API floor is 1.1. Native XDP is primary; SKB mode requires explicit
configuration and is never silently selected.

## Staging defaults

`config/gate.json` binds **loopback only**, on 25565, and expects a test backend
on loopback 25566. It permits backend identity loss explicitly for that local
test setup. For a public deployment, configure a private Velocity listener
with PROXY v2 support and set `proxy_v2=true`,
`allow_backend_identity_loss=false`. This gate does not provide transparent TCP
or add Bungee forwarding fields. See [identity and compatibility](docs/DEPLOYMENT.md).

`config/controller.json` owns **no destination prefixes** initially. Supply
only origin service destination addresses/CIDRs, not broad routed/Docker ranges.
All rates start at zero (disabled); empty mode thresholds never auto-escalate.
Resource defaults are finite engineering bounds, not measured player capacity.

```sh
gate/target/release/xddp-gate config/gate.json --check
python3 controller/ddosctl.py --config config/controller.json --check
sudo mount -t bpf bpf /sys/fs/bpf  # only if bpffs is not already mounted
sudo sh scripts/install.sh       # installs files; does not start or attach
```

## Control

Start the controller only after editing installed configuration:

```sh
sudo systemctl start xddp-controller
sudo ddosctl status
sudo ddosctl stats
sudo ddosctl history 2026-10-06             # server-local day; offline SQLite archive
sudo ddosctl history 2026-10-06 raw         # one-minute snapshots
sudo ddosctl config show
sudo ddosctl xdp status
sudo ddosctl xdp attach                 # requires no existing attachment
sudo ddosctl mode normal
sudo ddosctl mode attack                # retains observe setting
sudo ddosctl mode auto
sudo ddosctl observe on
sudo ddosctl allow 192.0.2.0/24          # documentation-only example prefix
sudo ddosctl unallow 192.0.2.0/24
sudo ddosctl block 198.51.100.0/24
sudo ddosctl unblock 198.51.100.0/24
```

Manual mode/observe/ACL commands persist atomically in the controller config.
Allow and block ACLs take effect at both XDP and the gate. Allow does not bypass
structural checks, explicit closed ports, hard resource caps or global admission
budgets. Enforced EMERGENCY stops all new accepts; established relays continue.
`observe off` is the separate, explicit enforcement switch. Changing mode
alone does not disable observation.

XDP raw syncookie/SYN-proxy is intentionally not implemented: kernel SYN cookies
remain in use. IPv6 direct TCP/UDP policies are available when enabled, but
extension chains, jumbograms and IPv6 fragments are delegated to the kernel.
There is no promise to defeat valid authenticated bot traffic or residual
ACK floods with source-only heuristics. See [defensive review](docs/DEFENSIVE_REVIEW.md).

## XDP and Gate hardening

- **Scoped malformed-packet enforcement:** XDP enforces malformed IP and
  transport decisions only when the destination is confirmed within
  `owned_prefixes`; short Ethernet headers and unowned destinations pass.
  IPv6 rules are enforced only when explicitly enabled. This protects
  unrelated traffic on shared Docker/Tailscale/routed interfaces.
- **Status frame limits:** the cached Minecraft status response budget includes
  packet ID and both VarInt lengths, including 16KiB+ JSON responses.
- **CIDR lookup:** small allow/block ACLs retain linear lookups. Larger ACLs
  use prefix-length-indexed IPv4/IPv6 hash sets instead of scanning 4096+
  prefixes at every connection. Matching semantics and allow precedence are
  verified in Rust tests; production throughput is not yet benchmarked.
- **Admission fairness:** global connection-rate tokens are committed only
  after per-IP, prefix and capacity checks succeed, preventing a rejected
  abusive source from exhausting healthy players' shared connect budget.
  Newly rejected identities/prefixes are not retained in bounded maps.
- **Gate diagnostics:** `ddosctl stats` now includes `gate_counters`; the
  Gate separately exposes `runtime_missing_reads` (missing file) and
  `runtime_rejected_reads` (invalid/unreadable file). These are health
  signals, **not** proof of a DDoS attack.

## Historical telemetry and controller startup safety

The controller archives a **single aggregate sample per minute** in
`/var/lib/xddp/history.sqlite3` (30 days by default). It contains XDP and
gate counters, sampled rates, defense mode and observation state. There are
**no per-IP or per-packet logs**. `ddosctl history YYYY-MM-DD [raw]` reads the
SQLite file directly even if the controller socket is down. Dates use the
server's local timezone; a missing day/archive does **not** imply no attack.
History begins only after the updated controller starts; old 2026-10-06
traffic cannot be recovered from a new database.

On systemd hosts a dedicated `xddp-bpffs.service` prepares only the bpffs
directory. The controller uses `ProtectKernelTunables=no` (needed to write
BPF pins) while retaining `ProtectSystem=strict` and a narrow
`ReadWritePaths=/sys/fs/bpf/xddp` exception. Repeated startup failures are
limited to five attempts in 60 seconds rather than an infinite restart storm.
Check service drop-ins before upgrades: an old override granting write access
to all of `/sys/fs/bpf` should be reviewed and removed when no longer needed.

**Do not restart the gate on a live server merely to apply these changes.**
Existing relays remain in the gate process; upgrading installed binaries with
the repository installer requires an operator-planned maintenance window.

## Recovery

```sh
sudo xddp-rollback                      # verifies ownership before detach
sudo ip link set dev eth0 xdpdrv off    # emergency operator override
```

Controller loss expires enforcement within its configured lease. Gate failure
closes its TCP connections; restarting it cannot resurrect them. XDP rollback
does not move the public Java listener back. Maintain a tested separate listener
migration plan and console access.

## Documents and tools

- [Threat model, architecture and decision path](docs/DESIGN.md)
- [L3/L4/L7 공격 시나리오와 방어 전략](docs/ATTACK_SCENARIOS.ko.md)
- [SYN Flood / conntrack incident triage](docs/SYN_CONNTRACK_TRIAGE.ko.md)
- [송신 정체·백엔드 장애·자동 대응 보호 설정](docs/RESILIENCE.ko.md)
- [Map/state sizes and memory estimates](docs/MEMORY.md)
- [Configuration and metrics](docs/CONFIGURATION.md)
- [Deployment, upgrade and rollback](docs/DEPLOYMENT.md)
- [Deployment diagnostics and Prometheus alerts](docs/MONITORING.md)
- [Resource-pressure strategy and recorded-counter replay](docs/PRESSURE_POLICY.md)
- [Benchmark methodology](docs/BENCHMARKS.md)
- [Tests and execution evidence](docs/VALIDATION.md)
- [Final defensive review and known limits](docs/DEFENSIVE_REVIEW.md)

No production connection, port migration, firewall change or benchmark is
performed merely by building or installing this repository.
