# Deployment, upgrades and failure recovery

## Preconditions and build evidence

The implementation is buildable and has CI validation; production readiness
requires the exact target kernel/driver, client compatibility and load matrix.
Do not translate a successful CI run into a throughput or latency guarantee.
Detailed operator environment facts are intentionally kept out of public source
control. Follow the supplied environment constraints without changing IRQ/RPS,
coalescing, GRO, conntrack, sysctls, MTU or firewall as a side effect of deployment.

Build/test on Debian 12 with libbpf 1.1 as shown in the README. On the target,
run `make xdp`, then the unattached verifier/fixture test before any attach.
Tests use private bpffs generations and documentation-only addresses. Netns tests
belong on owned disposable infrastructure. Capture stderr verifier logs on failure.

Keep console/out-of-band access, the previous XDP generation and current Java
listener configuration available. Native XDP succeeded in the operator's prior
PASS test; the full program still requires its own verifier and integration test.

## Configure an observation-only XDP deployment

1. Inventory `ip -br addr show dev eth0`, `ss -lntup`, nftables rules, routing,
   Docker port publishing and required UDP services. Do not infer unused ports
   from a historical listener snapshot. Determine whether service packets at XDP
   carry pre-DNAT destination addresses/ports; configure that actual tuple.
2. Put only intended public origin destination /32s (or explicit IPv6 /128s) in
   `owned_prefixes`. Broad ranges can affect routed traffic. Keep unused-port
   drops, allow/block/bogon lists empty until verified. No automatic bogon lists
   are provided because private/overlay/upstream addresses may be legitimate.
3. Keep `observe=true`, `manual_mode="normal"`, zero SYN budgets. Adjust paths
   only within the dedicated `/sys/fs/bpf/xddp/GENERATION` namespace. Existing
   maps must have the current ABI; use a fresh generation after ABI changes.
4. Install built files with `sudo sh scripts/install.sh`. The installer never
   starts services, attaches XDP, changes firewall policy or migrates Java.
5. Start `xddp-controller`. It loads/verifies and pins maps/program, reconciles
   policy while enforcement is expired, and starts refreshing leases. It does
   **not** attach automatically, including after reboot.
6. Run `ddosctl xdp status`, then `ddosctl xdp attach` when no existing program
   is attached. The operation refuses to replace an unexpected attachment.
   Confirm `ip -details link show eth0` and `bpftool net` report driver mode.
7. Check current game sessions, ICMP and PMTU, Tailscale, Docker, DHCP and routing.
   Compare the same load against no-XDP and minimal XDP_PASS baselines.

Controller SIGTERM sets an expired lease; SIGKILL is handled by lease expiry.
To test crash fallback without systemd immediately restarting it, use a disposable
service configuration with restart disabled. Confirm candidate-drop packets pass
after expiry while existing TCP sessions remain up. Check both XDP and gate state.
Do not terminate the production gate merely to test XDP's failure behavior.

## Gate staging and player identity

Run the gate against an owned staging Velocity/backend first. Public examples
use documentation/loopback addresses and are not an operational cutover script.
The public client connects to the gate; the gate opens a separate TCP connection.
Ordinary forwarding therefore changes the TCP peer identity at the backend.

For a supported Velocity deployment:

- Bind its listener to loopback/private connectivity reachable only from the gate.
- Enable Velocity's HAProxy/PROXY protocol support on that trusted listener.
- Set gate `proxy_v2=true` and `allow_backend_identity_loss=false`.
- Verify the backend logs and player API see the original client IP across IPv4
  and any explicitly enabled IPv6 listeners. No arbitrary internet client may
  reach a PROXY-trusting listener or inject a PROXY header directly.
- Keep authenticated Velocity-to-Paper forwarding/online-mode correctly configured.
  Do not use client-supplied NUL host suffixes as Bungee identity/authentication.

If direct Paper or another backend lacks PROXY v2 support, it will see the gate
IP unless that backend provides a separately verified compatible mechanism.
Explicit identity loss can be used in staging, but may break bans, anti-bot rules,
IP permissions and NAT behavior in production. Do not blindly enable Bungee mode.

One gate instance has one listener, one backend and one canonical status cache.
Use another instance/config/metrics port for an additional independent listener.
Multiple instances have independent resource/rate limits: aggregate them when
budgeting Java capacity. A dual-stack deployment also needs explicit listener and
backend family planning; this implementation does not translate PROXY address
families or implement incoming upstream PROXY parsing.

The sample timeout/cap settings require testing with high-latency, modded and
large-NAT clients. Status cache host/version must match the backend's intended
virtual host. Test new protocol releases using explicit `login_schemas` only after
verifying Login Start structure. All later gameplay is forwarded unchanged.

## Measure, then enable

Collect a quiet baseline and legitimate peak/reconnect/join bursts over a
representative period. Include per-source/per-prefix distributions and bot/monitor
status polling. [Benchmarks](BENCHMARKS.md) defines the A/B/C/D matrix and unknowns.
Choose initial rates above legitimate bursts with operator-approved error and
latency budgets. Do not infer thresholds from cumulative ListenDrops snapshots.

Enable measured nonzero rates in configuration. Static gate configuration changes
require a controlled restart and disconnect existing gate sessions; runtime
mode/observe/prefix commands do not. Controller static configuration reload uses
a service restart and temporarily expires XDP enforcement while reconciling maps.
Do not enable automated severity thresholds until observation shows expected
transitions with hysteresis and missing-data behavior.

Perform the public listener migration during a maintenance window using the
operator's actual Java/Velocity service names. Java must release the chosen public
port before the gate can bind it. Never attempt to bind both to the same address
and port. Change the existing firewall only through its normal reviewed process:
preserve external game access and block direct public backend access.
Starting the gate itself does not change firewall rules. Verify `ss -lntp`,
external joins/status, real client IP and gameplay before leaving the window.

Only then use `ddosctl observe off`, initially in NORMAL. Mode and observe are
separate. Test elevated/attack policies with controlled traffic, keeping admitted
PvP flows running. Enforced EMERGENCY intentionally rejects every new accept.

## Safe replacement and rollback

Keep the old generation pinned. Stage a new generation by changing `pin_dir` to
a new directory and restarting the controller. The previous attachment becomes
pass-only when its old lease expires; staging is not automatic replacement.
Get the currently attached program ID using `ddosctl xdp status`, then:

```sh
sudo ddosctl xdp attach EXPECTED_CURRENT_ID
```

`EXPECTED_CURRENT_ID` is the actual numeric ID just read. The loader opens the old
program FD and performs a compare-and-replace attachment with XDP_FLAGS_REPLACE.
If the ID changes concurrently, replacement fails. A mismatched program is never
silently overwritten. The code and the policy use fresh maps per generation;
this is not an in-place ABI migration.

To roll back the program, restore the previous controller `pin_dir`/object config,
restart the controller to renew the old generation's policy lease, then use the
same expected-ID replacement command. For immediate removal:

```sh
sudo xddp-rollback
sudo ip link set dev eth0 xdpdrv off
```

The first command verifies that the current program ID matches the configured
generation before detaching. The second is the emergency operator override: it
detaches any native XDP program currently on eth0. Use `xdpgeneric off` only if
SKB mode was explicitly deployed. Kernel/nftables policy remains in effect.

XDP detach does not remove the gate, stop Java or move the public listener. If
the gate fails, systemd restarts it, but its existing TCP relays are lost. To
remove the gate, restore the original public listener configuration as a separate
maintenance operation. Stopping the gate allows its configured drain period;
after it expires remaining relays are aborted. This release has no transparent
socket handoff or seamless gate binary upgrade.

`uninstall.sh` is explicit and disruptive to remaining gate clients: migrate the
listener first. It detaches only its own XDP, stops/disables XDDP units and removes
installed binaries/units. It retains config, user, logs and pins for recovery.
Delete individual unreferenced pins only after confirming no attachment uses that
generation. Never recursively remove a shared bpffs tree.

## Failure matrix

| Failure | Result and operator action |
| --- | --- |
| Controller crash | Short lease expires to XDP PASS and gate NORMAL/observation; alert and restore |
| Controller map/config update fails | Enforcement expires; startup/command fails; inspect logs, no fallback attach |
| XDP verifier or native attach fails | No automatic mode switch; old attachment unchanged |
| Identity table/shard full | New identities rejected; bounded memory, active entries retained |
| Prelogin/backend/admitted/socket cap | New admission rejected; existing relay byte path unchanged |
| Cache/backend down | Cached status until TTL, then fallback; player connect fails within deadline |
| Gate crash | Relayed sessions close; restart and investigate; no transparent preservation claim |
| Metrics unavailable | No missing-data escalation/recovery inference; alert on stale telemetry |
| Valid bot admissions | Consume bounded relay/backend slots; tune measured admission budgets and backend authentication |
| Upstream/link saturation | Outside residual host protection; coordinate upstream capacity/mitigation |

Production deployment and production benchmarks are **NOT EXECUTED** by this task:
no target SSH/session, maintenance window or measured thresholds were supplied.
