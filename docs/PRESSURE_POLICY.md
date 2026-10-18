# Resource-pressure strategy and recorded-counter replay

Host-wide conntrack saturation and TCP listen queue failures are actionable even
when packet capture and XDP SYN telemetry are unavailable. The controller can
respond to those measured failures without assuming that the attack is pure SYN
flood or identifying its destination port from aggregate metrics.

## Signals and response

The controller reads optional, bounded kernel telemetry:

- `conntrack_entries` and `conntrack_limit` from the existing netfilter sysctls.
- `host_conntrack_drop_total` summed across CPU rows of `/proc/net/stat/nf_conntrack`.
  The repeated `entries` field there is not summed. The format is defined by the
  [Linux 6.1 conntrack proc implementation](https://github.com/torvalds/linux/blob/v6.1/net/netfilter/nf_conntrack_standalone.c#L407-L438).
- `host_listen_overflow_total`, `host_listen_drop_total`, and
  `host_syncookies_sent_total` from named decimal fields in `/proc/net/netstat`.

The normal counter-to-rate calculation exports `conntrack_drops_per_second`,
`listen_overflows_per_second`, `listen_drops_per_second`, and
`syncookies_per_second`. Cookie activity is telemetry, not proof of attack identity.
Missing files, malformed values, resets and first observations are not fabricated
as zero load or an attack. Both proc files are bounded to 256 KiB independently;
failure in one source does not discard the other source.

When consecutive valid count/limit samples share the same table limit:

```
growth = max(0, current_entries - previous_entries) / elapsed_seconds
conntrack_projected_percent = min(100, 100 * (current_entries + 10 * growth) / limit)
```

This ten-second straight-line projection provides an early pressure signal. It is
not a forecast of attack identity or a capacity guarantee. A table-limit change or
missing count omits the projection. Decreasing occupancy produces zero growth.

`adaptive.immediate_signals` optionally names configured threshold signals whose
high condition immediately raises the corresponding mode, bypassing entry sample
debounce and entry cooldown. Required guards still apply. A disabled automatic
EMERGENCY remains disabled. Lowering the mode still uses the normal exit bands,
down-sample count and recovery cooldown. Without this explicit option, previous
debounce behavior is preserved.

## Observation profile

`config/controller-pressure.observe.json` is an opt-in **observation template**.
Default installation configuration is unchanged. The template has no owned
destination, so it must not be mistaken for an operational deployment.

| Mode | Entry conditions (any listed condition) | SYN rate / burst per CPU |
| --- | --- | --- |
| ELEVATED | occupancy or ten-second projected occupancy >= 60% | 512 / 1024 |
| ATTACK | occupancy >= 80%, projection >= 85%, conntrack drops >= 1/s, or listen overflow >= 1/s | 128 / 512 |

NORMAL uses 1024/2048. The two failure-rate conditions are immediate; occupancy and
projection retain the three-sample debounce. Recovery remains conservative with
separate lower exit thresholds and 60 seconds of cooldown. Automatic EMERGENCY is
off. SYN telemetry is deliberately not a required guard for these host-pressure
conditions. A missing rate cannot trigger its immediate condition.

These are staging candidates. SYN budgets are **per CPU**, not a global ceiling;
CPU/RX distribution affects aggregate admissions. A test fixture verifies that
120 initial SYNs fit the example burst and that existing ACK/PSH/FIN/RST paths pass
under SYN exhaustion. It does not certify 120 real clients, latency, or reconnect
patterns. Measure legitimate peak/reconnect bursts and proposed drops before
enforcement. Keep existing relays untouched during rollout.

The actions remain scoped to configured owned destinations and protected TCP
ports. Host-wide queue failures may be caused by a different listener. Reducing
new SYN admission is resource protection, not a claim that SYN filtering discards
valid ACK floods, established malicious traffic, or packets aimed at other ports.
Collect a bounded header capture or per-listener data for the next attribution
step; do not install source-IP deny rules based only on aggregate counters.

## Offline replay

```sh
python3 scripts/replay_pressure.py --config config/controller-pressure.observe.json \
  --input /path/to/private-counters.json --output /path/to/private-result.json
```

Input is a JSON object with one `samples` list. Each sample has an increasing
numeric `time` (seconds) and a `counters` object. For example, synthetic data:

```json
{"samples":[
  {"time":0,"counters":{"conntrack_entries":10,"conntrack_limit":1000,"host_listen_overflow_total":0}},
  {"time":15,"counters":{"conntrack_entries":400,"conntrack_limit":1000,"host_listen_overflow_total":100}}
]}
```

The tool uses the same rate, validation and mode selection code as the controller.
It respects manual mode, guards, input cadence and missing samples, and does not
interpolate one-second measurements into a sparse trace. It never sends packets
or modifies operating services. Its output is a one-way policy evaluation: it
cannot show how filtering would have changed later traffic, prove an outage would
have been prevented, or identify attack packets. Keep raw operator traces and
environment-specific settings outside source control.

Apply only through the [deployment procedure](DEPLOYMENT.md). Updating the Python
controller/config needs its controlled restart; updating gate static budgets is
a separate operation that disconnects its existing relays. Do not restart the gate
to install this controller-only strategy.
