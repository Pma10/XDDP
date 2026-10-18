# Deployment diagnostics and host-pressure alerts

An active controller or gate service does not establish that XDP is attached or
enforcing a configured destination policy. Check the running deployment explicitly:

```sh
sudo python3 scripts/deployment_check.py
sudo python3 scripts/deployment_check.py --require-enforcement
```

The script runs only `ddosctl config show`, `status` and `xdp status`. It does not
attach a program, change configuration or restart services. Exit 2 means a query
failed; strict mode exits 1 for warnings. Observation deployments intentionally
warn. A zero strict exit is not certification: confirm program ownership, actual
destination/port coverage, driver support, game compatibility and measured capacity
using [deployment gates](DEPLOYMENT.md). An attachment alone may be unrelated to
the configured pinned program. The script does not resolve that ownership check.

Checks identify no attachment, observation mode, no owned destinations, disabled
SYN shaping in the current mode, unavailable gate metrics and missing/expired gate
runtime policy. Disabled SYN shaping is a diagnostic, not a claim that other
structural/ACL checks or the gate's hard capacity limits are disabled.

For ongoing diagnostics without restarting the gate/controller, install the helper
and the supplied `xddp-deployment-check.service`/`.timer` (the main installer copies
them but does not enable them). The example unit assumes the Node Exporter collector
directory `/var/lib/prometheus/node-exporter`; adapt the unit and its `ReadWritePaths`
to the actual directory before enabling the timer:

```sh
sudo systemctl enable --now xddp-deployment-check.timer
```

The helper's explicit `--textfile PATH` option writes only a dedicated diagnostics
file via atomic replacement. It exports attachment, observe, owned-destination and
SYN-budget status every 30 seconds; query failures replace old success with
`xddp_deployment_check_success 0` rather than leaving reassuring stale values.
Its three controller reads are sequential snapshots, so transitions may temporarily
show mixed values. Alerts use a delay. The regular controller status metrics are
only available after updating/restarting that controller; this helper works with
older deployments and does not require that restart.

## Prometheus

`config/prometheus-alerts.rules.json` is JSON-formatted YAML accepted by Prometheus.
It contains host conntrack utilization/drop, TCP listen queue overflow, per-core
softirq pressure, missing/stale controller telemetry, attachment/check failure and
expected-enforcement diagnostics. These are host-wide
signals and do not identify an attack's destination port or source.

1. Add `xddp: enabled` to **only the Node Exporter scrape targets expected to
   publish XDDP controller textfile metrics**. Do not add this marker to the separate
   gate scrape job: it does not publish the controller textfile metric.
2. Configure the Node Exporter textfile collector so it reads `/run/xddp/xdp.prom`
   (or an operator-managed atomic copy in its existing collector directory). Confirm
   `xddp_controller_last_update_unix` appears in that target's `/metrics` response.
   Keep the directory/file readable across the controller's atomic replacements.
3. Scrape the gate's loopback `127.0.0.1:9109/metrics` through an existing approved
   local collector/proxy/tunnel path. That address means the **gate host's** loopback,
   not a remote Prometheus server's loopback. Keep the gate metrics listener private.
4. Add the installed rules file path under Prometheus `rule_files` and run
   `promtool check rules PATH` and `promtool check config PROMETHEUS_CONFIG` before
   the normal controlled reload. Confirm rules appear and evaluate successfully.
5. Configure Alertmanager routing or equivalent notifications. Evaluated rules alone
   do not deliver a notification. Confirm a test alert reaches its intended receiver.

Only add `xddp_enforcement: required` after explicitly approving an enforcing SYN
policy. Do not add it to observation/staging targets. Targets expected to run the
diagnostics timer also need normal target-down/series-absence alerts: the example
failure/staleness rule cannot detect removal of both diagnostic series forever.

Tune alert durations against scrape/evaluation intervals. The example 45-second
staleness threshold assumes roughly 15-second scrapes; longer intervals require
adjustment. Missing-series alerting also assumes the configured target and expected
marker remain present. Target removal, Node Exporter down and time skew need the
operator's normal infrastructure alerts.

These alerts do not activate mitigation. Do not raise conntrack limits or change
IRQ/RPS, MTU, sysctls or firewall as a side effect of adding monitoring. Validate
protection separately and preserve established game sessions during rollout.
