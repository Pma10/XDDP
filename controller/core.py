"""Pure policy and validation. No network/filesystem side effects."""
import ipaddress
import json
import math
import urllib.parse
from pathlib import Path

MODES = ("normal", "elevated", "attack", "emergency")
MAX_DOCUMENT_BYTES = 262144


def bounded_json(value, indent=None):
    text = json.dumps(value, indent=indent) + "\n"
    if len(text.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise ValueError("serialized policy/config exceeds 256 KiB; reduce prefix lists")
    return text


def runtime_document(cfg, generation, expires_unix, mode):
    return bounded_json(dict(generation=generation, expires_unix=expires_unix,
        mode=mode, observe=cfg["observe"], allow=cfg["allow_prefixes"],
        block=sorted(set(cfg["block_prefixes"]) | set(cfg["bogon_prefixes"]))))
SIGNALS = {"pps", "bps", "syn_per_second", "accepts_per_second", "handshakes_per_second",
           "status_per_second", "logins_per_second", "churn_per_second", "active_prelogin",
           "new_ip_entries_per_second", "new_prefix_entries_per_second", "active_status",
           "backend_connections", "backend_failures_per_second", "resource_limited_per_second", "conntrack_percent",
           "conntrack_projected_percent", "conntrack_growth_per_second", "conntrack_drops_per_second",
           "listen_overflows_per_second", "listen_drops_per_second", "syncookies_per_second"}


def host_pressure(root=Path("/proc/sys/net/netfilter")):
    """Optional read-only pressure signal. Missing/invalid values are not zero load."""
    try:
        values=[]
        for name in ("nf_conntrack_count", "nf_conntrack_max"):
            with (root / name).open("rb") as stream:
                raw=stream.read(65)
            if len(raw)>64 or not raw.strip().isdigit():
                return {}
            values.append(int(raw))
        count, maximum=values
        if maximum<=0:
            return {}
        return {"conntrack_percent":min(100.0,100.0*count/maximum),
                "conntrack_entries":count, "conntrack_limit":maximum}
    except (OSError, ValueError, OverflowError):
        return {}


def _proc_lines(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_DOCUMENT_BYTES + 1)
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ValueError("proc telemetry too large")
    return raw.decode("ascii").splitlines()


def host_network_counters(root=Path("/proc/net")):
    """Bounded read-only kernel counters; unavailable telemetry stays absent."""
    result = {}
    try:
        lines = _proc_lines(root / "stat/nf_conntrack")
        header = lines[0].split()
        if len(header) != len(set(header)) or "drop" not in header or len(lines) < 2:
            raise ValueError("invalid conntrack header")
        index = header.index("drop")
        dropped = 0
        for line in lines[1:]:
            values = line.split()
            if len(values) != len(header):
                raise ValueError("invalid conntrack row")
            value = values[index]
            if not value or any(c not in "0123456789abcdefABCDEF" for c in value):
                raise ValueError("invalid conntrack counter")
            dropped += int(value, 16)
        result["host_conntrack_drop_total"] = dropped
    except (OSError, ValueError, UnicodeError, IndexError):
        pass
    try:
        lines = _proc_lines(root / "netstat")
        names = {"ListenOverflows":"host_listen_overflow_total",
                 "ListenDrops":"host_listen_drop_total", "SyncookiesSent":"host_syncookies_sent_total"}
        for i, line in enumerate(lines):
            header = line.split()
            if not header or header[0] != "TcpExt:":
                continue
            values = lines[i+1].split()
            if (len(header) != len(values) or values[0] != "TcpExt:"
                    or len(header) != len(set(header))):
                raise ValueError("invalid TcpExt rows")
            counters = {}
            for name, value in zip(header[1:], values[1:]):
                if name in names:
                    if not value.isascii() or not value.isdecimal():
                        raise ValueError("invalid TcpExt counter")
                    counters[names[name]] = int(value)
            result.update(counters)
            break
    except (OSError, ValueError, UnicodeError, IndexError):
        pass
    return result


def positive(value, name, minimum=1, maximum=1_000_000_000):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not minimum <= value <= maximum:
        raise ValueError(f"invalid {name}")


def validate(cfg):
    expected = {"interface", "xdp_mode", "pin_dir", "object", "loader", "socket", "runtime_file",
                "metrics_file", "gate_metrics", "observe", "manual_mode", "lease_seconds", "ipv6",
                "drop_tcp_fragments", "owned_prefixes", "protected_tcp_ports", "drop_tcp_ports",
                "drop_udp_ports", "allow_prefixes", "block_prefixes", "bogon_prefixes", "syn_per_cpu", "adaptive"}
    if set(cfg) != expected:
        raise ValueError(f"configuration keys differ: {set(cfg) ^ expected}")
    if cfg["interface"] != "eth0" or cfg["xdp_mode"] not in ("driver", "skb"):
        raise ValueError("production controller attaches only to eth0; mode must be explicit")
    if cfg["manual_mode"] not in (*MODES, "auto"):
        raise ValueError("invalid manual_mode")
    for name in ("observe", "ipv6", "drop_tcp_fragments"):
        if type(cfg[name]) is not bool:
            raise ValueError(f"{name} must be boolean")
    positive(cfg["lease_seconds"], "lease_seconds", 5, 15)
    if not isinstance(cfg["lease_seconds"], int):
        raise ValueError("lease_seconds must be integer")
    for name in ("pin_dir", "object", "loader", "socket", "runtime_file", "metrics_file"):
        value = cfg[name]
        if not isinstance(value, str) or not value.startswith("/") or "\0" in value or ".." in value.split("/"):
            raise ValueError(f"{name} must be absolute without parent traversal")
    if not cfg["pin_dir"].startswith("/sys/fs/bpf/xddp/"):
        raise ValueError("pin_dir must be an XDDP generation under /sys/fs/bpf/xddp/")
    url = urllib.parse.urlsplit(cfg["gate_metrics"])
    if url.scheme != "http" or url.hostname not in ("127.0.0.1", "::1") or url.path != "/metrics" or url.username or url.query or url.fragment:
        raise ValueError("gate_metrics must be an explicit loopback HTTP /metrics endpoint")
    for name in ("owned_prefixes", "allow_prefixes", "block_prefixes", "bogon_prefixes"):
        if not isinstance(cfg[name], list) or len(cfg[name]) > 4096:
            raise ValueError("prefix limit exceeded")
        cfg[name] = sorted({str(ipaddress.ip_network(n, strict=False)) for n in cfg[name]})
    if len(set(cfg["block_prefixes"]) | set(cfg["bogon_prefixes"])) > 4096:
        raise ValueError("shared deny map capacity exceeded")
    for name in ("protected_tcp_ports", "drop_tcp_ports", "drop_udp_ports"):
        if not isinstance(cfg[name], list) or len(cfg[name]) > 65535:
            raise ValueError("invalid ports")
        if any(type(p) is not int or not 1 <= p <= 65535 for p in cfg[name]):
            raise ValueError("ports must be integers 1..65535")
    if set(cfg["protected_tcp_ports"]) & set(cfg["drop_tcp_ports"]):
        raise ValueError("cannot protect and drop the same TCP port")
    if set(cfg["syn_per_cpu"]) != set(MODES):
        raise ValueError("all four SYN budget modes required")
    for bucket in cfg["syn_per_cpu"].values():
        if set(bucket) != {"rate", "burst"}:
            raise ValueError("invalid SYN budget keys")
        for key, maximum in (("rate", 1_000_000_000), ("burst", 1_000_000)):
            positive(bucket[key], key, 0, maximum)
            if type(bucket[key]) is not int:
                raise ValueError("SYN budgets must be integers")
        if (bucket["rate"] == 0) != (bucket["burst"] == 0):
            raise ValueError("SYN rate and burst must both be zero or positive")
    a = cfg["adaptive"]
    required = {"up_samples", "down_samples", "cooldown_seconds", "thresholds"}
    if not required <= set(a) or set(a) - required - {"required_signals", "immediate_signals", "allow_emergency", "up_cooldown_seconds"}:
        raise ValueError("invalid adaptive keys")
    if "up_cooldown_seconds" in a:
        positive(a["up_cooldown_seconds"], "up_cooldown_seconds", 0, 3600)
        if type(a["up_cooldown_seconds"]) is not int:
            raise ValueError("up_cooldown_seconds must be integer")
    if type(a.get("allow_emergency", False)) is not bool:
        raise ValueError("adaptive allow_emergency must be boolean")
    guards = a.get("required_signals", {})
    if not isinstance(guards, dict) or not set(guards) <= set(MODES[1:]):
        raise ValueError("invalid required signal modes")
    immediate = a.get("immediate_signals", {})
    if not isinstance(immediate, dict) or not set(immediate) <= set(MODES[1:]):
        raise ValueError("invalid immediate signal modes")
    for n in ("up_samples", "down_samples", "cooldown_seconds"):
        positive(a[n], n, 1, 3600)
        if type(a[n]) is not int:
            raise ValueError("adaptive intervals must be integer")
    if set(a["thresholds"]) != set(MODES[1:]):
        raise ValueError("all adaptive threshold modes required")
    for mode, thresholds in a["thresholds"].items():
        if not isinstance(thresholds, dict) or not set(thresholds) <= SIGNALS:
            raise ValueError(f"invalid signals for {mode}")
        for name, bands in thresholds.items():
            if set(bands) != {"enter", "exit"}:
                raise ValueError("each signal needs enter and exit")
            positive(bands["enter"], name)
            positive(bands["exit"], name, 0)
            if bands["exit"] >= bands["enter"]:
                raise ValueError("exit must be below enter")
        for options in (guards, immediate):
            names = options.get(mode, [])
            if (not isinstance(names, list) or any(not isinstance(n, str) for n in names)
                    or len(names) != len(set(names)) or not set(names) <= set(thresholds)):
                raise ValueError("required/immediate signals must be unique configured threshold names")
    # Check both writer formats before any map, persistent config or lease change.
    bounded_json(cfg, indent=2)
    runtime_document(cfg, (1 << 64)-1, (1 << 64)-1, 3)
    return cfg


class Adaptive:
    def __init__(self, cfg, now):
        self.cfg = cfg
        self.mode = 0
        self.changed = now
        self.up = self.down = 0
        self.target = 0

    def sample(self, signals, now):
        target = 0
        immediate_target = 0
        for i, mode in enumerate(MODES[1:], 1):
            if mode == "emergency" and not self.cfg.get("allow_emergency", False):
                continue
            bands = self.cfg["thresholds"][mode]
            high = {n for n, b in bands.items() if n in signals and math.isfinite(signals[n]) and signals[n] >= b["enter"]}
            guards = self.cfg.get("required_signals", {}).get(mode, [])
            if high and all(n in high for n in guards):
                target = i
                if any(n in high for n in self.cfg.get("immediate_signals", {}).get(mode, [])):
                    immediate_target = i
        if immediate_target > self.mode:
            # Explicit kernel-failure signals can bypass entry debounce/cooldown.
            # Required guards and emergency opt-in above still apply.
            self.mode, self.changed = immediate_target, now
            self.up = self.down = self.target = 0
            return self.mode
        if target > self.mode:
            self.up = self.up + 1 if self.target == target else 1
            self.target = target
            self.down = 0
            # Keep legacy timing unless explicitly configured. Recovery cooldown
            # must not force a busy host to wait before a stronger response.
            up_cooldown = self.cfg.get("up_cooldown_seconds", self.cfg["cooldown_seconds"])
            if self.up >= self.cfg["up_samples"] and now - self.changed >= up_cooldown:
                self.mode, self.changed, self.up = target, now, 0
        else:
            self.up = 0
            bands = self.cfg["thresholds"].get(MODES[self.mode], {})
            # All configured signals must be present and below exit; missing data holds.
            cool = bool(bands) and all(n in signals and math.isfinite(signals[n]) and signals[n] <= b["exit"] for n, b in bands.items())
            self.down = self.down + 1 if cool else 0
            if self.mode and self.down >= self.cfg["down_samples"] and now - self.changed >= self.cfg["cooldown_seconds"]:
                self.mode -= 1
                self.changed, self.down = now, 0
        return self.mode


def rates(previous, current, dt):
    if not previous or not math.isfinite(dt) or dt <= 0:
        return {}
    result = {}
    counter_names = {"rx_packets": "pps", "rx_bytes": "bps", "syn_packets": "syn_per_second",
                     "tcp_accepts": "accepts_per_second", "handshake_ok": "handshakes_per_second",
                     "status_requests": "status_per_second", "login_starts": "logins_per_second",
                     "churn": "churn_per_second", "new_ip_entries": "new_ip_entries_per_second",
                     "new_prefix_entries": "new_prefix_entries_per_second",
                     "backend_connect_failures": "backend_failures_per_second",
                     "resource_limited": "resource_limited_per_second",
                     "host_conntrack_drop_total":"conntrack_drops_per_second",
                     "host_listen_overflow_total":"listen_overflows_per_second",
                     "host_listen_drop_total":"listen_drops_per_second",
                     "host_syncookies_sent_total":"syncookies_per_second"}
    for counter, signal in counter_names.items():
        if counter in current and counter in previous and current[counter] >= previous[counter]:
            result[signal] = (current[counter] - previous[counter]) / dt * (8 if signal == "bps" else 1)
    for gauge in ("active_prelogin", "active_status", "backend_connections", "conntrack_percent"):
        if gauge in current:
            result[gauge] = current[gauge]
    count, old_count = current.get("conntrack_entries"), previous.get("conntrack_entries")
    maximum = current.get("conntrack_limit")
    if (type(count) is int and type(old_count) is int and type(maximum) is int and maximum > 0
            and min(count, old_count) >= 0 and previous.get("conntrack_limit") == maximum):
        growth = max(0.0, (count - old_count) / dt)
        result["conntrack_growth_per_second"] = growth
        # A short-horizon estimate, not a prediction of attack identity/capacity.
        result["conntrack_projected_percent"] = min(100.0, 100.0 * (count + 10 * growth) / maximum)
    return result
