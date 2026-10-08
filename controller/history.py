"""Bounded, minute-granularity historical telemetry. No packet or client-IP logs."""
import datetime as dt
import json
from pathlib import Path
import sqlite3
import time

DEFAULT_PATH = "/var/lib/xddp/history.sqlite3"
COUNTERS = ("rx_packets", "rx_bytes", "drop_packets", "syn_packets",
            "tcp_accepts", "handshake_invalid", "resource_limited",
            "rate_limited_ip", "rate_limited_prefix", "rate_limited_global",
            "backend_connect_failures", "status_requests")


class History:
    def __init__(self, path=DEFAULT_PATH, retention_days=30):
        self.path = Path(path) if path else None
        self.retention_days = retention_days
        self.last_minute = None
        self.last_prune_day = None

    def record(self, timestamp, mode, observe, counters, signals, gate_available):
        if self.path is None:
            return False
        minute = timestamp // 60 * 60
        if self.last_minute == minute:
            return False
        # A full disk must not cause a database attempt on every controller tick.
        self.last_minute = minute
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path, timeout=0.2) as db:
            db.execute("CREATE TABLE IF NOT EXISTS samples ("
                       "ts INTEGER PRIMARY KEY, mode TEXT NOT NULL, observe INTEGER NOT NULL, "
                       "gate_available INTEGER NOT NULL, counters TEXT NOT NULL, signals TEXT NOT NULL)")
            db.execute("INSERT OR REPLACE INTO samples VALUES (?, ?, ?, ?, ?, ?)",
                       (minute, mode, int(observe), int(gate_available),
                        json.dumps(counters, separators=(",", ":"), allow_nan=False),
                        json.dumps(signals, separators=(",", ":"), allow_nan=False)))
            day = minute // 86400
            if self.last_prune_day != day:
                db.execute("DELETE FROM samples WHERE ts < ?",
                           (minute - self.retention_days * 86400,))
                self.last_prune_day = day
            db.commit()
        return True


def _local_midnight(day):
    # mktime uses the server's configured local timezone (including DST).
    return int(time.mktime((day.year, day.month, day.day, 0, 0, 0, 0, 0, -1)))


def read_day(path, date_text, raw=False):
    """Read archives even when the controller socket is unavailable."""
    day = dt.date.fromisoformat(date_text)
    start = _local_midnight(day)
    end = _local_midnight(day + dt.timedelta(days=1))
    db_path = Path(path) if path else None
    if db_path is None or not db_path.is_file():
        raise FileNotFoundError("XDDP history archive missing; earlier traffic cannot be reconstructed")
    with sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True, timeout=0.2) as db:
        previous = db.execute("SELECT ts, counters FROM samples WHERE ts < ? ORDER BY ts DESC LIMIT 1",
                              (start,)).fetchone()
        rows = db.execute("SELECT ts, mode, observe, gate_available, counters, signals "
                          "FROM samples WHERE ts >= ? AND ts < ? ORDER BY ts", (start, end)).fetchall()
    hours = {}
    samples = []
    last_ts, last_counts = ((previous[0], json.loads(previous[1])) if previous else (None, {}))
    for ts, mode, observe, available, counts_json, signals_json in rows:
        counts = json.loads(counts_json)
        signals = json.loads(signals_json)
        hour = time.strftime("%Y-%m-%d %H:00", time.localtime(ts))
        entry = hours.setdefault(hour, {"hour": hour, "samples": 0, "deltas": {},
                                        "max_sampled_rates": {}, "modes": []})
        entry["samples"] += 1
        if mode not in entry["modes"]:
            entry["modes"].append(mode)
        # Do not attribute multiple minutes of missing telemetry to one minute.
        if last_ts is not None and 0 < ts - last_ts <= 90:
            for key in COUNTERS:
                a, b = last_counts.get(key), counts.get(key)
                if type(a) is int and type(b) is int and b >= a:
                    entry["deltas"][key] = entry["deltas"].get(key, 0) + b - a
        for key in ("pps", "bps", "syn_per_second", "accepts_per_second", "resource_limited_per_second"):
            value = signals.get(key)
            if isinstance(value, (float, int)) and not isinstance(value, bool):
                entry["max_sampled_rates"][key] = max(value, entry["max_sampled_rates"].get(key, 0))
        if raw:
            samples.append({"ts": ts, "mode": mode, "observe": bool(observe),
                            "gate_metrics_available": bool(available), "counters": counts, "signals": signals})
        last_ts, last_counts = ts, counts
    output = {"date": date_text, "timezone": time.tzname[time.daylight if time.daylight else 0],
              "samples": len(rows), "resolution_seconds": 60,
              "note": "Deltas omit gaps over 90 seconds and counter resets; sampled rates are not whole-minute peaks.",
              "hours": list(hours.values())}
    if raw:
        output["raw_samples"] = samples
    return output
