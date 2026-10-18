#!/usr/bin/env python3
"""Evaluate a controller policy against recorded counters, without network replay."""
import argparse
import copy
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controller"))
from core import Adaptive, MODES, MAX_DOCUMENT_BYTES, rates, validate

COUNTERS = {"conntrack_entries", "conntrack_limit", "host_conntrack_drop_total",
            "host_listen_overflow_total", "host_listen_drop_total", "host_syncookies_sent_total",
            "syn_packets", "rx_packets", "rx_bytes"}


def read_json(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_DOCUMENT_BYTES + 1)
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ValueError("input exceeds 256 KiB")
    return json.loads(raw)


def replay(config, samples):
    cfg = validate(copy.deepcopy(config))
    if not isinstance(samples, list) or not samples:
        raise ValueError("samples must be a nonempty list")
    prepared = []
    for sample in samples:
        if not isinstance(sample, dict) or set(sample) != {"time", "counters"}:
            raise ValueError("sample requires only time and counters")
        time = sample["time"]
        if type(time) not in (int, float) or not math.isfinite(time) or time < 0:
            raise ValueError("invalid sample time")
        if prepared and time <= prepared[-1][0]:
            raise ValueError("sample times must strictly increase")
        current = sample["counters"]
        if (not isinstance(current, dict) or not set(current) <= COUNTERS
                or any(type(v) is not int or not 0 <= v <= (1 << 64)-1 for v in current.values())):
            raise ValueError("invalid/unknown counter")
        current = dict(current)
        if current.get("conntrack_limit", 0) > 0 and "conntrack_entries" in current:
            current["conntrack_percent"] = min(100, 100 * current["conntrack_entries"] / current["conntrack_limit"])
        prepared.append((time, current))
    adaptive = Adaptive(cfg["adaptive"], prepared[0][0])
    previous, last = {}, prepared[0][0]
    rows = []
    for time, current in prepared:
        signals = rates(previous, current, time - last)
        suggested = adaptive.sample(signals, time)
        mode = suggested if cfg["manual_mode"] == "auto" else MODES.index(cfg["manual_mode"])
        rows.append({"time":time, "mode":MODES[mode], "signals":signals,
                     "syn_per_cpu":dict(cfg["syn_per_cpu"][MODES[mode]])})
        previous, last = current, time
    return {"observe":cfg["observe"], "manual_mode":cfg["manual_mode"], "samples":len(rows),
            "first_attack_time":next((r["time"] for r in rows if r["mode"] in ("attack","emergency")), None),
            "limitations":["Uses recorded cadence without interpolating missing samples.",
                           "One-way policy evaluation; does not model mitigation changing subsequent traffic.",
                           "Cannot prove packet identity, attack capacity or avoided packet loss."],
            "trace":rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(ROOT / "config/controller-pressure.observe.json"))
    parser.add_argument("--input", required=True, help="JSON object containing a samples list")
    parser.add_argument("--output", help="write JSON result instead of stdout")
    args = parser.parse_args()
    try:
        document = read_json(args.input)
        if not isinstance(document, dict) or set(document) != {"samples"}:
            raise ValueError("input requires only samples")
        result = replay(read_json(args.config), document["samples"])
        text = json.dumps(result, indent=2, allow_nan=False) + "\n"
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            print(text, end="")
    except (OSError, ValueError, TypeError, OverflowError) as error:
        parser.exit(2, f"replay failed: {type(error).__name__}\n")


if __name__ == "__main__":
    main()
