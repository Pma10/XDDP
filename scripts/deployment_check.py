#!/usr/bin/env python3
"""Read-only deployment diagnostics; service activity alone is not protection."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def inspect(config, status, attachment):
    """Report observed prerequisites, without certifying mitigation capacity."""
    warnings = []
    program_id = attachment.get("program_id")
    attached = type(program_id) is int and program_id > 0
    if not attached:
        warnings.append("xdp_not_attached")
    observe = status.get("observe")
    if observe is not False:
        warnings.append("observation_or_unknown_mode")
    owned = config.get("owned_prefixes", [])
    if not owned:
        warnings.append("no_owned_destinations")
    mode = status.get("mode")
    budget = config.get("syn_per_cpu", {}).get(mode, {})
    if not budget.get("rate", 0):
        warnings.append("syn_shaping_disabled_in_current_mode")
    if status.get("gate_metrics_available") is not True:
        warnings.append("gate_metrics_unavailable")
    generation = status.get("gate_runtime_generation")
    gate_policy_valid = type(generation) is int and generation > 0
    if not gate_policy_valid:
        warnings.append("gate_runtime_policy_missing_or_expired")
    return {
        "xdp_attached": attached,
        "program_id": program_id,
        "observe": observe,
        "mode": mode,
        "owned_destination_count": len(owned),
        "syn_rate_per_cpu": budget.get("rate", 0),
        "gate_metrics_available": status.get("gate_metrics_available") is True,
        "gate_policy_valid": gate_policy_valid,
        "warnings": warnings,
        "note": "Attachment ownership, traffic coverage, game compatibility and capacity still require verification.",
    }


def query(binary, arguments):
    result = subprocess.run([binary, *arguments], check=True, capture_output=True,
                            text=True, timeout=12)
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value


def write_textfile(path, report):
    """Atomically replace only this check's file, including on query failure."""
    metrics = {"check_success": int("error" not in report),
               "last_check_unix": int(time.time())}
    if "error" not in report:
        metrics.update(xdp_attached=int(report["xdp_attached"]),
                       observe=int(report["observe"]) if type(report["observe"]) is bool else -1,
                       owned_destination_count=report["owned_destination_count"],
                       syn_rate_per_cpu=report["syn_rate_per_cpu"],
                       gate_metrics_available=int(report["gate_metrics_available"]),
                       gate_policy_valid=int(report["gate_policy_valid"]))
    # Fixed names and integer values only; never render configuration text as labels.
    if any(type(value) is not int for value in metrics.values()):
        raise ValueError("invalid metric value")
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="ascii", dir=path.parent,
                                         prefix=".xddp-check-", delete=False) as stream:
            temporary = stream.name
            for name, value in metrics.items():
                stream.write(f"# TYPE xddp_deployment_{name} gauge\n")
                stream.write(f"xddp_deployment_{name} {value}\n")
            stream.flush()
            os.fchmod(stream.fileno(), 0o644) if hasattr(os, "fchmod") else None
        os.replace(temporary, path)
    finally:
        if temporary and Path(temporary).exists():
            Path(temporary).unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ddosctl", default="/usr/local/sbin/ddosctl")
    parser.add_argument("--require-enforcement", action="store_true",
                        help="exit 1 for any warning (observation deployments intentionally warn)")
    parser.add_argument("--textfile", help="atomically export diagnostics to this dedicated Node Exporter .prom file")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    try:
        config = query(args.ddosctl, ["config", "show"])
        status = query(args.ddosctl, ["status"])
        attachment = query(args.ddosctl, ["xdp", "status"])
        report = inspect(config, status, attachment)
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, AttributeError) as error:
        # Do not print arbitrary subprocess output or whole configuration files.
        report = {"error": "deployment_query_failed", "type": type(error).__name__}
    if args.textfile:
        try:
            write_textfile(args.textfile, report)
        except (OSError, ValueError, TypeError) as error:
            if not args.quiet:
                print(json.dumps({"error":"textfile_write_failed", "type":type(error).__name__}))
            return 2
    if not args.quiet:
        print(json.dumps(report, indent=2))
    if "error" in report:
        return 2
    return 1 if args.require_enforcement and report["warnings"] else 0


if __name__ == "__main__":
    sys.exit(main())
