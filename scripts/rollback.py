#!/usr/bin/env python3
"""Detach only the program pinned by this configured generation. Never touch Java."""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--config",default="/etc/xddp/controller.json")
    args = p.parse_args()
    cfg = json.loads(Path(args.config).read_text())
    if cfg["interface"] != "eth0" or cfg["xdp_mode"] not in ("driver","skb"):
        raise ValueError("only explicitly configured eth0 mode supported")
    def loader(*args):
        result = subprocess.run([cfg["loader"],*map(str,args)],check=True,capture_output=True,text=True)
        return json.loads(result.stdout) if result.stdout.strip() else {}
    active = loader("status","eth0",cfg["xdp_mode"])["program_id"]
    if active == 0:
        print("No XDP in configured mode; nothing detached."); return
    owned = loader("id",cfg["pin_dir"])["program_id"]
    if active != owned:
        raise ValueError("active program does not match this generation; refusing detach")
    loader("detach","eth0",cfg["xdp_mode"],owned)
    print("XDDP detached. Gate/backend listener rollback is a separate operator action.")


if __name__ == "__main__":
    try:
        main()
    except (OSError,ValueError,subprocess.SubprocessError) as e:
        print(f"rollback: {e}",file=sys.stderr); sys.exit(1)
