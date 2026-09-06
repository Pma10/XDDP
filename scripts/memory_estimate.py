#!/usr/bin/env python3
"""Conservative planning estimates, never claims to measure kernel allocator RSS."""
import argparse
import json
import math
import subprocess


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--gate-binary")
    p.add_argument("--cpus",type=int,default=6)
    a=p.parse_args()
    if not 1<=a.cpus<=4096:
        p.error("cpus must represent possible CPUs")
    sizes=json.loads(subprocess.check_output([a.gate_binary,"--state-sizes"],text=True)) if a.gate_binary else dict(identity_key_bytes=24,identity_value_bytes=256)
    output={"gate_layout":sizes,"layout_source":"binary sizeof" if a.gate_binary else "conservative estimate; measure binary layout", "rows":[]}
    for entries in (100000,500000,1000000):
        per_shard=math.ceil(entries/64)
        capacity=1 << math.ceil(math.log2(per_shard/0.875))
        output["rows"].append(dict(entries=entries,
            gate_table_capacity_estimate_mib=64*capacity*(sizes["identity_key_bytes"]+sizes["identity_value_bytes"]+9)/2**20,
            hypothetical_lru_hash_mib=entries*104/2**20,
            hypothetical_lru_percpu_hash_mib=entries*(72+32*a.cpus)/2**20))
    output["notes"]=["No dynamic LRU is allocated by XDDP XDP.","Hypothetical IPv4 LRU: key4/value32, estimated shared overhead68.",
        "Per-CPU values duplicate over possible CPUs, not active RX queues.","Kernel allocator/slab/bucket/map metadata are approximate; inspect bpftool and RSS on target.",
        "Gate estimate includes hash capacity rounding and padding; tables start empty and grow to caps."]
    print(json.dumps(output,indent=2))


if __name__ == "__main__":
    main()
