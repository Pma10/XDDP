#!/usr/bin/env python3
"""Read-only bounded Linux host sampling. Does not change XDP, NIC or sysctls."""
import argparse
import json
from pathlib import Path
import time
import urllib.request

LABELS = ("BASELINE","A","B","C","D")


def read(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def sample(interface,pids):
    result = {"time_unix":time.time(),"monotonic":time.monotonic()}
    result["cpu"] = {line.split()[0]:list(map(int,line.split()[1:])) for line in (read("/proc/stat") or "").splitlines() if line.startswith("cpu")}
    result["net_rx_softirq"] = next((list(map(int,line.split()[1:])) for line in (read("/proc/softirqs") or "").splitlines() if line.strip().startswith("NET_RX:")),None)
    result["interface"] = {name:read(f"/sys/class/net/{interface}/statistics/{name}") for name in ("rx_packets","rx_bytes","rx_dropped","rx_errors","tx_packets","tx_bytes")}
    result["softnet_stat"] = read("/proc/net/softnet_stat")
    result["netstat"] = read("/proc/net/netstat")
    result["processes"] = {str(pid):{"stat":read(f"/proc/{pid}/stat"),"status":read(f"/proc/{pid}/status"),"io":read(f"/proc/{pid}/io")} for pid in pids}
    result["xdp_prometheus"] = read("/run/xddp/xdp.prom")
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open("http://127.0.0.1:9109/metrics",timeout=0.3) as response:
            result["gate_metrics"] = response.read(65536).decode()
    except OSError:
        result["gate_metrics"] = None
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--label",choices=LABELS,required=True)
    p.add_argument("--interface",default="eth0")
    p.add_argument("--seconds",type=int,default=120)
    p.add_argument("--pid",type=int,action="append",default=[])
    p.add_argument("--output",required=True)
    args = p.parse_args()
    if not 1 <= args.seconds <= 3600 or not args.interface.replace("-","").replace("_","").isalnum():
        p.error("seconds 1..3600 and valid interface required")
    with open(args.output,"x",encoding="utf-8") as out:
        out.write(json.dumps({"label":args.label,"kind":"metadata","mtu":read(f"/sys/class/net/{args.interface}/mtu"),"kernel":read("/proc/sys/kernel/osrelease"),"allocations":"NOT MEASURED"})+"\n")
        start = time.monotonic()
        for i in range(args.seconds+1):
            time.sleep(max(0,start+i-time.monotonic()))
            out.write(json.dumps(sample(args.interface,args.pid))+"\n"); out.flush()


if __name__ == "__main__":
    main()
