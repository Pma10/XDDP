#!/usr/bin/env python3
"""Offline exact per-second identity counts from a bounded authorized PCAP.
Capture is a separate operator action; this tool does not sniff live traffic.
"""
import argparse
import ipaddress
import json
import subprocess


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("pcap")
    p.add_argument("--output",required=True)
    p.add_argument("--max-packets",type=int,default=200000)
    a=p.parse_args()
    if not 1<=a.max_packets<=1000000:
        p.error("packet cap must be 1..1000000")
    cmd=["tshark","-n","-r",a.pcap,"-c",str(a.max_packets),"-Y","tcp.flags.syn==1 && tcp.flags.ack==0",
         "-T","fields","-E","occurrence=f","-e","frame.time_epoch","-e","ip.src","-e","ipv6.src"]
    proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,text=True)
    second=None; ips=set(); prefixes=set(); count=0; total=0
    with open(a.output,"x",encoding="utf-8") as out:
        def emit():
            if second is not None:
                out.write(json.dumps(dict(second=second,syn_packets=count,unique_source_ips=len(ips),unique_prefixes=len(prefixes)))+"\n")
        try:
            for line in proc.stdout:
                fields=line.rstrip("\n").split("\t")
                if len(fields)<3:
                    continue
                stamp=int(float(fields[0])); ip=ipaddress.ip_address(fields[1] or fields[2])
                if second != stamp:
                    emit(); second=stamp; ips.clear(); prefixes.clear(); count=0
                ips.add(ip); prefixes.add(ipaddress.ip_network(f"{ip}/{24 if ip.version==4 else 64}",strict=False))
                count+=1; total+=1
            emit()
        finally:
            proc.stdout.close()
            code=proc.wait()
        if code:
            raise SystemExit(code)
        out.write(json.dumps({"capture_scope":"operator selected; counts exclude uncaptured/dropped packets",
                              "source":"bounded PCAP, ordered timestamps required","matched_syn_packets":total,"packet_cap":a.max_packets})+"\n")


if __name__ == "__main__":
    main()
