#!/usr/bin/env python3
"""Low-rate TCP/status/ping probe for an explicitly owned test endpoint."""
import argparse
import json
from pathlib import Path
import socket
import statistics
import struct
import time


def vi(value):
    value &= 0xffffffff
    result = bytearray()
    while True:
        b = value & 127; value >>= 7
        result.append(b | (128 if value else 0))
        if not value:
            return bytes(result)


def frame(body):
    return vi(len(body))+body


def exact(sock,n):
    result = bytearray()
    while len(result) < n:
        chunk = sock.recv(n-len(result))
        if not chunk:
            raise OSError("unexpected EOF")
        result.extend(chunk)
    return bytes(result)


def packet(sock):
    size = 0
    for i in range(5):
        b = exact(sock,1)[0]; size |= (b & 127) << (7*i)
        if not b & 128:
            if size > 65536:
                raise OSError("oversized response")
            return exact(sock,size)
    raise OSError("invalid response VarInt")


def summarize(samples):
    if not samples:
        return {"count":0}
    ordered = sorted(samples)
    return {"count":len(samples),"mean_ms":statistics.mean(samples),
            **{f"p{q}_ms":ordered[min(len(ordered)-1,int((len(ordered)-1)*q/100))] for q in (50,95,99)},
            "adjacent_absolute_jitter_ms":statistics.mean(abs(a-b) for a,b in zip(samples,samples[1:])) if len(samples)>1 else 0}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--owned-test-endpoint",action="store_true",required=True)
    p.add_argument("--host",required=True)
    p.add_argument("--port",type=int,default=25565)
    p.add_argument("--virtual-host",default="localhost")
    p.add_argument("--count",type=int,default=60)
    p.add_argument("--interval",type=float,default=1)
    p.add_argument("--output",required=True)
    a = p.parse_args()
    if not 1 <= a.count <= 3600 or a.interval < 0.2 or len(a.virtual_host.encode())>255 or not 1<=a.port<=65535:
        p.error("bounded count/interval/host/port required")
    values = {"tcp":[],"status":[],"minecraft_ping":[]}; failures=[]
    for i in range(a.count):
        start=time.perf_counter()
        try:
            with socket.create_connection((a.host,a.port),timeout=3) as s:
                s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
                values["tcp"].append((time.perf_counter()-start)*1000)
                host=a.virtual_host.encode()
                s.sendall(frame(b"\0"+vi(-1)+vi(len(host))+host+struct.pack("!H",a.port)+b"\1")+b"\1\0")
                packet(s); values["status"].append((time.perf_counter()-start)*1000)
                ping=b"\1"+struct.pack("!q",i); stamp=time.perf_counter()
                s.sendall(frame(ping))
                if packet(s)!=ping:
                    raise OSError("wrong ping echo")
                values["minecraft_ping"].append((time.perf_counter()-stamp)*1000)
        except OSError as e:
            failures.append({"sample":i,"error":str(e)})
        time.sleep(max(0,a.interval-(time.perf_counter()-start)))
    result={"samples":values,"summary":{k:summarize(v) for k,v in values.items()},"failures":failures,
            "authenticated_login_latency":"NOT MEASURED; use instrumented owned Minecraft clients",
            "gameplay_latency":"NOT MEASURED; use player/client instrumentation"}
    with open(a.output,"x",encoding="utf-8") as out:
        json.dump(result,out,indent=2)


if __name__ == "__main__":
    main()
