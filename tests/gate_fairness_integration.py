#!/usr/bin/env python3
"""Bounded owned-loopback status pressure with live and reconnecting players."""
import argparse
import asyncio
import json
from pathlib import Path
import subprocess
import tempfile

from gate_integration import ROOT, LOGIN, frame, handshake, metrics, port, readframe
from gate_abuse_integration import closed, wait_metric


async def run(binary):
    backend_clients=set()
    player_writers=[]
    counts={"login":0,"status":0}

    async def backend(reader,writer):
        backend_clients.add(writer)
        try:
            h=await readframe(reader); await readframe(reader)
            if h[-1]==1:
                counts["status"]+=1
                text=b'{"description":{"text":"cached"}}'
                writer.write(frame(b"\x00"+bytes([len(text)])+text)); await writer.drain()
            else:
                counts["login"]+=1
                writer.write(b"admitted"); await writer.drain()
                while data:=await reader.read(8192):
                    writer.write(data); await writer.drain()
        except (ConnectionError,asyncio.IncompleteReadError):
            pass
        finally:
            writer.close(); backend_clients.discard(writer)

    server=await asyncio.start_server(backend,"127.0.0.1",0)
    public,metric=port(),port()
    cfg=json.loads((ROOT/"config/gate.json").read_text())
    cfg.update(listen=f"127.0.0.1:{public}",backend=f"127.0.0.1:{server.sockets[0].getsockname()[1]}",
        metrics=f"127.0.0.1:{metric}",runtime_file="",observe=False)
    cfg["limits"].update(total_sockets=32,prelogin=8,status_connections=2,status_ip=1,
        admitted=8,backend=9,separate_status_budget=True,churn_score_threshold=0.1)
    # Fixture-only rates: these are not production recommendations.
    cfg["limits"]["global"]["handshake"]={"per_second":0.001,"burst":3}
    cfg["limits"]["global"]["status"]={"per_second":0.001,"burst":3}
    cfg["timeouts"].update(first_progress_ms=5000,progress_ms=5000,status_ms=10000,shutdown_seconds=0)
    cfg["cache"]["ttl_seconds"]=300

    async def connect(source="127.0.0.1"):
        r,w=await asyncio.open_connection("127.0.0.1",public,local_addr=(source,0))
        player_writers.append(w)
        return r,w

    async def login():
        r,w=await connect()
        w.write(handshake()+LOGIN); await w.drain()
        assert await asyncio.wait_for(r.readexactly(8),2)==b"admitted"
        return r,w

    async def held_status(source):
        r,w=await connect(source)
        w.write(handshake(1)); await w.drain()
        return r,w

    async def finish_status(pair):
        r,w=pair
        w.write(frame(b"\x00")); await w.drain()
        await asyncio.wait_for(readframe(r),2)
        ping=b"\x01abcdefgh"
        w.write(frame(ping)); await w.drain()
        assert await asyncio.wait_for(readframe(r),2)==ping
        assert await closed(r)==b""
        w.close(); await w.wait_closed()

    with tempfile.TemporaryDirectory() as tmp:
        path=Path(tmp)/"gate.json"; path.write_text(json.dumps(cfg))
        subprocess.run([binary,str(path),"--check"],check=True)
        with open(Path(tmp)/"stderr.log","w+") as log:
            process=subprocess.Popen([binary,str(path)],stdout=log,stderr=log)
            try:
                for _ in range(100):
                    if process.poll() is not None: raise AssertionError("gate exited")
                    try:
                        await metrics(metric); break
                    except OSError: await asyncio.sleep(0.03)
                else: raise AssertionError("gate not ready")
                for _ in range(100):
                    if counts["status"]: break
                    await asyncio.sleep(0.01)
                assert counts["status"]==1
                live_r,live_w=await login()
                first=await held_status("127.0.0.1")
                await wait_metric(metric,"active_status",1)
                # Rejected source attempts must not spend the shared status burst.
                for _ in range(4):
                    r,w=await held_status("127.0.0.1")
                    assert await closed(r)==b""; w.close()
                assert (await metrics(metric))["status_source_limited"]==4
                second=await held_status("127.0.0.2")
                await wait_metric(metric,"active_status",2)
                # Neither may a full global status semaphore spend its burst.
                r,w=await held_status("127.0.0.3")
                assert await closed(r)==b""; w.close()
                assert (await metrics(metric))["status_capacity_limited"]==1
                await finish_status(first)
                await wait_metric(metric,"active_status",1)
                third=await held_status("127.0.0.3")
                await wait_metric(metric,"active_status",2)
                await finish_status(second)
                await wait_metric(metric,"active_status",1)
                # All three status tokens were spent at handshake, even before
                # a request arrives. The next status peer is rejected immediately.
                r,w=await held_status("127.0.0.4")
                assert await closed(r)==b""; w.close()
                assert (await metrics(metric))["rate_limited_global"]==1
                live_w.write(b"still-playing"); await live_w.drain()
                assert await asyncio.wait_for(live_r.readexactly(13),2)==b"still-playing"
                # The highest supported protocol uses the bounded UUID schema and
                # must not ban a compatible same-IP reconnect.
                r,w=await connect()
                w.write(handshake(version=776)+frame(b"\x00\x06Player"+bytes(16))); await w.drain()
                assert await asyncio.wait_for(r.readexactly(8),2)==b"admitted"
                new_r,new_w=await login()
                new_w.write(b"reconnected"); await new_w.drain()
                assert await asyncio.wait_for(new_r.readexactly(11),2)==b"reconnected"
                await finish_status(third)
                w.close(); new_w.close(); live_w.close()
                await wait_metric(metric,"active_connections",0)
                result=await metrics(metric)
                assert result["churn"]==0
                assert result["active_prelogin"]==result["active_status"]==result["admitted_clients"]==0
                assert counts=={"login":3,"status":1}
                print("PASS: status source/global cap fairness, early status budget, future protocol admission, live relay and zero churn")
            finally:
                for w in player_writers: w.close()
                process.terminate()
                try: await asyncio.to_thread(process.wait,timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
                log.seek(0); print(log.read())
                server.close(); await server.wait_closed()
                for w in list(backend_clients): w.close()


if __name__=="__main__":
    parser=argparse.ArgumentParser(); parser.add_argument("--binary",required=True)
    asyncio.run(run(str(Path(parser.parse_args().binary).resolve())))
