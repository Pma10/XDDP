#!/usr/bin/env python3
"""Owned loopback fixtures: one large uploader, concurrent healthy relay, pending caps."""
import argparse
import asyncio
import json
from pathlib import Path
import subprocess
import tempfile

from gate_integration import ROOT, LOGIN, frame, handshake, metrics, port, readframe


async def closed(reader):
    try:
        return await asyncio.wait_for(reader.read(),2)
    except ConnectionError:
        return b""


async def wait_metric(address,name,value):
    for _ in range(100):
        result=await metrics(address)
        if result[name]==value:
            return result
        await asyncio.sleep(0.01)
    raise AssertionError(f"{name} never reached {value}: {result[name]}")


async def scenario(binary,mode):
    clients=set()
    async def backend(reader,writer):
        clients.add(writer)
        try:
            h=await readframe(reader); await readframe(reader)
            if h[-1]==1:
                text=b'{"description":{"text":"fixture"}}'
                writer.write(frame(b"\x00"+bytes([len(text)])+text)); await writer.drain()
            else:
                writer.write(b"admitted"); await writer.drain()
                while data:=await reader.read(8192):
                    writer.write(data); await writer.drain()
        except (ConnectionError,asyncio.IncompleteReadError):
            pass
        finally:
            writer.close(); clients.discard(writer)
    server=await asyncio.start_server(backend,"127.0.0.1",0)
    public,metric=port(),port()
    cfg=json.loads((ROOT/"config/gate.json").read_text())
    cfg.update(listen=f"127.0.0.1:{public}",backend=f"127.0.0.1:{server.sockets[0].getsockname()[1]}",
        metrics=f"127.0.0.1:{metric}",runtime_file="",relay_buffer=1024)
    cfg["limits"].update(total_sockets=32,prelogin=4,status_connections=2,admitted=8,backend=9,prelogin_ip=1)
    cfg["timeouts"].update(first_progress_ms=1000,progress_ms=1000,handshake_ms=2000,shutdown_seconds=0)
    cfg["upload"]={"bytes_per_second":0 if mode=="disabled" else 1,
        "burst_bytes":0 if mode=="disabled" else 2048,"enforce":mode=="enforce"}
    cfg["cache"]["ttl_seconds"]=300
    async def login():
        reader,writer=await asyncio.open_connection("127.0.0.1",public)
        writer.write(handshake()+LOGIN); await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(8),2)==b"admitted"
        return reader,writer
    with tempfile.TemporaryDirectory() as tmp:
        path=Path(tmp)/"gate.json"; path.write_text(json.dumps(cfg))
        with open(Path(tmp)/"stderr.log","w+") as log:
            process=subprocess.Popen([binary,str(path)],stdout=log,stderr=log)
            try:
                for _ in range(100):
                    if process.poll() is not None: raise AssertionError("gate exited")
                    try:
                        await metrics(metric); break
                    except OSError: await asyncio.sleep(0.03)
                else: raise AssertionError("gate not ready")
                healthy_r,healthy_w=await login()
                flood_r,flood_w=await login() # Same IP; active relay consumes no pending slot.
                payload=b"x"*16384
                flood_w.write(payload); await flood_w.drain()
                if mode=="enforce":
                    received=await closed(flood_r)
                    assert len(received)<=2048
                else:
                    assert await asyncio.wait_for(flood_r.readexactly(len(payload)),2)==payload
                    flood_w.write_eof(); assert await closed(flood_r)==b""
                flood_w.close()
                await wait_metric(metric,"admitted_clients",1)
                healthy_w.write(b"still-playing"); await healthy_w.drain()
                assert await asyncio.wait_for(healthy_r.readexactly(13),2)==b"still-playing"

                # One silent peer cannot accumulate multiple pending slots for
                # the same IP, but this policy never evicts its active relay.
                idle_r,idle_w=await asyncio.open_connection("127.0.0.1",public)
                await wait_metric(metric,"active_prelogin",1)
                rejected_r,rejected_w=await asyncio.open_connection("127.0.0.1",public)
                assert await closed(rejected_r)==b""
                rejected_w.close()
                assert (await metrics(metric))["prelogin_source_limited"]>=1
                idle_w.close(); await idle_w.wait_closed()
                await wait_metric(metric,"active_prelogin",0)
                new_r,new_w=await login()
                new_w.write(b"reconnected"); await new_w.drain()
                assert await asyncio.wait_for(new_r.readexactly(11),2)==b"reconnected"
                new_w.close(); healthy_w.close()
                result=await wait_metric(metric,"admitted_clients",0)
                assert result["upload_budget_exceeded_connections"]==(0 if mode=="disabled" else 1)
                if mode!="disabled": assert result["monitored_upload_bytes"]>2048
                print(f"PASS: upload={mode}, bounded large upload, same-IP healthy relay, pending cap, slot release and reconnect")
            finally:
                process.terminate()
                try: await asyncio.to_thread(process.wait,timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
                log.seek(0); print(log.read())
                server.close(); await server.wait_closed()
                for writer in list(clients): writer.close()


async def run(binary):
    for mode in ("disabled","monitor","enforce"):
        await scenario(binary,mode)


if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--binary",required=True)
    asyncio.run(run(str(Path(p.parse_args().binary).resolve())))
