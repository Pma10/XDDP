#!/usr/bin/env python3
"""Bounded loopback fixture: outage backoff, status isolation, relay guards."""
import argparse
import asyncio
import json
from pathlib import Path
import subprocess
import tempfile
from gate_integration import ROOT, LOGIN, handshake, frame, vi, readframe, port, metrics


async def run(binary):
    public, metric, backend_port = port(), port(), port()
    cfg=json.loads((ROOT/"config/gate.json").read_text())
    cfg.update(listen=f"127.0.0.1:{public}",backend=f"127.0.0.1:{backend_port}",
        metrics=f"127.0.0.1:{metric}",runtime_file="",proxy_v2=False,allow_backend_identity_loss=True)
    cfg["backend_protection"]={"max_connecting":2,"failure_threshold":1,"cooldown_ms":1000}
    cfg["timeouts"].update(backend_ms=300,relay_stall_ms=500,half_close_ms=250,shutdown_seconds=0)
    cfg["cache"]["ttl_seconds"]=300
    writers=set()
    errors=[]
    async def backend(reader,writer):
        writers.add(writer)
        try:
            h=await readframe(reader); await readframe(reader)
            if h[-1]==1:
                text=b'{"description":{"text":"cached"}}'
                writer.write(frame(b'\0'+vi(len(text))+text)); await writer.drain()
            else:
                writer.write(b"admitted"); await writer.drain()
                while data:=await reader.read(1024):
                    writer.write(data); await writer.drain()
                # Deliberately retain the reverse direction after FIN.
                await reader.read()
                await asyncio.sleep(1)
        except (ConnectionError,asyncio.IncompleteReadError):
            pass
        except Exception as exc:
            errors.append(exc)
        finally:
            writer.close(); writers.discard(writer)

    async def login():
        r,w=await asyncio.open_connection("127.0.0.1",public)
        w.write(handshake()+LOGIN); await w.drain()
        return r,w

    async def rejected_login():
        r,w=await login()
        assert await asyncio.wait_for(r.read(),2)==b""
        w.close(); await w.wait_closed()

    with tempfile.TemporaryDirectory() as tmp:
        path=Path(tmp)/"gate.json"; path.write_text(json.dumps(cfg))
        subprocess.run([binary,str(path),"--check"],check=True)
        with open(Path(tmp)/"gate.log","w+") as log:
            process=subprocess.Popen([binary,str(path)],stdout=log,stderr=log)
            server=None
            try:
                for _ in range(100):
                    assert process.poll() is None,"gate exited"
                    try: await metrics(metric); break
                    except OSError: await asyncio.sleep(0.02)
                else: raise AssertionError("metrics never ready")
                before=await metrics(metric)
                await rejected_login() # Real dial failure opens the player circuit.
                opened=await metrics(metric)
                assert opened["backend_circuit_opened"]==1
                attempts=opened["backend_connect_attempts"]
                for _ in range(5): await rejected_login()
                after=await metrics(metric)
                assert after["backend_connect_attempts"]==attempts
                assert after["backend_protection_rejected"]==5
                assert after["churn"]==before["churn"]
                assert after["active_prelogin"]==0
                # Client-selected status protocol still receives a bounded cached fallback.
                for version in (47,774,2147483647):
                    r,w=await asyncio.open_connection("127.0.0.1",public)
                    w.write(handshake(1,version=version)+frame(b'\0')); await w.drain()
                    body=await asyncio.wait_for(readframe(r),2)
                    assert f'"protocol":{version}'.encode() in body
                    w.close(); await w.wait_closed()
                assert (await metrics(metric))["backend_connect_attempts"]==attempts
                server=await asyncio.start_server(backend,"127.0.0.1",backend_port)
                await asyncio.sleep(1.05)
                r,w=await login(); assert await asyncio.wait_for(r.readexactly(8),2)==b"admitted"
                await asyncio.sleep(0.6) # Longer than stall_ms, but no pending write.
                w.write(b"alive"); await w.drain()
                assert await asyncio.wait_for(r.readexactly(5),2)==b"alive"
                w.write_eof(); assert await asyncio.wait_for(r.read(),2)==b""
                w.close(); await w.wait_closed()
                final=await metrics(metric)
                assert final["half_close_timeouts"]==1
                assert final["relay_stall_timeouts"]==0
                assert final["churn"]==before["churn"]
                assert not errors,errors
                print("PASS: outage backoff, recovery, no per-status dial, no server-side churn, healthy idle and half-close cleanup")
            finally:
                process.terminate()
                await asyncio.to_thread(process.wait,timeout=5)
                if server:
                    server.close(); await server.wait_closed()
                for writer in list(writers): writer.close()
                log.seek(0); print(log.read())


if __name__=="__main__":
    parser=argparse.ArgumentParser(); parser.add_argument("--binary",required=True)
    args=parser.parse_args()
    asyncio.run(asyncio.wait_for(run(str(Path(args.binary).resolve())),30))
