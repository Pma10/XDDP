#!/usr/bin/env python3
"""Bounded loopback-only admission, cache, relay and resource integration tests."""
import argparse
import asyncio
import copy
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def vi(n):
    n &= 0xffffffff
    b = bytearray()
    while True:
        value = n & 127; n >>= 7
        b.append(value | (128 if n else 0))
        if not n:
            return bytes(b)


def frame(body):
    return vi(len(body))+body


def handshake(state=2,host=b"localhost",version=47):
    return frame(b"\x00"+vi(version)+vi(len(host))+host+b"\x63\xdd"+vi(state))


LOGIN = frame(b"\x00\x06Player")


async def readframe(reader):
    n = 0
    for i in range(5):
        b = (await reader.readexactly(1))[0]
        n |= (b & 127) << (7*i)
        if not b & 128:
            if n > 65536:
                raise ValueError("huge fixture frame")
            return await reader.readexactly(n)
    raise ValueError("fixture varint")


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0)); return sock.getsockname()[1]


async def metrics(address):
    r,w = await asyncio.open_connection("127.0.0.1",address)
    w.write(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n"); await w.drain()
    data = (await r.read()).decode(); w.close(); await w.wait_closed()
    return {line.split()[0].removeprefix("xddp_gate_"):float(line.split()[1])
            for line in data.splitlines() if line.startswith("xddp_gate_")}


async def run(binary):
    counts = dict(login=0,status=0)
    backend_clients = set()
    async def backend(reader,writer):
        backend_clients.add(writer)
        try:
            h = await readframe(reader)
            initial = await readframe(reader)
            if h[-1] == 1:
                counts["status"] += 1
                text = b'{"version":{"name":"Fixture","protocol":47},"players":{"max":100,"online":1},"description":{"text":"cached"}}'
                writer.write(frame(b"\0"+vi(len(text))+text)); await writer.drain()
            else:
                assert initial == b"\0\x06Player"
                counts["login"] += 1
                writer.write(b"admitted"); await writer.drain()
                while data := await reader.read(8192):
                    writer.write(data); await writer.drain()
        except (asyncio.IncompleteReadError,ConnectionError):
            pass
        finally:
            writer.close(); backend_clients.discard(writer)

    server = await asyncio.start_server(backend,"127.0.0.1",0)
    backend_port = server.sockets[0].getsockname()[1]
    public,metric = port(),port()
    cfg = json.loads((ROOT/"config/gate.json").read_text())
    cfg.update(listen=f"127.0.0.1:{public}",backend=f"127.0.0.1:{backend_port}",metrics=f"127.0.0.1:{metric}",runtime_file="")
    cfg["limits"].update(total_sockets=64,prelogin=8,admitted=16,backend=17,ip_entries=128,prefix_entries=128)
    cfg["timeouts"].update(first_progress_ms=200,progress_ms=200,handshake_ms=1500,login_ms=500,status_ms=500,shutdown_seconds=1)
    cfg["cache"]["ttl_seconds"] = 300
    logins = 0
    with tempfile.TemporaryDirectory() as tmp:
        config_path = Path(tmp)/"gate.json"; config_path.write_text(json.dumps(cfg))
        subprocess.run([binary,str(config_path),"--check"],check=True)
        with open(Path(tmp)/"stderr.log","w+") as log:
            process = subprocess.Popen([binary,str(config_path)],stdout=log,stderr=log)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise AssertionError("gate exited at startup")
                    try:
                        await metrics(metric); break
                    except OSError:
                        await asyncio.sleep(0.05)
                else:
                    raise AssertionError("gate never ready")
                for _ in range(100):
                    if counts["status"]:
                        break
                    await asyncio.sleep(0.01)

                # Coalesced handshake/Login Start/game bytes must arrive exactly once.
                for split,host in ((False,b"localhost\0FML3\0"),(True,b"a"*130)):
                    r,w = await asyncio.open_connection("127.0.0.1",public)
                    wire = handshake(host=host)+LOGIN+b"\xff\x00encrypted-gameplay\x03"
                    if split:
                        for byte in wire:
                            w.write(bytes([byte])); await w.drain(); await asyncio.sleep(0.001)
                    else:
                        w.write(wire); await w.drain()
                    assert await asyncio.wait_for(r.readexactly(8),2) == b"admitted"
                    payload = b"\xff\x00encrypted-gameplay\x03"
                    assert await asyncio.wait_for(r.readexactly(len(payload)),2) == payload
                    w.write_eof(); assert await asyncio.wait_for(r.read(),2) == b""
                    w.close(); await w.wait_closed(); logins += 1

                # Cached status + ping must never create per-client backend sockets.
                before = counts["status"]
                for _ in range(20):
                    r,w = await asyncio.open_connection("127.0.0.1",public)
                    ping = b"\x01"+b"12345678"
                    w.write(handshake(1,version=-1)+frame(b"\0")+frame(ping)); await w.drain()
                    response = await asyncio.wait_for(readframe(r),2)
                    assert b'"cached"' in response
                    assert await readframe(r) == ping
                    w.close(); await w.wait_closed()
                assert counts["status"] == before

                bad = [b"\x80"*5,b"\xff\xff\x7f",b"\x80\x00",handshake()+frame(b"\x01\x00"),
                       handshake()+frame(b"\x00\x40"+b"a"*64),handshake(3),handshake()+LOGIN+b"more"]
                # Last entry is valid admission and is intentionally excluded from rejection fixtures.
                for wire in bad[:-1]:
                    r,w = await asyncio.open_connection("127.0.0.1",public)
                    w.write(wire); await w.drain()
                    try:
                        assert await asyncio.wait_for(r.read(),2) == b""
                    except ConnectionError:
                        pass
                    w.close()
                assert counts["login"] == logins

                # Idle first byte and slow partial handshake have bounded lifetimes.
                for initial in (b"",b"\x80",handshake()[:4]):
                    r,w = await asyncio.open_connection("127.0.0.1",public)
                    w.write(initial); await w.drain()
                    start = time.monotonic()
                    assert await asyncio.wait_for(r.read(),2) == b""
                    assert time.monotonic()-start < 1.8
                    w.close(); await w.wait_closed()

                # Capacity is enforced before spawning unbounded pre-login tasks.
                held = [await asyncio.open_connection("127.0.0.1",public) for _ in range(12)]
                live = await metrics(metric)
                assert live["active_prelogin"] <= 8
                assert live["resource_limited"] >= 4
                for _,writer in held:
                    writer.close()
                for _ in range(20):
                    r,w = await asyncio.open_connection("127.0.0.1",public)
                    w.close(); await w.wait_closed()
                await asyncio.sleep(0.3)
                final = await metrics(metric)
                assert final["active_prelogin"] == 0
                assert final["admitted_clients"] == 0
                assert final["invalid_varint"] >= 2
                assert final["oversized_packet"] >= 1
                assert final["slow_connection"] >= 3
                assert counts["login"] == logins
                print("PASS: split/coalesced admission, opaque relay, half-close, status cache/ping, malformed input, deadlines, capacity and reconnect cleanup")
            finally:
                process.terminate()
                try:
                    await asyncio.to_thread(process.wait,timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
                log.seek(0); print(log.read())
    for writer in list(backend_clients):
        writer.close()
    server.close(); await server.wait_closed()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary",required=True)
    args = parser.parse_args()
    asyncio.run(run(str(Path(args.binary).resolve())))
