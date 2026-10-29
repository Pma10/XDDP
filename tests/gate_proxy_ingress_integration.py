#!/usr/bin/env python3
"""End-to-end trusted inbound PROXY v2 identity and backend forwarding fixture."""
import argparse
import asyncio
import json
import socket
import subprocess
import tempfile
from pathlib import Path
from gate_integration import ROOT, frame, handshake, LOGIN, metrics, port, readframe, vi

SIGNATURE = b"\r\n\r\n\0\r\nQUIT\n"

def proxy(src, dest=b"\xc0\x00\x02\x0a", src_port=3456):
    return SIGNATURE + bytes([0x21, 0x11, 0, 12]) + src + dest + src_port.to_bytes(2, "big") + (25565).to_bytes(2, "big")

async def run(binary):
    seen = []
    async def backend(reader, writer):
        try:
            header = await reader.readexactly(16)
            assert header[:12] == SIGNATURE
            assert header[12:14] == b"\x21\x11"
            addr = await reader.readexactly(12)
            first = await readframe(reader)
            _next = await readframe(reader)
            if first[-1] == 1:
                response = b'{"version":{"name":"Fixture","protocol":757},"players":{"max":20,"online":1},"description":{"text":"ok"}}'
                writer.write(frame(b"\0" + vi(len(response)) + response))
                await writer.drain()
            else:
                seen.append((addr[:4], addr[4:8]))
                writer.write(b"admitted")
                await writer.drain()
                await reader.read()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
    server = await asyncio.start_server(backend, "127.0.0.1", 0)
    listen, metric = port(), port()
    cfg = json.loads((ROOT / "config/gate.json").read_text())
    cfg.update(listen=f"127.0.0.1:{listen}", backend=f"127.0.0.1:{server.sockets[0].getsockname()[1]}",
               metrics=f"127.0.0.1:{metric}", runtime_file="", proxy_v2=True, allow_backend_identity_loss=False)
    cfg["incoming_proxy_v2"] = {"enabled": True, "trusted_proxies": ["127.0.0.1/32"]}
    cfg["limits"]["connections_ip"] = 1
    cfg["timeouts"]["shutdown_seconds"] = 1
    with tempfile.TemporaryDirectory() as temp:
        config_path = Path(temp) / "gate.json"
        config_path.write_text(json.dumps(cfg))
        subprocess.run([binary, str(config_path), "--check"], check=True)
        with open(Path(temp) / "gate.log", "w+") as log:
            proc = subprocess.Popen([binary, str(config_path)], stderr=log, stdout=log)
            writers = []
            try:
                for _ in range(100):
                    if proc.poll() is not None:
                        raise AssertionError("gate exited before ready")
                    try:
                        await metrics(metric)
                        break
                    except OSError:
                        await asyncio.sleep(.05)
                else:
                    raise AssertionError("gate not ready")
                # Two different asserted players through ONE real proxy may both join.
                for ip in (bytes([203,0,113,1]), bytes([203,0,113,2])):
                    reader, writer = await asyncio.open_connection("127.0.0.1", listen)
                    writer.write(proxy(ip) + handshake() + LOGIN)
                    await writer.drain()
                    assert await asyncio.wait_for(reader.readexactly(8), 3) == b"admitted"
                    writers.append(writer)
                assert seen[-2:] == [(bytes([203,0,113,1]),bytes([192,0,2,10])),
                                     (bytes([203,0,113,2]),bytes([192,0,2,10]))]
                # A 2nd connection from the same actual client IP is limited.
                reader,writer = await asyncio.open_connection("127.0.0.1",listen)
                writer.write(proxy(bytes([203,0,113,1])) + handshake() + LOGIN)
                await writer.drain()
                assert await asyncio.wait_for(reader.read(), 2) == b""
                writer.close(); await writer.wait_closed()
                # Bare Minecraft (no PROXY header) must never pass.
                reader,writer = await asyncio.open_connection("127.0.0.1",listen)
                writer.write(handshake() + LOGIN)
                await writer.drain()
                assert await asyncio.wait_for(reader.read(), 2) == b""
                writer.close(); await writer.wait_closed()
                print("PASS: trusted incoming PROXY v2, source-based limiter, Leaf forwarding, direct rejection")
            finally:
                for writer in writers:
                    writer.close()
                proc.terminate()
                try:
                    await asyncio.to_thread(proc.wait,timeout=4)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait()
                log.seek(0)
                print(log.read())
    server.close()
    await server.wait_closed()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--binary", required=True)
    args = p.parse_args()
    asyncio.run(run(str(Path(args.binary).resolve())))
