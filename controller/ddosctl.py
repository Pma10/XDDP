#!/usr/bin/env python3
"""Privileged leased XDP controller and local AF_UNIX control client."""
import argparse
import copy
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import urllib.request

from core import Adaptive, MODES, rates, validate, bounded_json, runtime_document


def atomic(path, data, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def read_config(path):
    with open(path, encoding="utf-8") as stream:
        raw = stream.read(262145)
    if len(raw) > 262144:
        raise ValueError("configuration too large")
    return validate(json.loads(raw))


class Controller:
    def __init__(self, cfg, path):
        self.cfg, self.path = cfg, path
        self.adaptive = Adaptive(cfg["adaptive"], time.monotonic())
        self.previous, self.previous_time = {}, time.monotonic()
        self.snapshot, self.signals, self.mode = {}, {}, 0
        self.stopping = False
        self.generation = time.time_ns()

    def loader(self, *args):
        p = subprocess.run([self.cfg["loader"], *map(str, args)], capture_output=True,
                           text=True, timeout=8, check=True)
        return json.loads(p.stdout) if p.stdout.strip().startswith("{") else p.stdout.strip()

    def lease(self, seconds=None):
        c = self.cfg
        seconds = c["lease_seconds"] if seconds is None else seconds
        budget = c["syn_per_cpu"][MODES[self.mode]]
        self.loader("config", c["pin_dir"], time.monotonic_ns() + int(seconds * 1e9) if seconds else 0,
                    int(c["observe"]), self.mode, int(c["ipv6"]), int(c["drop_tcp_fragments"]),
                    budget["rate"], budget["burst"], 1)

    def prepare(self):
        pin = Path(self.cfg["pin_dir"])
        if not (pin / "program").exists():
            pin.mkdir(parents=True, exist_ok=True)
            self.loader("load", self.cfg["object"], pin)
        self.loader("validate",pin)
        # Static policy reconciliation is fail-open and single-writer.
        self.lease(0)
        for name in ("ports", "owned", "allow", "block"):
            self.loader("clear", pin, name)
        policies = {}
        for key, flag in (("protected_tcp_ports",1),("drop_tcp_ports",2),("drop_udp_ports",4)):
            for port in self.cfg[key]:
                policies[port] = policies.get(port,0) | flag
        for port, flags in policies.items():
            self.loader("port", pin, port, flags)
        for key, mapname, reason in (("owned_prefixes","owned",1),("allow_prefixes","allow",1),
                                     ("bogon_prefixes","block",5),("block_prefixes","block",11)):
            for prefix in self.cfg[key]:
                self.loader("prefix",pin,mapname,"add",prefix,reason)

    def gate_counters(self):
        # Proxy environment variables must never send localhost telemetry elsewhere.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(self.cfg["gate_metrics"],timeout=0.4) as response:
            data = response.read(65537)
        if len(data) > 65536:
            raise ValueError("gate metrics too large")
        counters = {}
        for line in data.decode("ascii").splitlines():
            if line.startswith("xddp_gate_"):
                name, value = line.split()
                counters[name.removeprefix("xddp_gate_")] = int(value) if value.isdecimal() else float(value)
        return counters

    def tick(self):
        now = time.monotonic()
        current = self.loader("stats",self.cfg["pin_dir"])
        self.snapshot = copy.deepcopy(current)
        try:
            current.update(self.gate_counters())
            self.snapshot["gate_metrics_available"] = True
            self.snapshot["gate_runtime_generation"] = current.get("runtime_generation",0)
            self.snapshot["gate_runtime_rejected_reads"] = current.get("runtime_rejected_reads",0)
        except (OSError, ValueError, UnicodeError):
            self.snapshot["gate_metrics_available"] = False
        self.signals = rates(self.previous,current,now-self.previous_time)
        self.previous, self.previous_time = current, now
        mode = self.adaptive.sample(self.signals,now)
        self.mode = mode if self.cfg["manual_mode"] == "auto" else MODES.index(self.cfg["manual_mode"])
        self.publish()
        self.lease()
        text = []
        for key, value in self.snapshot.items():
            if type(value) in (int,float):
                text.append(f"xddp_xdp_{key} {value}")
        for reason, count in self.snapshot["candidate_reasons"].items():
            text.append(f'xddp_xdp_candidate_drop{{reason="{reason}"}} {count}')
        for name,value in self.signals.items():
            text.append(f"xddp_observed_{name} {value}")
        text.extend([f"xddp_controller_mode {self.mode}", f"xddp_controller_observe {int(self.cfg['observe'])}",
                     f"xddp_controller_last_update_unix {int(time.time())}"])
        atomic(self.cfg["metrics_file"],"\n".join(text)+"\n")

    def publish(self, expired=False):
        self.generation += 1
        text = runtime_document(self.cfg,self.generation,
            int(time.time())+(0 if expired else self.cfg["lease_seconds"]),self.mode)
        atomic(self.cfg["runtime_file"],text)

    def command(self, args):
        if args == ["status"]:
            return dict(mode=MODES[self.mode],observe=self.cfg["observe"],signals=self.signals,
                        gate_metrics_available=self.snapshot.get("gate_metrics_available",False),
                        published_generation=self.generation,
                        gate_runtime_generation=self.snapshot.get("gate_runtime_generation"),
                        gate_runtime_rejected_reads=self.snapshot.get("gate_runtime_rejected_reads"))
        if args == ["stats"]:
            return self.snapshot
        if args == ["config","show"]:
            return self.cfg
        if args == ["xdp","status"]:
            return self.loader("status",self.cfg["interface"],self.cfg["xdp_mode"])
        if len(args) in (2,3) and args[:2] == ["xdp","attach"]:
            expected = int(args[2]) if len(args) == 3 else 0
            if expected < 0:
                raise ValueError("invalid expected id")
            self.loader("validate",self.cfg["pin_dir"])
            self.loader("attach",self.cfg["interface"],self.cfg["pin_dir"],self.cfg["xdp_mode"],"confirmed",expected)
            return self.command(["xdp","status"])
        if len(args) == 3 and args[:2] == ["xdp","detach"]:
            self.loader("detach",self.cfg["interface"],self.cfg["xdp_mode"],int(args[2]))
            return self.command(["xdp","status"])
        c = copy.deepcopy(self.cfg)
        if len(args) == 2 and args[0] == "mode" and args[1] in (*MODES,"auto"):
            c["manual_mode"] = args[1]
        elif len(args) == 2 and args[0] == "observe" and args[1] in ("on","off"):
            c["observe"] = args[1] == "on"
        elif len(args) == 2 and args[0] in ("allow","unallow","block","unblock"):
            network = str(ipaddress.ip_network(args[1],strict=False))
            key = "allow_prefixes" if args[0] in ("allow","unallow") else "block_prefixes"
            values = set(c[key])
            if args[0].startswith("un"):
                values.discard(network)
            else:
                values.add(network)
            c[key] = sorted(values)
        else:
            raise ValueError("unknown command; see ddosctl --help")
        validate(c)
        old = self.cfg
        # Persist only after map updates succeed; a failure leaves the lease expired.
        try:
            self.lease(0)
            for key,mapname,reason in (("allow_prefixes","allow",1),("block_prefixes","block",11)):
                for n in set(old[key])-set(c[key]):
                    self.loader("prefix",old["pin_dir"],mapname,"del",n,reason)
                    if mapname == "block" and n in c["bogon_prefixes"]:
                        self.loader("prefix",old["pin_dir"],mapname,"add",n,5)
                for n in set(c[key])-set(old[key]):
                    self.loader("prefix",old["pin_dir"],mapname,"add",n,reason)
            atomic(self.path,bounded_json(c,indent=2),0o640)
            self.cfg = c
            self.mode = self.adaptive.mode if c["manual_mode"] == "auto" else MODES.index(c["manual_mode"])
            self.publish()
            self.lease()
        except Exception:
            self.stopping = True
            raise
        return self.command(["status"])

    def cleanup(self):
        # Try each cleanup independently: a full/read-only runtime filesystem
        # must not prevent expiring the kernel lease or removing the socket.
        try:
            self.publish(expired=True)
        finally:
            try:
                self.lease(0)
            finally:
                Path(self.cfg["socket"]).unlink(missing_ok=True)

    def run(self):
        lock_path = Path(self.cfg["socket"]).with_suffix(".lock")
        lock_path.parent.mkdir(parents=True,exist_ok=True)
        with open(lock_path,"w",encoding="ascii") as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.prepare()
            path = Path(self.cfg["socket"])
            path.unlink(missing_ok=True)
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
                server.bind(str(path)); os.chmod(path,0o600); server.listen(8); server.settimeout(0.2)
                for sig in (signal.SIGTERM,signal.SIGINT):
                    signal.signal(sig,lambda *_: setattr(self,"stopping",True))
                next_tick = 0
                try:
                    while not self.stopping:
                        if time.monotonic() >= next_tick:
                            self.tick(); next_tick = time.monotonic()+1
                        try:
                            client,_ = server.accept()
                        except socket.timeout:
                            continue
                        with client:
                            client.settimeout(0.5)
                            try:
                                data = bytearray()
                                while b"\n" not in data and len(data) <= 4096:
                                    chunk = client.recv(min(1024,4097-len(data)))
                                    if not chunk:
                                        break
                                    data.extend(chunk)
                                if len(data) > 4096:
                                    raise ValueError("request too large")
                                args = json.loads(data)
                                if not isinstance(args,list) or len(args) > 4 or not all(isinstance(a,str) for a in args):
                                    raise ValueError("expected argument array")
                                response = dict(ok=True,result=self.command(args))
                            except (ValueError,OSError,subprocess.SubprocessError) as exc:
                                response = dict(ok=False,error=str(exc))
                            try:
                                client.sendall((json.dumps(response)+"\n").encode())
                            except OSError:
                                pass
                finally:
                    self.cleanup()


def main():
    p = argparse.ArgumentParser(description="XDDP local control (root socket). Commands: status, stats, mode normal|elevated|attack|emergency|auto, observe on|off, allow|unallow|block|unblock CIDR, config show, xdp status|attach [EXPECTED_ID]|detach EXPECTED_ID")
    p.add_argument("--config",default="/etc/xddp/controller.json")
    p.add_argument("--socket",default="/run/xddp/control.sock")
    p.add_argument("--check",action="store_true")
    p.add_argument("--daemon",action="store_true")
    p.add_argument("command",nargs="*")
    args = p.parse_args()
    if args.check:
        read_config(args.config); print("configuration valid; rates without measurements remain disabled"); return
    if args.daemon:
        Controller(read_config(args.config),args.config).run(); return
    if not args.command:
        p.error("command required")
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(15); client.connect(args.socket)
        client.sendall((json.dumps(args.command)+"\n").encode())
        data = bytearray()
        while b"\n" not in data:
            chunk = client.recv(65536)
            if not chunk:
                raise RuntimeError("controller closed before response")
            data.extend(chunk)
            if len(data) > 1_048_576:
                raise RuntimeError("response too large")
    result = json.loads(data)
    if not result["ok"]:
        raise RuntimeError(result["error"])
    print(json.dumps(result["result"],indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
        print(f"ddosctl: {error}",file=sys.stderr)
        sys.exit(1)
