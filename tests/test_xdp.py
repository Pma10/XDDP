"""BPF_PROG_TEST_RUN: uses private bpffs generation, no interface attachment."""
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]


def tcp(flags=0x10,payload=b"",port=25565):
    eth = bytes(12)+b"\x08\x00"
    ip = struct.pack("!BBHHHBBH4s4s",0x45,0,40+len(payload),0,0,64,6,0,
                     bytes([198,51,100,7]),bytes([192,0,2,1]))
    header = struct.pack("!HHIIBBHHH",12345,port,1,1,0x50,flags,65535,0,0)
    return eth+ip+header+payload


@unittest.skipUnless(os.environ.get("XDDP_BPF_TEST") == "1","set XDDP_BPF_TEST=1 as root on Linux")
class XDPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pin = Path("/sys/fs/bpf")/("xddp-test-"+uuid.uuid4().hex)
        cls.pin.mkdir()
        cls.loader("load",ROOT/"build/xdp_ddos.bpf.o",cls.pin)
        cls.loader("prefix",cls.pin,"owned","add","192.0.2.1/32",1)
        cls.loader("port",cls.pin,25565,1)
        cls.tmp = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
        for p in cls.pin.iterdir():
            p.unlink()
        cls.pin.rmdir()

    @classmethod
    def loader(cls,*args):
        return subprocess.run([str(ROOT/"build/xddp-loader"),*map(str,args)],check=True,capture_output=True,text=True).stdout

    def setUp(self):
        self.configure()
        self.loader("clear",self.pin,"allow")
        self.loader("clear",self.pin,"block")

    def configure(self,observe=0,lease=60,fragments=0,rate=0,burst=0):
        self.loader("config",self.pin,time.monotonic_ns()+int(lease*1e9),observe,0,1,fragments,rate,burst,1)

    def run_packet(self,data):
        path = Path(self.tmp.name)/"packet.bin"; path.write_bytes(data)
        raw = subprocess.run(["bpftool","-j","prog","run","pinned",str(self.pin/"program"),
                              "data_in",str(path),"repeat","1"],check=True,capture_output=True,text=True).stdout
        return json.loads(raw)["retval"]

    def test_valid_small_gameplay_and_flags(self):
        for n in (0,3,5,7,12,14,28,36):
            for flags in (0x10,0x18,0x11,0x04,0x14,0x02,0xc2,0x12):
                self.assertEqual(self.run_packet(tcp(flags,bytes(n))),2)

    def test_malformed(self):
        for n in (1,13,14,20,33,40,53):
            self.assertEqual(self.run_packet(tcp()[:n]),1)
        for index,value in ((14,0x44),(46,0x40),(46,0xf0),(47,3),(47,6),(47,5)):
            data = bytearray(tcp()); data[index]=value
            self.assertEqual(self.run_packet(data),1)

    def test_observe_and_stale_lease(self):
        for observe,lease in ((1,60),(0,-1)):
            self.configure(observe=observe,lease=lease)
            self.assertEqual(self.run_packet(tcp(flags=3)),2)

    def test_fragment_policy(self):
        data = bytearray(tcp()); data[20]=0x20
        self.assertEqual(self.run_packet(data),2)
        self.configure(fragments=1)
        self.assertEqual(self.run_packet(data),1)

    def test_allow_block_and_unowned(self):
        self.loader("prefix",self.pin,"block","add","198.51.100.0/24",11)
        self.assertEqual(self.run_packet(tcp()),1)
        self.loader("prefix",self.pin,"allow","add","198.51.100.7/32",1)
        self.assertEqual(self.run_packet(tcp()),2)
        self.assertEqual(self.run_packet(tcp(port=22)),2)
        data = bytearray(tcp()); data[33]=2
        self.assertEqual(self.run_packet(data),2)

    def test_icmp_udp_and_port_closure(self):
        data = bytearray(tcp()); data[23]=1
        self.assertEqual(self.run_packet(data),2)
        data = bytearray(tcp()); data[23]=17; data[17]=28; data[38:40]=b"\x00\x08"; data=data[:42]
        self.assertEqual(self.run_packet(data),2)
        self.loader("port",self.pin,25565,5)
        self.assertEqual(self.run_packet(data),1)
        self.loader("port",self.pin,25565,1)


if __name__ == "__main__":
    unittest.main()
