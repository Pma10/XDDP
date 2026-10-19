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
from contextlib import contextmanager

ROOT = Path(__file__).resolve().parents[1]


def tcp(flags=0x10,payload=b"",port=25565):
    eth = bytes(12)+b"\x08\x00"
    ip = struct.pack("!BBHHHBBH4s4s",0x45,0,40+len(payload),0,0,64,6,0,
                     bytes([198,51,100,7]),bytes([192,0,2,1]))
    header = struct.pack("!HHIIBBHHH",12345,port,1,1,0x50,flags,65535,0,0)
    return eth+ip+header+payload


@unittest.skipUnless(os.environ.get("XDDP_BPF_TEST") == "1","set XDDP_BPF_TEST=1 as root on Linux")
class XDPTests(unittest.TestCase):
    def policy(self, text, check=True):
        return subprocess.run([str(ROOT/'build/xddp-loader'),'policy',str(self.pin)],
                              input=text,text=True,capture_output=True,check=check)

    def test_bulk_policy_reconciles_ports_prefixes_and_canonical_ipv6(self):
        self.configure(lease=0)
        self.policy('port 25565 1\nowned 192.0.2.1/32 1\nblock 198.51.100.7/32 11\n'
                    'allow 2001:db8::1234/64 1\n')
        self.configure()
        path=Path(self.tmp.name)/'bulk.packet'; path.write_bytes(tcp())
        self.assertEqual(json.loads(self.loader('test',self.pin,path))['retval'],1)
        self.configure(lease=0)
        self.policy('port 25565 1\nowned 192.0.2.1/32 1\n')
        self.configure()
        self.assertEqual(json.loads(self.loader('test',self.pin,path))['retval'],2)

    def test_invalid_bulk_policy_leaves_existing_maps_untouched(self):
        self.loader('prefix',self.pin,'block','add','198.51.100.7/32',11)
        for text in ('port 25565 1\nblock invalid/32 11\n',
                     'port 25565 1\nport 25565 2\n',
                     'owned 192.0.2.1/24 1\nowned 192.0.2.9/24 1\n',
                     'unknown 192.0.2.1/32 1\n',
                     'port 25565 1 extra\n', 'port 25565 1'):
            with self.subTest(text=text):
                self.assertNotEqual(self.policy(text,check=False).returncode,0)
                path=Path(self.tmp.name)/'invalid-bulk.packet'; path.write_bytes(tcp())
                self.assertEqual(json.loads(self.loader('test',self.pin,path))['retval'],1)

    def test_bulk_policy_refuses_live_lease_before_mutation(self):
        self.assertNotEqual(self.policy('port 25565 2\n',check=False).returncode,0)
        path=Path(self.tmp.name)/'live-lease.packet'; path.write_bytes(tcp())
        self.assertEqual(json.loads(self.loader('test',self.pin,path))['retval'],2)

    def test_bulk_policy_full_prefix_capacity_and_overflow_rejection(self):
        rows=''.join(f'block 198.51.{96+i//256}.{i%256}/32 11\n' for i in range(4096))
        self.configure(lease=0)
        self.policy('port 25565 1\nowned 192.0.2.1/32 1\n'+rows)
        self.configure()
        path=Path(self.tmp.name)/'capacity.packet'; path.write_bytes(tcp())
        self.assertEqual(json.loads(self.loader('test',self.pin,path))['retval'],1)
        self.assertNotEqual(self.policy(rows+'block 203.0.113.1/32 11\n',check=False).returncode,0)
        self.assertEqual(json.loads(self.loader('test',self.pin,path))['retval'],1)

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

    def configure(self,observe=0,lease=60,fragments=0,rate=0,burst=0,mode=0):
        deadline = time.monotonic_ns()+int(lease*1e9) if lease else 0
        self.loader("config",self.pin,deadline,observe,mode,1,fragments,rate,burst,2)

    @contextmanager
    def foreign_counters(self,value_size=176,map_type=6,key_size=4,entries=1):
        # Deliberately replace only a private test pin; keep the original FD
        # alive and restore it even when an assertion fails.
        import ctypes
        lib=ctypes.CDLL("libbpf.so.1",use_errno=True)
        lib.bpf_obj_get.argtypes=[ctypes.c_char_p]; lib.bpf_obj_get.restype=ctypes.c_int
        lib.bpf_obj_pin.argtypes=[ctypes.c_int,ctypes.c_char_p]; lib.bpf_obj_pin.restype=ctypes.c_int
        lib.bpf_map_create.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_uint,ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p]
        lib.bpf_map_create.restype=ctypes.c_int
        path=self.pin/"counters"; encoded=os.fsencode(path)
        original=lib.bpf_obj_get(encoded)
        self.assertGreaterEqual(original,0)
        foreign=-1
        try:
            path.unlink()
            foreign=lib.bpf_map_create(map_type,b"foreign",key_size,value_size,entries,None)
            self.assertGreaterEqual(foreign,0,f"map_create errno={ctypes.get_errno()}")
            self.assertEqual(lib.bpf_obj_pin(foreign,encoded),0)
            yield
        finally:
            path.unlink(missing_ok=True)
            restored=lib.bpf_obj_pin(original,encoded)
            os.close(original)
            if foreign>=0: os.close(foreign)
            self.assertEqual(restored,0,"could not restore test map pin")

    def test_loader_rejects_wrong_map_geometry_before_buffer_access(self):
        for kwargs in ({"value_size":256},{"map_type":2},{"map_type":1,"key_size":8},{"entries":2}):
            with self.subTest(kwargs=kwargs),self.foreign_counters(**kwargs):
                with self.assertRaises(subprocess.CalledProcessError) as failure:
                    self.loader("stats",self.pin)
                self.assertIn("incompatible pinned map counters",failure.exception.stderr)

    def test_generation_validation_rejects_foreign_compatible_map(self):
        self.assertTrue(json.loads(self.loader("validate",self.pin))["valid"])
        with self.foreign_counters():
            with self.assertRaises(subprocess.CalledProcessError) as failure:
                self.loader("validate",self.pin)
            self.assertIn("does not belong to this program",failure.exception.stderr)
        self.assertTrue(json.loads(self.loader("validate",self.pin))["valid"])

    def run_packet(self,data):
        path = Path(self.tmp.name)/"packet.bin"; path.write_bytes(data)
        try:
            raw = self.loader("test",self.pin,path)
        except subprocess.CalledProcessError as e:
            self.fail(f"BPF test run failed: {e.stderr}")
        return json.loads(raw)["retval"]

    def test_valid_small_gameplay_and_flags(self):
        for n in (0,3,5,7,12,14,28,36):
            for flags in (0x10,0x18,0x11,0x04,0x14,0x02,0xc2,0x12):
                self.assertEqual(self.run_packet(tcp(flags,bytes(n))),2)

    def test_malformed(self):
        # Kernel test-run requires >= Ethernet header; shorter fixtures run in ASan C tests.
        # Truncated L2 or IP headers without a validated destination must
        # fail open, even when enforcement is on.
        for n in (14,20,33):
            self.assertEqual(self.run_packet(tcp()[:n]),2)
        # Once the full fixed IP header identifies an owned destination,
        # malformed length and TCP fields can be enforced.
        for n in (40,53):
            self.assertEqual(self.run_packet(tcp()[:n]),1)
        for index,value in ((46,0x40),(46,0xf0),(47,3),(47,6),(47,5)):
            data = bytearray(tcp()); data[index]=value
            self.assertEqual(self.run_packet(data),1)
        bad_ihl = bytearray(tcp()); bad_ihl[14]=0x44
        self.assertEqual(self.run_packet(bad_ihl),1)
        bad_version = bytearray(tcp()); bad_version[14]=0x54
        self.assertEqual(self.run_packet(bad_version),2)

    def test_unowned_malformed_packets_never_drop_unrelated_traffic(self):
        for malformed in ("ipv4_length", "invalid_tcp", "truncated_tcp"):
            owned = bytearray(tcp())
            if malformed == "ipv4_length":
                owned[17] = 0
            elif malformed == "invalid_tcp":
                owned[47] = 3
            else:
                owned = owned[:45]
            self.assertEqual(self.run_packet(owned),1)
            other = bytearray(owned)
            other[33] = 2 # Identical malformed packet for an unowned host
            self.assertEqual(self.run_packet(other),2)
        # Without a valid fixed IP header there is no reliable destination.
        self.assertEqual(self.run_packet(tcp()[:20]),2)

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

    def test_vlan_options_ipv6_and_extension_delegation(self):
        p=tcp()
        tagged=p[:12]+b"\x81\x00\x00\x01\x08\x00"+p[14:]
        self.assertEqual(self.run_packet(tagged),2)
        double=p[:12]+b"\x88\xa8\x00\x01\x81\x00\x00\x02\x08\x00"+p[14:]
        self.assertEqual(self.run_packet(double),2)
        options=bytearray(tcp()); options[14]=0x46; options[17]=48
        options[34:34]=bytes(4); options[50]=0x60; options.extend(bytes(4))
        self.assertEqual(self.run_packet(options),2)
        import ipaddress
        src=ipaddress.IPv6Address("2001:db8::7").packed
        dst=ipaddress.IPv6Address("2001:db8::1").packed
        v6=bytes(12)+b"\x86\xdd"+struct.pack("!IHBB16s16s",6<<28,20,6,64,src,dst)+p[34:]
        self.loader("prefix",self.pin,"owned","add","2001:db8::1/128",1)
        self.assertEqual(self.run_packet(v6),2)
        self.loader("prefix",self.pin,"block","add","2001:db8::/32",11)
        self.assertEqual(self.run_packet(v6),1)
        self.loader("prefix",self.pin,"allow","add","2001:db8::7/128",1)
        self.assertEqual(self.run_packet(v6),2)
        ext=bytearray(v6); ext[20]=0
        self.assertEqual(self.run_packet(ext),2) # explicit extension-chain deferral

    def test_emergency_freezes_only_new_syn_for_owned_game_service(self):
        # No rate/burst is configured: emergency itself must still freeze SYN.
        self.configure(mode=3, rate=0, burst=0)
        self.assertEqual(self.run_packet(tcp(flags=0x02)),1)
        for flags in (0x10,0x18,0x11,0x12,0x04):
            self.assertEqual(self.run_packet(tcp(flags=flags,payload=b"play")),2)
        self.assertEqual(self.run_packet(tcp(flags=0x02,port=25566)),2)
        outside = bytearray(tcp(flags=0x02))
        outside[30:34] = bytes([192,0,2,2])  # Destination outside owned /32.
        self.assertEqual(self.run_packet(outside),2)
        self.loader("prefix",self.pin,"allow","add","198.51.100.7/32",1)
        self.assertEqual(self.run_packet(tcp(flags=0x02)),1)
        self.assertEqual(self.run_packet(tcp(flags=0x18)),2)
        stats=json.loads(self.loader("stats",self.pin))
        self.assertGreater(stats["candidate_reasons"]["emergency_syn"],0)

    def test_emergency_observation_and_expired_lease_fail_open(self):
        for observe,lease in ((1,60),(0,-1)):
            with self.subTest(observe=observe,lease=lease):
                self.configure(mode=3,observe=observe,lease=lease)
                self.assertEqual(self.run_packet(tcp(flags=0x02)),2)
                self.assertEqual(self.run_packet(tcp(flags=0x18)),2)

    def test_malformed_ipv6_only_enforced_for_owned_enabled_destination(self):
        import ipaddress
        src = ipaddress.IPv6Address("2001:db8::7").packed
        owned = ipaddress.IPv6Address("2001:db8::10").packed
        foreign = ipaddress.IPv6Address("2001:db8::11").packed
        # Payload length claims more bytes than the frame contains; the fixed
        # 40-byte IPv6 header still gives us a trustworthy destination key.
        raw = bytes(12) + b"\x86\xdd" + struct.pack("!IHBB16s16s",
            6 << 28, 40, 6, 64, src, owned) + tcp()[34:]
        self.loader("prefix", self.pin, "owned", "add", "2001:db8::10/128", 1)
        self.assertEqual(self.run_packet(raw), 1)
        other = bytearray(raw)
        other[38:54] = foreign
        self.assertEqual(self.run_packet(other), 2)
        self.loader("config",self.pin,time.monotonic_ns()+int(60e9),0,0,0,0,0,0,2)
        self.assertEqual(self.run_packet(raw),2)
        self.configure()

    def test_syn_budget_exempts_ack_and_has_no_dynamic_source_map(self):
        self.configure(rate=1,burst=1)
        results=[self.run_packet(tcp(flags=2)) for _ in range(32)]
        self.assertIn(1,results)
        for _ in range(8):
            self.assertEqual(self.run_packet(tcp(flags=0x18,payload=b"abc")),2)
        stats=json.loads(self.loader("stats",self.pin))
        self.assertGreater(stats["candidate_reasons"]["syn_rate"],0)
        self.assertEqual(set(p.name for p in self.pin.iterdir()),
                         {"configuration","counters","syn_budget","ports","owned","allow","block","program"})

    def test_reconnect_burst_and_exhaustion_leave_existing_tcp_untouched(self):
        # A packet fixture, not a real-player capacity or latency certification.
        self.configure(rate=128,burst=512)
        for _ in range(120):
            self.assertEqual(self.run_packet(tcp(flags=2)),2)
        self.configure(rate=1,burst=1)
        self.assertIn(1,[self.run_packet(tcp(flags=2)) for _ in range(64)])
        for flags in (0x10,0x18,0x11,0x14,0x12,0x04):
            self.assertEqual(self.run_packet(tcp(flags=flags)),2)


if __name__ == "__main__":
    unittest.main()
