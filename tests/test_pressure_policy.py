import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controller"))
from core import Adaptive, host_network_counters, rates, validate

SPEC = importlib.util.spec_from_file_location("replay_pressure", ROOT / "scripts/replay_pressure.py")
REPLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPLAY)


class PressureTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / "config/controller-pressure.observe.json").read_text())

    def test_profile_is_observation_only_and_has_no_owned_environment(self):
        validate(self.config)
        self.assertTrue(self.config["observe"])
        self.assertEqual(self.config["owned_prefixes"], [])
        self.assertFalse(self.config["adaptive"]["allow_emergency"])

    def test_hex_per_cpu_drop_and_decimal_tcp_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "stat").mkdir()
            (root / "stat/nf_conntrack").write_text("entries drop early_drop\n00000040 0000000a 00000002\n00000040 00000004 00000003\n")
            (root / "netstat").write_text("TcpExt: ListenDrops SyncookiesSent ListenOverflows Other\nTcpExt: 9 20 8 999\n")
            self.assertEqual(host_network_counters(root), {"host_conntrack_drop_total":14,
                "host_listen_drop_total":9,"host_syncookies_sent_total":20,"host_listen_overflow_total":8})
            # Entries is a repeated host gauge in this proc file, never a sum.
            self.assertNotIn("conntrack_entries", host_network_counters(root))

    def test_missing_truncated_invalid_and_oversized_telemetry_stays_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(host_network_counters(root), {})
            (root / "stat").mkdir()
            for text in ("", "drop drop\n01 01\n", "entries drop\n01\n", "entries drop\n01 -1\n", "x"*262145):
                (root / "stat/nf_conntrack").write_text(text)
                (root / "netstat").write_text("TcpExt: ListenOverflows\nTcpExt:\n")
                with self.subTest(text=text[:40]): self.assertEqual(host_network_counters(root), {})

    def test_one_missing_source_does_not_discard_the_other(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/"netstat").write_text("TcpExt: ListenOverflows\nTcpExt: 3\n")
            self.assertEqual(host_network_counters(root), {"host_listen_overflow_total":3})

    def test_predicts_ten_second_headroom_without_syn_telemetry(self):
        result = rates({"conntrack_entries":10,"conntrack_limit":1000},
                       {"conntrack_entries":400,"conntrack_limit":1000,"conntrack_percent":40},10)
        self.assertEqual(result["conntrack_growth_per_second"],39)
        self.assertEqual(result["conntrack_projected_percent"],79)
        adaptive=Adaptive(self.config["adaptive"],0)
        for t in (1,2): self.assertEqual(adaptive.sample(result,t),0)
        self.assertEqual(adaptive.sample(result,3),1)

    def test_changed_limit_and_missing_gauge_do_not_fabricate_prediction(self):
        previous={"conntrack_entries":100,"conntrack_limit":1000}
        for current in ({"conntrack_entries":200,"conntrack_limit":2000},{"conntrack_limit":1000}):
            self.assertNotIn("conntrack_projected_percent",rates(previous,current,1))
        self.assertEqual(rates(previous,previous,float("nan")),{})

    def test_recovery_growth_is_zero_and_resets_do_not_become_failure_rates(self):
        result=rates({"conntrack_entries":500,"conntrack_limit":1000,"host_conntrack_drop_total":20},
                     {"conntrack_entries":100,"conntrack_limit":1000,"host_conntrack_drop_total":1},1)
        self.assertEqual(result["conntrack_growth_per_second"],0)
        self.assertEqual(result["conntrack_projected_percent"],10)
        self.assertNotIn("conntrack_drops_per_second",result)

    def test_kernel_failure_immediately_promotes_and_recovery_stays_slow(self):
        adaptive=Adaptive(self.config["adaptive"],0)
        self.assertEqual(adaptive.sample({"listen_overflows_per_second":10},1),2)
        cool=dict(conntrack_percent=1,conntrack_projected_percent=1,conntrack_drops_per_second=0,listen_overflows_per_second=0)
        for t in range(2,61): self.assertEqual(adaptive.sample(cool,t),2)
        self.assertEqual(adaptive.sample(cool,61),1)

    def test_immediate_signal_cannot_bypass_guards_or_emergency_opt_in(self):
        cfg=copy.deepcopy(self.config["adaptive"])
        cfg["required_signals"]={"attack":["conntrack_percent"]}
        adaptive=Adaptive(cfg,0)
        self.assertEqual(adaptive.sample({"listen_overflows_per_second":10},1),0)
        cfg["thresholds"]["emergency"]={"listen_overflows_per_second":{"enter":1,"exit":0}}
        cfg["immediate_signals"]["emergency"]=["listen_overflows_per_second"]
        adaptive=Adaptive(cfg,0)
        self.assertEqual(adaptive.sample({"listen_overflows_per_second":10,"conntrack_percent":90},1),2)

    def test_invalid_immediate_signal_options_are_rejected(self):
        for value in ([], {"normal":[]}, {"attack":"conntrack_percent"}, {"attack":["syn_per_second"]},
                      {"attack":[{}]}, {"attack":["conntrack_percent","conntrack_percent"]}):
            cfg=copy.deepcopy(self.config)
            cfg["adaptive"]["immediate_signals"]=value
            with self.subTest(value=value), self.assertRaises(ValueError): validate(cfg)

    def test_replay_detects_failure_before_full_table_without_syn_input(self):
        samples=[{"time":0,"counters":{"conntrack_entries":10,"conntrack_limit":1000,"host_listen_overflow_total":0}},
                 {"time":15,"counters":{"conntrack_entries":400,"conntrack_limit":1000,"host_listen_overflow_total":100}},
                 {"time":30,"counters":{"conntrack_entries":1000,"conntrack_limit":1000,"host_listen_overflow_total":200}}]
        original=copy.deepcopy(samples)
        result=REPLAY.replay(self.config,samples)
        self.assertEqual(result["first_attack_time"],15)
        self.assertEqual(samples,original)
        self.assertTrue(result["observe"])

    def test_quiet_reconnect_burst_does_not_trigger_pressure_policy(self):
        samples=[{"time":t,"counters":{"conntrack_entries":100+(120 if t>=1 else 0),"conntrack_limit":10000,
                  "host_conntrack_drop_total":9999,"host_listen_overflow_total":10000}} for t in range(10)]
        self.assertIsNone(REPLAY.replay(self.config,samples)["first_attack_time"])

    def test_replay_rejects_out_of_order_and_unknown_counter_input(self):
        for samples in ([{"time":1,"counters":{}},{"time":1,"counters":{}}],
                        [{"time":0,"counters":{"unexpected":1}}],
                        [{"time":0,"counters":{"syn_packets":True}}]):
            with self.subTest(samples=samples), self.assertRaises(ValueError): REPLAY.replay(self.config,samples)


if __name__ == "__main__":
    unittest.main()
