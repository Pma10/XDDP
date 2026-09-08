import copy
import json
from pathlib import Path
import sys
import unittest
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT / "controller"))
from core import Adaptive, rates, validate, host_pressure


class ConfigTests(unittest.TestCase):
    def test_conntrack_pressure_missing_invalid_and_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.assertEqual(host_pressure(root),{})
            (root/"nf_conntrack_count").write_text("75\n")
            (root/"nf_conntrack_max").write_text("100\n")
            self.assertEqual(host_pressure(root),{"conntrack_percent":75})
            (root/"nf_conntrack_max").write_text("0\n")
            self.assertEqual(host_pressure(root),{})
            (root/"nf_conntrack_max").write_text("9"*65)
            self.assertEqual(host_pressure(root),{})
    def setUp(self):
        self.cfg = json.loads((ROOT / "config/controller.json").read_text())

    def test_observe_defaults(self):
        validate(self.cfg)
        self.assertTrue(self.cfg["observe"])
        self.assertEqual(self.cfg["owned_prefixes"],[])
        self.assertTrue(all(x["rate"] == 0 for x in self.cfg["syn_per_cpu"].values()))

    def test_invalid_configs(self):
        mutations = [lambda c:c.update(observe="false"),lambda c:c.update(interface="docker0"),
                     lambda c:c.update(drop_tcp_ports=[25565]),lambda c:c.update(pin_dir="/sys/fs/bpf/../x"),
                     lambda c:c.update(gate_metrics="http://example.com/metrics"),
                     lambda c:c["syn_per_cpu"]["attack"].update(rate=10,burst=0),
                     lambda c:c["syn_per_cpu"]["attack"].update(rate=float("nan")),
                     lambda c:c["adaptive"]["thresholds"]["attack"].update(pps={"enter":5,"exit":8})]
        for mutate in mutations:
            c = copy.deepcopy(self.cfg); mutate(c)
            with self.subTest(c=c),self.assertRaises(ValueError):
                validate(c)

    def test_cidr_canonicalization(self):
        self.cfg["allow_prefixes"] = ["192.0.2.7/24","192.0.2.0/24"]
        self.assertEqual(validate(self.cfg)["allow_prefixes"],["192.0.2.0/24"])

    def test_required_signals_reject_typos_and_wrong_types(self):
        for guards in ({"attack":["active_prelogin"]}, {"unknown":[]}, {"attack":"pps"}, {"attack":[{}]}):
            cfg=copy.deepcopy(self.cfg)
            cfg["adaptive"]["required_signals"]=guards
            with self.subTest(guards=guards), self.assertRaises(ValueError): validate(cfg)
        self.cfg["adaptive"]["allow_emergency"]="false"
        with self.assertRaises(ValueError): validate(self.cfg)


class ModeTests(unittest.TestCase):
    def setUp(self):
        self.cfg = dict(up_samples=2,down_samples=3,cooldown_seconds=5,thresholds={
            "elevated":{"pps":{"enter":100,"exit":50}},
            "attack":{"pps":{"enter":200,"exit":100}},
            "emergency":{"active_prelogin":{"enter":10,"exit":5}}})

    def test_hysteresis_cooldown_and_missing_metrics(self):
        a = Adaptive(self.cfg,0)
        self.assertEqual(a.sample({"pps":250},1),0)
        self.assertEqual(a.sample({"pps":250},2),0)
        self.assertEqual(a.sample({"pps":250},5),2)
        for i in range(6,20):
            self.assertEqual(a.sample({},i),2)
        self.assertEqual(a.sample({"pps":90},20),2)
        self.assertEqual(a.sample({"pps":90},21),2)
        self.assertEqual(a.sample({"pps":90},22),1)

    def test_empty_thresholds_never_escalate(self):
        self.cfg["thresholds"] = {k:{} for k in self.cfg["thresholds"]}
        a = Adaptive(self.cfg,0)
        for i in range(100):
            self.assertEqual(a.sample({"pps":1e9},i),0)

    def test_counter_resets_are_not_attacks(self):
        self.assertEqual(rates({"rx_packets":100},{"rx_packets":1},1),{})
        self.assertEqual(rates({"rx_bytes":100},{"rx_bytes":200},2),{"bps":400})
        self.assertEqual(rates({}, {"rx_packets":100},1),{})

    def test_traffic_spike_requires_configured_pressure_and_emergency_opt_in(self):
        self.cfg["thresholds"]["attack"]["active_prelogin"]={"enter":8,"exit":4}
        self.cfg["required_signals"]={"attack":["pps","active_prelogin"]}
        a=Adaptive(self.cfg,0)
        for t in range(1,20): self.assertLessEqual(a.sample({"pps":1000},t),1)
        a.sample({"pps":1000,"active_prelogin":9},20)
        self.assertEqual(a.sample({"pps":1000,"active_prelogin":9},21),2)
        for t in range(22,30): self.assertEqual(a.sample({"pps":1000,"active_prelogin":100},t),2)
        self.cfg["allow_emergency"]=True
        a.sample({"active_prelogin":100},30)
        self.assertEqual(a.sample({"active_prelogin":100},31),3)

    def test_pressure_gauges_and_failure_rates(self):
        self.assertEqual(rates({"backend_connect_failures":4,"resource_limited":2},
            {"backend_connect_failures":8,"resource_limited":8,"active_status":3,"backend_connections":9},2),
            {"backend_failures_per_second":2,"resource_limited_per_second":3,"active_status":3,"backend_connections":9})


if __name__ == "__main__":
    unittest.main()
