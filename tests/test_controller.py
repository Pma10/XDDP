import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT / "controller"))
from core import Adaptive, rates, validate


class ConfigTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
