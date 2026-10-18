"""Guarded automatic FREEZE and stage-by-stage XDP v2 reopening."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controller"))
from core import Adaptive, validate
from ddosctl import Controller

def profile():
    cfg = json.loads((ROOT / "config/controller-pressure.observe.json").read_text())
    cfg["adaptive"]["allow_emergency"] = True
    cfg["adaptive"]["required_signals"] = {
        "emergency": ["syn_per_second", "conntrack_percent"]
    }
    cfg["adaptive"]["thresholds"]["emergency"] = {
        "syn_per_second": {"enter": 50, "exit": 20},
        "conntrack_percent": {"enter": 85, "exit": 55}
    }
    cfg["adaptive"]["up_samples"] = 2
    cfg["adaptive"]["down_samples"] = 2
    cfg["adaptive"]["cooldown_seconds"] = 3
    cfg["adaptive"]["up_cooldown_seconds"] = 0
    cfg["adaptive"]["recovery"]["enabled"] = True
    cfg["adaptive"]["recovery"]["stages"] = [
        {"seconds": 5, "rate": 8, "burst": 16},
        {"seconds": 6, "rate": 32, "burst": 64}
    ]
    validate(cfg)
    return cfg

HIGH = {"syn_per_second": 100, "conntrack_percent": 90}
LOW = {"syn_per_second": 1, "conntrack_percent": 1,
       "conntrack_projected_percent": 1, "conntrack_drops_per_second": 0,
       "listen_overflows_per_second": 0}

class RecoveryProbeTests(unittest.TestCase):
    def test_freeze_probe_ramp_and_normal_recovery(self):
        cfg = profile()
        a = Adaptive(cfg["adaptive"], 0)
        budgets = cfg["syn_per_cpu"]
        self.assertEqual(a.sample(HIGH, 1), 0)
        self.assertEqual(a.sample(HIGH, 2), 3)
        self.assertEqual(a.recovery_stage(), 0)
        self.assertEqual(a.sample({}, 3), 3)
        self.assertEqual(a.sample(LOW, 4), 3)
        self.assertEqual(a.sample(LOW, 5), 2)
        self.assertEqual(a.recovery_stage(), 1)
        self.assertEqual(a.syn_budget(budgets), {"rate": 8, "burst": 16})
        for t in range(6, 10):
            self.assertEqual(a.sample(LOW, t), 2)
            self.assertEqual(a.recovery_stage(), 1)
        self.assertEqual(a.sample(LOW, 10), 2)
        self.assertEqual(a.recovery_stage(), 2)
        self.assertEqual(a.syn_budget(budgets), {"rate": 32, "burst": 64})
        for t in range(11, 16):
            self.assertEqual(a.sample(LOW, t), 2)
        self.assertEqual(a.sample(LOW, 16), 2)
        self.assertEqual(a.recovery_stage(), 0)
        self.assertEqual(a.syn_budget(budgets), budgets["attack"])
        self.assertEqual(a.sample(LOW, 17), 2)
        self.assertEqual(a.sample(LOW, 18), 1)

    def test_pressure_and_missing_telemetry_reset_probe(self):
        cfg = profile()
        a = Adaptive(cfg["adaptive"], 0)
        a.sample(HIGH, 1)
        a.sample(HIGH, 2)
        a.sample(LOW, 4)
        a.sample(LOW, 5)
        a.sample(LOW, 10)
        self.assertEqual(a.recovery_stage(), 2)
        a.sample({"conntrack_percent": 10}, 11)
        self.assertEqual(a.recovery_stage(), 1)
        a.sample(LOW, 15)
        self.assertEqual(a.recovery_stage(), 1)
        a.sample(LOW, 16)
        self.assertEqual(a.recovery_stage(), 2)

    def test_renewed_severe_attack_refreezes(self):
        cfg = profile()
        a = Adaptive(cfg["adaptive"], 0)
        a.sample(HIGH, 1)
        a.sample(HIGH, 2)
        a.sample(LOW, 4)
        a.sample(LOW, 5)
        self.assertEqual(a.recovery_stage(), 1)
        self.assertEqual(a.sample(HIGH, 6), 2)
        self.assertEqual(a.sample(HIGH, 7), 3)
        self.assertEqual(a.recovery_stage(), 0)

    def test_validation_rejects_unsafe_recovery_stages(self):
        for mutation in [
            lambda c: c["adaptive"]["recovery"].update(enabled="yes"),
            lambda c: c["adaptive"]["recovery"].update(stages=[]),
            lambda c: c["adaptive"]["recovery"]["stages"][0].update(rate=0),
            lambda c: c["adaptive"]["recovery"]["stages"][0].update(burst=0),
            lambda c: c["adaptive"]["recovery"]["stages"][0].update(seconds=-1),
            lambda c: c["adaptive"]["recovery"]["stages"][0].update(rate=256),
            lambda c: c["adaptive"]["recovery"]["stages"][1].update(rate=4),
            lambda c: c["adaptive"]["recovery"]["stages"][1].update(burst=8),
            lambda c: c["adaptive"]["recovery"].update(unknown=1),
            lambda c: c["adaptive"].update(allow_emergency=False),
            lambda c: c["adaptive"]["thresholds"].update(attack={}),
        ]:
            c = profile()
            mutation(c)
            with self.subTest(adaptive=c["adaptive"]), self.assertRaises(ValueError):
                validate(c)

    def test_default_policy_backward_compatible(self):
        cfg = json.loads((ROOT / "config/controller.json").read_text())
        self.assertNotIn("recovery", cfg["adaptive"])
        validate(cfg)
        self.assertEqual(Adaptive(cfg["adaptive"], 0).recovery_stage(), 0)

    def test_controller_uses_probe_budget_without_gate_restart_or_abi_change(self):
        cfg = profile()
        with tempfile.TemporaryDirectory() as tmp:
            cfg["runtime_file"] = tmp + "/runtime.json"
            cfg["metrics_file"] = tmp + "/metrics.prom"
            cfg["socket"] = tmp + "/control.sock"
            c = Controller(cfg, tmp + "/config.json")
            calls = []
            c.loader = lambda *args: calls.append(args) or {}
            c.mode = c.adaptive.mode = 2
            c.adaptive.recovery_index = 0
            c.lease()
            self.assertEqual(calls[-1][0], "config")
            self.assertEqual(calls[-1][4], 2)
            self.assertEqual(calls[-1][7:9], (8, 16))
            self.assertEqual(calls[-1][9], 2)
            self.assertEqual(c.command(["status"])["recovery_stage"], 1)
            self.assertEqual(c.command(["status"])["configured_syn_per_cpu"], {"rate": 8, "burst": 16})
            c.cfg["manual_mode"] = "attack"
            c.lease()
            self.assertEqual(calls[-1][7:9], (128, 512))
            self.assertEqual(c.command(["status"])["recovery_stage"], 0)

if __name__ == "__main__":
    unittest.main()
