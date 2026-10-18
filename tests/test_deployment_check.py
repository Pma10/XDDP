import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("deployment_check", ROOT / "scripts/deployment_check.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class DeploymentCheckTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / "config/controller.json").read_text())
        self.status = dict(mode="normal", observe=True, gate_metrics_available=True,
                           gate_runtime_generation=123)

    def test_active_services_with_default_policy_are_not_armed(self):
        result = CHECK.inspect(self.config, self.status, {"program_id": 0})
        self.assertEqual(result["warnings"], ["xdp_not_attached", "observation_or_unknown_mode",
                         "no_owned_destinations", "syn_shaping_disabled_in_current_mode"])

    def test_missing_status_is_not_success(self):
        result = CHECK.inspect(self.config, {}, {})
        self.assertIn("xdp_not_attached", result["warnings"])
        self.assertIn("observation_or_unknown_mode", result["warnings"])
        self.assertIn("gate_metrics_unavailable", result["warnings"])
        self.assertIn("gate_runtime_policy_missing_or_expired", result["warnings"])

    def test_current_mode_budget_not_another_mode(self):
        self.config["syn_per_cpu"]["attack"] = dict(rate=100, burst=200)
        result = CHECK.inspect(self.config, self.status, {"program_id": 4})
        self.assertIn("syn_shaping_disabled_in_current_mode", result["warnings"])

    def test_lagging_generation_is_not_an_expired_policy(self):
        self.config["owned_prefixes"] = ["192.0.2.1/32"]
        self.config["syn_per_cpu"]["normal"] = dict(rate=100, burst=200)
        self.status.update(observe=False, published_generation=124)
        original = copy.deepcopy(self.config)
        result = CHECK.inspect(self.config, self.status, {"program_id": 4})
        self.assertEqual(result["warnings"], [])
        self.assertEqual(self.config, original)
        self.assertIn("require verification", result["note"])

    def test_strict_exit_status_and_read_only_commands(self):
        with patch.object(CHECK, "query", side_effect=[self.config, self.status, {"program_id":0}]) as query, patch("builtins.print"):
            self.assertEqual(CHECK.main(["--require-enforcement"]), 1)
        self.assertEqual([c.args[1] for c in query.call_args_list],
                         [["config", "show"], ["status"], ["xdp", "status"]])

    def test_failed_queries_return_unknown_without_leaking_output(self):
        error = subprocess.CalledProcessError(1, ["ddosctl"], output="sensitive diagnostic")
        with patch.object(CHECK, "query", side_effect=error), patch("builtins.print") as output:
            self.assertEqual(CHECK.main([]), 2)
        self.assertNotIn("sensitive diagnostic", output.call_args.args[0])

    def test_query_is_bounded_and_uses_no_shell(self):
        with patch.object(CHECK.subprocess, "run") as run:
            run.return_value.stdout = '{"program_id":0}'
            self.assertEqual(CHECK.query("/usr/local/sbin/ddosctl", ["xdp","status"]), {"program_id":0})
        self.assertEqual(run.call_args.args[0], ["/usr/local/sbin/ddosctl","xdp","status"])
        self.assertEqual(run.call_args.kwargs["timeout"], 12)
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_failed_check_replaces_old_success_in_textfile(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"xddp-deployment.prom"
            report=CHECK.inspect(self.config,self.status,{"program_id":42})
            CHECK.write_textfile(path,report)
            self.assertIn("xddp_deployment_xdp_attached 1\n",path.read_text())
            with patch.object(CHECK,"query",side_effect=OSError()), patch("builtins.print"):
                self.assertEqual(CHECK.main(["--textfile",str(path)]),2)
            text=path.read_text()
            self.assertIn("xddp_deployment_check_success 0\n",text)
            self.assertNotIn("xddp_deployment_xdp_attached",text)
            self.assertEqual(list(Path(directory).iterdir()),[path])

    def test_invalid_runtime_generation_is_not_a_valid_policy(self):
        for generation in (None,0,False,"123"):
            self.status["gate_runtime_generation"]=generation
            with self.subTest(generation=generation):
                result=CHECK.inspect(self.config,self.status,{"program_id":42})
                self.assertIn("gate_runtime_policy_missing_or_expired",result["warnings"])

    def test_textfile_refuses_non_numeric_configuration_content(self):
        report=CHECK.inspect(self.config,self.status,{"program_id":42})
        report["syn_rate_per_cpu"]="0\ninjected_metric 1"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError): CHECK.write_textfile(Path(directory)/"m.prom",report)
            self.assertEqual(list(Path(directory).iterdir()),[])


if __name__ == "__main__":
    unittest.main()
