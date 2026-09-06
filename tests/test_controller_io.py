import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"controller"))


@unittest.skipUnless(sys.platform.startswith("linux"),"Linux controller uses fcntl/AF_UNIX")
class ControllerIOTests(unittest.TestCase):
    def setUp(self):
        from ddosctl import Controller
        self.tmp=tempfile.TemporaryDirectory()
        cfg=json.loads((ROOT/"config/controller.json").read_text())
        self.config_path=Path(self.tmp.name)/"controller.json"
        cfg["runtime_file"]=str(Path(self.tmp.name)/"runtime.json")
        cfg["metrics_file"]=str(Path(self.tmp.name)/"metrics.prom")
        cfg["socket"]=str(Path(self.tmp.name)/"control.sock")
        self.config_path.write_text(json.dumps(cfg))
        self.controller=Controller(cfg,str(self.config_path)); self.calls=[]
        def loader(*args):
            self.calls.append(args)
            return {}
        self.controller.loader=loader

    def tearDown(self):
        self.tmp.cleanup()

    def test_mode_and_observe_are_separate_persisted_controls(self):
        self.controller.command(["mode","attack"])
        cfg=json.loads(self.config_path.read_text())
        self.assertEqual(cfg["manual_mode"],"attack"); self.assertTrue(cfg["observe"])
        self.controller.command(["observe","off"])
        runtime=json.loads(Path(cfg["runtime_file"]).read_text())
        self.assertEqual(runtime["mode"],2); self.assertFalse(runtime["observe"])
        self.assertTrue(any(call[0]=="config" and call[2]==0 for call in self.calls))

    def test_acl_command_updates_kernel_and_gate(self):
        self.controller.command(["block","198.51.100.7/24"])
        c=self.controller.cfg
        self.assertEqual(c["block_prefixes"],["198.51.100.0/24"])
        self.assertIn(("prefix",c["pin_dir"],"block","add","198.51.100.0/24",11),self.calls)
        runtime=json.loads(Path(c["runtime_file"]).read_text())
        self.assertEqual(runtime["block"],c["block_prefixes"])
        self.controller.command(["unblock","198.51.100.1/24"])
        self.assertEqual(self.controller.cfg["block_prefixes"],[])

    def test_failed_map_update_does_not_persist_or_renew_lease(self):
        original=self.config_path.read_text()
        def failing(*args):
            self.calls.append(args)
            if args[0]=="prefix":
                raise subprocess.CalledProcessError(1,args)
            return {}
        self.controller.loader=failing
        with self.assertRaises(subprocess.CalledProcessError):
            self.controller.command(["block","198.51.100.0/24"])
        self.assertEqual(self.config_path.read_text(),original)
        self.assertTrue(self.controller.stopping)
        self.assertEqual(self.calls[0][0],"config"); self.assertEqual(self.calls[0][2],0)

    def test_publication_failure_stops_instead_of_resuming_next_tick(self):
        with patch.object(self.controller,"publish",side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.controller.command(["mode","attack"])
        self.assertTrue(self.controller.stopping)
        self.assertEqual([c[2] for c in self.calls if c[0]=="config"],[0])

    def test_expire_and_renew_failures_both_stop_controller(self):
        for failed_call in (1,2):
            self.controller.stopping=False
            def lease_call(*args):
                self.calls.append(args)
                if args[0]=="config" and len(self.calls)==failed_call:
                    raise subprocess.CalledProcessError(1,args)
                return {}
            self.calls.clear(); self.controller.loader=lease_call
            with self.subTest(failed_call=failed_call),self.assertRaises(subprocess.CalledProcessError):
                self.controller.command(["mode","attack"])
            self.assertTrue(self.controller.stopping)

    def test_cleanup_attempts_kernel_expiry_and_socket_unlink_despite_publish_error(self):
        sock=Path(self.controller.cfg["socket"]); sock.touch()
        with patch.object(self.controller,"publish",side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.controller.cleanup()
        self.assertFalse(sock.exists())
        self.assertEqual(self.calls[-1][0],"config"); self.assertEqual(self.calls[-1][2],0)

    def test_attach_checks_complete_generation_before_network_mutation(self):
        self.controller.command(["xdp","attach"])
        self.assertEqual(self.calls[0],("validate",self.controller.cfg["pin_dir"]))
        self.assertEqual(self.calls[1][0],"attach")

    def test_invalid_generation_prevents_reconciliation_and_attach(self):
        pin=Path(self.tmp.name)/"pins"; pin.mkdir(); (pin/"program").touch()
        self.controller.cfg["pin_dir"]=str(pin)
        def invalid(*args):
            self.calls.append(args)
            raise subprocess.CalledProcessError(2,args)
        self.controller.loader=invalid
        for action in (self.controller.prepare,lambda:self.controller.command(["xdp","attach"])):
            self.calls.clear()
            with self.assertRaises(subprocess.CalledProcessError): action()
            self.assertEqual(len(self.calls),1)
            self.assertEqual(self.calls[0][0],"validate")


if __name__ == "__main__":
    unittest.main()
