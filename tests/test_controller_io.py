import copy
import http.client
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
    def test_prepare_sends_one_bulk_policy_and_manual_blocks_override_bogons(self):
        pin=Path(self.tmp.name)/'pins'; pin.mkdir(); (pin/'program').touch()
        self.controller.cfg.update(pin_dir=str(pin),
            allow_prefixes=[f'198.51.{i//256}.{i%256}/32' for i in range(1000)],
            bogon_prefixes=['192.0.2.0/24'], block_prefixes=['192.0.2.0/24'])
        with patch.object(self.controller, 'loader', return_value={}) as loader:
            self.controller.prepare()
        self.assertEqual([c.args[0] for c in loader.call_args_list], ['validate','config','policy'])
        policy=loader.call_args.kwargs['input']
        self.assertEqual(policy.count('allow '), 1000)
        self.assertIn('block 192.0.2.0/24 11\n',policy)
        self.assertNotIn('block 192.0.2.0/24 5\n',policy)
        self.assertIn('port 25565 1\n',policy)

    def test_stats_failure_preserves_attack_lease_and_recovers_without_rate_spike(self):
        from core import Adaptive
        cfg=json.loads((ROOT/'config/controller-pressure.observe.json').read_text())
        self.controller.adaptive=Adaptive(cfg['adaptive'],0)
        self.controller.adaptive.mode=self.controller.mode=2
        self.controller.cfg['manual_mode']='auto'
        self.controller.previous={'syn_packets':100}
        samples=iter([subprocess.TimeoutExpired('stats',0.5),
                      {'syn_packets':100000,'candidate_reasons':{}},
                      {'syn_packets':100002,'candidate_reasons':{}}])
        def loader(*args):
            self.calls.append(args)
            if args[0]=='stats':
                result=next(samples)
                if isinstance(result,Exception): raise result
                return result
            if args[0]=='status': return {'program_id':42}
            return {}
        self.controller.loader=loader
        with patch('ddosctl.host_pressure',return_value={}), \
             patch('ddosctl.host_network_counters',return_value={}), \
             patch.object(self.controller,'gate_counters',side_effect=http.client.IncompleteRead(b'')), \
             patch('ddosctl.time.monotonic',side_effect=[10.,11.,12.]):
            self.controller.tick()
            self.assertEqual(self.controller.mode,2)
            self.assertFalse(self.controller.command(['status'])['xdp_stats_available'])
            self.assertNotIn('syn_per_second',self.controller.signals)
            self.controller.tick()
            self.assertNotIn('syn_per_second',self.controller.signals)
            self.controller.tick()
        self.assertEqual(self.controller.signals['syn_per_second'],2)
        self.assertEqual(self.controller.telemetry_errors,4)
        self.assertEqual(len([c for c in self.calls if c[0]=='config']),3)
        self.assertFalse(self.controller.stopping)

    def test_metrics_write_error_isolated_but_runtime_write_is_fatal(self):
        from ddosctl import atomic
        def loader(*args):
            self.calls.append(args)
            return {'candidate_reasons':{}} if args[0]=='stats' else {}
        self.controller.loader=loader
        def write(path,*args):
            if path==self.controller.cfg['metrics_file']: raise OSError('disk full')
            return atomic(path,*args)
        with patch('ddosctl.atomic',side_effect=write), \
             patch.object(self.controller,'gate_counters',return_value={}), patch('ddosctl.sys.stderr'):
            self.controller.tick()
        self.assertEqual(self.controller.metrics_errors,1)
        self.assertEqual(self.calls[-1][0],'config')
        with patch.object(self.controller,'publish',side_effect=OSError('runtime unavailable')), \
             patch.object(self.controller,'gate_counters',return_value={}):
            with self.assertRaises(OSError): self.controller.tick()

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

    def test_status_reports_configured_syn_policy_without_claiming_attachment(self):
        self.controller.cfg["owned_prefixes"]=["192.0.2.1/32"]
        self.controller.cfg["syn_per_cpu"]["attack"]={"rate":100,"burst":200}
        self.controller.mode=2
        state=self.controller.command(["status"])
        self.assertEqual(state["configured_syn_per_cpu"],{"rate":100,"burst":200})
        self.assertEqual(state["configured_owned_prefixes"],1)
        self.assertEqual(state["configured_protected_tcp_ports"],[25565])
        self.assertTrue(state["observe"])

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

    def test_oversized_policy_is_rejected_before_maps_or_persistence(self):
        cfg=self.controller.cfg
        cfg["allow_prefixes"]=[f"2001:db8:1234:5678:9abc:def0:1234:{0x1000+i:x}/128" for i in range(3000)]
        cfg["block_prefixes"]=[f"2001:db8:2345:6789:abcd:ef01:2345:{0x2000+i:x}/128" for i in range(3000)]
        original=self.config_path.read_text()
        with self.assertRaisesRegex(ValueError,"256 KiB"):
            self.controller.command(["mode","attack"])
        self.assertEqual(self.calls,[])
        self.assertEqual(self.config_path.read_text(),original)
        self.assertFalse(self.controller.stopping)

    def test_stats_contain_gate_counters_without_overwriting_xdp_metrics(self):
        def fake_loader(*args):
            self.calls.append(args)
            if args[0] == "stats":
                return {"candidate_reasons": {}, "rx_packets": 42}
            return {}
        self.controller.loader = fake_loader
        self.controller.history.path = None
        with patch.object(self.controller, "gate_counters", return_value={
            "tcp_accepts": 9001, "runtime_generation": 15}):
            self.controller.tick()
        stats = self.controller.command(["stats"])
        self.assertEqual(stats["rx_packets"], 42)
        self.assertEqual(stats["gate_counters"]["tcp_accepts"], 9001)
        self.assertTrue(stats["gate_metrics_available"])
        self.assertEqual(stats["gate_runtime_generation"], 15)

    def test_history_disk_error_does_not_interrupt_policy_lease(self):
        def fake_loader(*args):
            self.calls.append(args)
            if args[0] == "stats":
                return {"candidate_reasons": {}, "rx_packets": 100}
            return {}
        self.controller.loader = fake_loader
        with patch.object(self.controller, "gate_counters", return_value={}), \
             patch.object(self.controller.history, "record", side_effect=OSError("disk full")), \
             patch("ddosctl.sys.stderr"):
            self.controller.tick()
        self.assertEqual(self.controller.history_errors, 1)
        self.assertTrue(any(call[0] == "config" for call in self.calls))
        self.assertTrue(Path(self.controller.cfg["metrics_file"]).exists())
        self.assertFalse(self.controller.stopping)

    def test_runtime_generation_metric_keeps_full_integer_precision(self):
        generation=18446744073709551000
        with patch("ddosctl.urllib.request.build_opener") as build:
            build.return_value.open.return_value.__enter__.return_value.read.return_value=(
                f"xddp_gate_runtime_generation {generation}\nxddp_gate_average_prelogin_duration_seconds 0.1\n").encode()
            counters=self.controller.gate_counters()
        self.assertEqual(counters["runtime_generation"],generation)
        self.assertIsInstance(counters["runtime_generation"],int)
        self.assertEqual(counters["average_prelogin_duration_seconds"],0.1)

    def test_attachment_metrics_and_unknown_do_not_block_lease_renewal(self):
        for attachment, expected in (({"program_id":0},0),({"program_id":42},1),({},-1)):
            def loader(*args):
                self.calls.append(args)
                if args[0]=="stats": return {"candidate_reasons":{}}
                if args[0]=="status": return attachment
                return {}
            self.controller.loader=loader
            with self.subTest(attachment=attachment), patch.object(self.controller,"gate_counters",return_value={}):
                self.controller.tick()
                text=Path(self.controller.cfg["metrics_file"]).read_text()
                self.assertIn(f"xddp_xdp_attached {expected}\n",text)
                self.assertIn("xddp_xdp_owned_destination_count 0\n",text)
                self.assertEqual(self.calls[-1][0],"config")
                self.assertEqual(self.controller.command(["status"])["xdp_attached"],expected)

    def test_attachment_query_failure_is_unknown_not_no_traffic(self):
        def loader(*args):
            if args[0]=="stats": return {"candidate_reasons":{}}
            if args[0]=="status": raise subprocess.CalledProcessError(1,args)
            self.calls.append(args)
            return {}
        self.controller.loader=loader
        with patch.object(self.controller,"gate_counters",return_value={}): self.controller.tick()
        self.assertEqual(self.controller.snapshot["attached"],-1)
        self.assertEqual(self.calls[-1][0],"config")

    def test_kernel_queue_failure_selects_attack_syn_budget_without_syn_signal(self):
        from core import Adaptive
        profile=json.loads((ROOT/"config/controller-pressure.observe.json").read_text())
        self.controller.cfg.update(adaptive=profile["adaptive"],syn_per_cpu=profile["syn_per_cpu"],manual_mode="auto")
        self.controller.adaptive=Adaptive(profile["adaptive"],0)
        def loader(*args):
            self.calls.append(args)
            if args[0]=="stats": return {"candidate_reasons":{}}
            if args[0]=="status": return {"program_id":42}
            return {}
        self.controller.loader=loader
        with patch("ddosctl.time.monotonic",side_effect=[100.,101.]), \
             patch("ddosctl.host_pressure",return_value={"conntrack_entries":400,"conntrack_limit":1000,"conntrack_percent":40}), \
             patch("ddosctl.host_network_counters",side_effect=[{"host_listen_overflow_total":100},{"host_listen_overflow_total":110}]), \
             patch.object(self.controller,"gate_counters",return_value={}):
            self.controller.tick()
            self.controller.tick()
        self.assertEqual(self.controller.mode,2)
        self.assertEqual(self.calls[-1][0],"config")
        self.assertEqual(self.calls[-1][3:5],(1,2))  # observation is unchanged
        self.assertEqual(self.calls[-1][7:9],(128,512))
        self.assertNotIn("syn_per_second",self.controller.signals)


if __name__ == "__main__":
    unittest.main()
