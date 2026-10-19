"""Static policy wire-format contracts shared by startup and the loader."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controller"))
from policy import loader_policy


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.cfg = json.loads((ROOT / "config/controller.json").read_text())

    def test_combines_port_flags_and_manual_block_precedence(self):
        self.cfg.update(
            protected_tcp_ports=[25565], drop_udp_ports=[25565],
            owned_prefixes=["192.0.2.1/32"], allow_prefixes=["198.51.100.0/24"],
            bogon_prefixes=["203.0.113.0/24"], block_prefixes=["203.0.113.0/24"],
        )
        self.assertEqual(loader_policy(self.cfg),
                         "port 25565 5\nowned 192.0.2.1/32 1\n"
                         "allow 198.51.100.0/24 1\nblock 203.0.113.0/24 11\n")

    def test_order_independent_and_does_not_mutate_configuration(self):
        self.cfg.update(protected_tcp_ports=[25566, 25565],
                        allow_prefixes=["203.0.113.0/24", "198.51.100.0/24"])
        original = copy.deepcopy(self.cfg)
        expected = loader_policy(self.cfg)
        self.assertEqual(self.cfg, original)
        reversed_cfg = copy.deepcopy(self.cfg)
        reversed_cfg['protected_tcp_ports'].reverse()
        reversed_cfg['allow_prefixes'].reverse()
        self.assertEqual(loader_policy(reversed_cfg), expected)

    def test_size_boundary_counts_encoded_document_including_final_newline(self):
        document = loader_policy(self.cfg)
        with patch('policy.MAX_POLICY_BYTES', len(document.encode('ascii'))):
            self.assertEqual(loader_policy(self.cfg), document)
        with patch('policy.MAX_POLICY_BYTES', len(document.encode('ascii')) - 1):
            with self.assertRaisesRegex(ValueError, '4 MiB'):
                loader_policy(self.cfg)


if __name__ == "__main__":
    unittest.main()
