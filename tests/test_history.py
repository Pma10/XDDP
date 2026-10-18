import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controller"))
from history import History, read_day, _local_midnight


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "history.sqlite3")
        self.day = dt.date(2026, 10, 6)
        self.start = _local_midnight(self.day)

    def tearDown(self):
        self.tmp.cleanup()

    def test_one_record_per_minute_and_offline_hourly_deltas(self):
        h = History(self.path)
        a = self.start + 60
        first = {"rx_packets": 100, "drop_packets": 10, "handshake_invalid": 2,
                 "candidate_reasons": {"syn_rate": 7}}
        self.assertTrue(h.record(a, "normal", True, first, {"pps": 10}, True))
        self.assertFalse(h.record(a + 5, "normal", True, first, {"pps": 20}, True))
        self.assertTrue(h.record(a + 60, "attack", False,
                                 {"rx_packets": 150, "drop_packets": 16, "handshake_invalid": 3,
                                  "candidate_reasons": {"syn_rate": 12}},
                                 {"pps": 25}, True))
        result = read_day(self.path, str(self.day), raw=True)
        self.assertEqual(result["samples"], 2)
        hour = result["hours"][0]
        self.assertEqual(hour["deltas"]["rx_packets"], 50)
        self.assertEqual(hour["deltas"]["drop_packets"], 6)
        self.assertEqual(hour["candidate_deltas"]["syn_rate"], 5)
        self.assertEqual(hour["max_sampled_rates"]["pps"], 25)
        self.assertEqual(hour["modes"], ["normal", "attack"])
        self.assertEqual(len(result["raw_samples"]), 2)
        self.assertTrue(result["raw_samples"][0]["observe"])
        self.assertFalse(result["raw_samples"][1]["observe"])

    def test_gaps_resets_and_deleted_days_not_reported_as_drops(self):
        h = History(self.path, retention_days=1)
        a = self.start + 60
        h.record(a, "normal", True, {"drop_packets": 100}, {}, False)
        h.record(a + 120, "normal", True, {"drop_packets": 500}, {}, False)
        h.record(a + 180, "normal", True, {"drop_packets": 2}, {}, False)
        result = read_day(self.path, str(self.day))
        self.assertEqual(result["samples"], 3)
        self.assertNotIn("drop_packets", result["hours"][0]["deltas"])
        h.record(a + 2 * 86400, "normal", True, {"drop_packets": 9}, {}, False)
        self.assertEqual(read_day(self.path, str(self.day))["samples"], 0)

    def test_missing_archive_is_not_misrepresented_as_zero_traffic(self):
        with self.assertRaises(FileNotFoundError):
            read_day(self.path, str(self.day))

    def test_invalid_date_rejected(self):
        h = History(self.path)
        h.record(self.start + 60, "normal", True, {}, {}, False)
        with self.assertRaises(ValueError):
            read_day(self.path, "2026-02-30")


if __name__ == "__main__":
    unittest.main()
