import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ipbatch_inspector.monitor import run_once


class MonitorTest(unittest.TestCase):
    @patch("ipbatch_inspector.monitor.run_action")
    def test_history_and_change_detection(self, action):
        action.return_value = {"exit_ips": ["1.1.1.1"]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = run_once({"mode": "exit", "history_limit": 2}, root)
            second = run_once({"mode": "exit", "history_limit": 2}, root)
            self.assertTrue(first["changed"])
            self.assertFalse(second["changed"])
            self.assertEqual(["1.1.1.1"], json.loads((root / "latest.json").read_text())["result"]["exit_ips"])
            self.assertLessEqual(len(list((root / "history").glob("*.json"))), 2)


if __name__ == "__main__":
    unittest.main()
