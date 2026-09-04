import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ipbatch_inspector.monitor import run_action, run_once


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

    @patch("ipbatch_inspector.monitor.detailed_investigation")
    def test_detail_mode_requires_one_target(self, investigate):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            run_action({"mode": "detail", "targets": ["1.1.1.1", "8.8.8.8"]})
        run_action({"mode": "detail", "targets": ["1.1.1.1"], "tls_ports": [443]})
        investigate.assert_called_once()

    @patch("ipbatch_inspector.monitor.real_subscription_test")
    @patch("ipbatch_inspector.monitor.load_saved", return_value="https://sub.example/token")
    def test_background_realtest_uses_saved_url_and_never_opens_browser(self, load_saved, test):
        test.return_value = {"results": []}
        run_action({"mode": "realtest", "saved_subscription": "primary", "nodes": ["node-a"]})
        load_saved.assert_called_once_with("primary")
        self.assertFalse(test.call_args.kwargs["open_browser"])


if __name__ == "__main__":
    unittest.main()
