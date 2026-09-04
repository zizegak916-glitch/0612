from __future__ import annotations

import unittest
from unittest.mock import patch

from ipbatch_inspector import realtest


class FakeController:
    selected = "DIRECT"

    def __init__(self, *args, **kwargs):
        pass

    def version(self):
        return {"meta": True, "version": "test"}

    def configs(self):
        return {"tun": {"enable": True}}

    def proxies(self):
        return {
            "PROXY": {
                "type": "Selector",
                "all": ["DIRECT", "node-a", "other"],
                "now": self.__class__.selected,
            }
        }

    def select(self, group, node):
        self.__class__.selected = node


class RealTest(unittest.TestCase):
    def setUp(self):
        FakeController.selected = "DIRECT"

    def test_remote_controller_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            realtest.MihomoController("http://192.0.2.1:9090")

    def test_login_redirect_is_reachability_not_geo_block(self):
        verdict, reason = realtest._classify(302, "https://example.com/login", "")
        self.assertEqual("authentication_required", verdict)
        self.assertIn("authentication", reason)

    def test_real_test_matches_subscription_node_and_restores_group(self):
        subscription = {
            "subscription": {"final_host": "sub.example"},
            "parse": {"node_count": 1, "nodes": [{"name": "node-a"}]},
        }
        targets = [{"url": "https://chatgpt.com/", "name": "chatgpt", "resolved_addresses": ["1.1.1.1"]}]
        probe = {
            "url": "https://chatgpt.com/", "status": 200, "verdict": "reachable",
            "reason": "ok", "elapsed_ms": 1, "location": "", "headers": {},
            "error": None, "body_excerpt": "", "cookies_or_credentials_sent": False,
        }
        with (
            patch.object(realtest, "MihomoController", FakeController),
            patch.object(realtest, "inspect_subscription", return_value=subscription),
            patch.object(realtest, "detect_exit_ips", return_value={"exit_ips": ["1.1.1.1"]}),
            patch.object(realtest, "_target_list", return_value=targets),
            patch.object(realtest, "_probe", return_value=probe),
        ):
            report = realtest.real_subscription_test(
                "https://sub.example/token", nodes=("node-a",), settle_seconds=0
            )
        self.assertEqual("node-a", report["results"][0]["node"])
        self.assertTrue(report["controller"]["original_node_restored"])
        self.assertEqual("DIRECT", FakeController.selected)
        self.assertFalse(report["test_semantics"]["messages_sent"])


if __name__ == "__main__":
    unittest.main()
