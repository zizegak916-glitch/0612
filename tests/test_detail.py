from __future__ import annotations

import unittest
from unittest.mock import patch

from ipbatch_inspector import detail


class _Intel:
    def as_dict(self):
        return {
            "ip": "1.1.1.1",
            "status": "ok",
            "evidence": [
                {"source": "ipapi", "ok": True},
                {"source": "geojs", "ok": True},
            ],
        }


class DetailTest(unittest.TestCase):
    def test_private_ip_is_rejected_before_network(self):
        with self.assertRaisesRegex(ValueError, "public IP"):
            detail.detailed_investigation("192.168.1.1")

    def test_single_ip_report_separates_passive_and_tls_evidence(self):
        fake_detail = lambda *args, **kwargs: {"ok": True}
        with (
            patch.object(detail, "scan_ip", return_value=_Intel()),
            patch.object(detail, "_rdap_detail", side_effect=fake_detail),
            patch.object(detail, "_ripestat", side_effect=fake_detail),
            patch.object(detail, "_internetdb", return_value={"found": True, "hostnames": ["one.one.one.one"], "ports": [443]}),
            patch.object(detail, "_greynoise", return_value={"found": True, "riot": True}),
            patch.object(detail, "_reverse_dns", return_value={"primary": "one.one.one.one", "aliases": [], "addresses": ["1.1.1.1"]}),
            patch.object(detail, "_host_points_to_ip", return_value=True),
            patch.object(detail, "_tls_certificate", return_value={"certificate": {"sha256": "abc"}}),
        ):
            report = detail.detailed_investigation("1.1.1.1", tls_ports=(443,), domestic_fallback=True)
        self.assertEqual("single-ip-detailed-investigation", report["mode"])
        self.assertFalse(report["network_actions"]["port_scan_performed"])
        self.assertEqual([443], [row["port"] for row in report["network_actions"]["active_target_connections"]])
        self.assertFalse(report["domestic_fallback"]["triggered"])
        self.assertGreaterEqual(len(report["tls_evidence"]), 2)


if __name__ == "__main__":
    unittest.main()
