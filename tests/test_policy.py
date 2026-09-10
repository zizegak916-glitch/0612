import unittest

from ipbatch_inspector.ai import _classify, build_ai_assessment


class PolicyTest(unittest.TestCase):
    def test_hong_kong_ip_is_not_called_unsupported(self):
        hk = build_ai_assessment("HK")
        self.assertEqual("not-tested", hk["availability_verdict"])
        rendered = " ".join(hk.values()).lower()
        self.assertNotIn("likely unavailable", rendered)
        self.assertIn("not a chatgpt-web", hk["geolocation_boundary"].lower())

    def test_missing_risk_is_not_called_low_risk(self):
        result = build_ai_assessment("US")
        self.assertIn("cannot be claimed", result["ip_risk_evidence"])
        self.assertIn("no supported/unsupported conclusion", result["boundary"])

    def test_plain_403_is_not_called_geo_block(self):
        status, detail = _classify(403, "access denied", "web")
        self.assertEqual("denial-or-challenge-observed", status)
        self.assertIn("unproven", detail)


if __name__ == "__main__":
    unittest.main()
