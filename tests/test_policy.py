import unittest

from ipbatch_inspector.ai import infer_ai_policy


class PolicyTest(unittest.TestCase):
    def test_openai_and_gemini_are_separate(self):
        hk = infer_ai_policy("HK")
        self.assertIn("likely unavailable", hk["openai"])
        self.assertIn("official support", hk["gemini_web"])

    def test_missing_risk_is_not_called_low_risk(self):
        result = infer_ai_policy("US")
        self.assertIn("cannot be claimed", result["ip_risk_inference"])
        self.assertIn("not connected", result["boundary"])


if __name__ == "__main__":
    unittest.main()
