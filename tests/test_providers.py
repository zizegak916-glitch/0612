from __future__ import annotations

import os
import tempfile
import time
import unittest
from unittest.mock import patch

from ipbatch_inspector import providers
from ipbatch_inspector.models import SourceEvidence


class ProvidersTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.environment = patch.dict(os.environ, {"IPBATCH_CACHE_DIR": self.temporary.name})
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.temporary.cleanup()

    @staticmethod
    def delayed(country_code):
        def call(ip, timeout):
            time.sleep(0.12)
            return {"country_code": country_code, "asn": "13335"}
        return call

    def test_sources_for_one_ip_run_concurrently(self):
        replacements = {
            "ipapi": self.delayed("AU"),
            "proxycheck": self.delayed("AU"),
            "geojs": self.delayed("AU"),
        }
        with patch.dict(providers.PROVIDERS, replacements):
            started = time.monotonic()
            result = providers.scan_many(
                ["1.1.1.1"], ("ipapi", "proxycheck", "geojs"), workers=1, fresh=True
            )[0]
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.28)
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.confidence["level"], "high")
        self.assertEqual(result.consensus["country_code"]["agree"], 3)

    def test_cache_avoids_second_provider_call(self):
        calls = 0

        def fake(ip, timeout):
            nonlocal calls
            calls += 1
            return {"country_code": "AU", "asn": "AS13335"}

        with patch.dict(providers.PROVIDERS, {"geojs": fake}):
            first = providers.scan_many(["1.1.1.1"], ("geojs",), workers=1)[0]
            second = providers.scan_many(["1.1.1.1"], ("geojs",), workers=1)[0]
        self.assertEqual(calls, 1)
        self.assertFalse(first.evidence[0].cache_hit)
        self.assertTrue(second.evidence[0].cache_hit)
        self.assertEqual(second.confidence["cached_sources"], 1)

    def test_failure_backoff_avoids_immediate_retry(self):
        calls = 0

        def failing(ip, timeout):
            nonlocal calls
            calls += 1
            raise OSError("temporary failure")

        with patch.dict(providers.PROVIDERS, {"geojs": failing}):
            first = providers.scan_many(["1.1.1.1"], ("geojs",), workers=1)[0]
            second = providers.scan_many(["1.1.1.1"], ("geojs",), workers=1)[0]
        self.assertEqual(calls, 1)
        self.assertEqual(first.status, "failed")
        self.assertTrue(second.evidence[0].cache_hit)
        self.assertEqual(second.evidence[0].ttl_seconds, 60)

    def test_conflicts_and_unknown_are_not_hidden(self):
        replacements = {
            "ipapi": lambda ip, timeout: {"country_code": "US", "asn": "AS1", "proxy": False},
            "proxycheck": lambda ip, timeout: {"country_code": "CA", "asn": "AS2", "proxy": True},
            "geojs": lambda ip, timeout: {"country_code": "US", "asn": "AS1"},
        }
        with patch.dict(providers.PROVIDERS, replacements):
            result = providers.scan_many(
                ["1.1.1.1"], ("ipapi", "proxycheck", "geojs"), workers=1, fresh=True
            )[0]
        self.assertEqual(result.country_code, "US")
        self.assertEqual(result.asn, "AS1")
        self.assertEqual(result.signals["proxy"]["state"], "disputed")
        self.assertGreaterEqual(
            {item["field"] for item in result.conflicts}, {"country_code", "asn", "proxy"}
        )

    def test_private_addresses_never_reach_providers(self):
        def fail(ip, timeout):
            raise AssertionError("provider called")

        with patch.dict(providers.PROVIDERS, {"geojs": fail}):
            result = providers.scan_many(["192.168.1.2"], ("geojs",), fresh=True)[0]
        self.assertEqual(result.status, "local/reserved")
        self.assertFalse(result.evidence[0].fields["sent_to_providers"])

    def test_domestic_fallback_is_automatic_and_cannot_make_confidence_high(self):
        failed = SourceEvidence(source="failed", fetched_at="now", elapsed_ms=1, ok=False, error="offline")
        domestic = SourceEvidence(
            source="cngeo",
            fetched_at="now",
            elapsed_ms=1,
            ok=True,
            fields={"country": "示例", "organization": "镜像结果", "trust_tier": "fallback-unverified"},
        )
        with patch.object(providers, "_query_source", side_effect=[failed, failed, domestic]) as query:
            result = providers.scan_ip("1.1.1.1", ("ipapi", "geojs"), timeout=1, fresh=True)
        self.assertEqual(query.call_count, 3)
        self.assertTrue(any(item.source == "cngeo" for item in result.evidence))
        self.assertNotEqual(result.confidence["level"], "high")

    def test_domestic_fallback_is_skipped_when_two_geo_sources_succeed(self):
        first = SourceEvidence(source="ipapi", fetched_at="now", elapsed_ms=1, ok=True, fields={"country_code": "US"})
        second = SourceEvidence(source="geojs", fetched_at="now", elapsed_ms=1, ok=True, fields={"country_code": "US"})
        with patch.object(providers, "_query_source", side_effect=[first, second]) as query:
            providers.scan_ip("1.1.1.1", ("ipapi", "geojs"), timeout=1, fresh=True)
        self.assertEqual(query.call_count, 2)

    def test_domestic_fallback_can_be_disabled(self):
        failed = SourceEvidence(source="failed", fetched_at="now", elapsed_ms=1, ok=False, error="offline")
        with patch.object(providers, "_query_source", side_effect=[failed, failed]) as query:
            providers.scan_ip(
                "1.1.1.1", ("ipapi", "geojs"), timeout=1, fresh=True, domestic_fallback=False
            )
        self.assertEqual(query.call_count, 2)


if __name__ == "__main__":
    unittest.main()
