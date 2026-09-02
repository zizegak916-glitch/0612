import base64
import json
import unittest

from ipbatch_inspector.subscriptions import SubscriptionParser, alternate_fsl_url, subscription_url_from_input


def b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


class SubscriptionParserTest(unittest.TestCase):
    def test_all_uri_families_and_nested_base64(self):
        vmess = b64(json.dumps({"add": "vm.example", "port": "443", "ps": "vm"}))
        ss = b64("aes-256-gcm:secret@ss.example:8388")
        ssr = b64("ssr.example:443:origin:aes-256-cfb:plain:cGFzcw/?remarks=" + b64("SSR node"))
        content = "\n".join(
            [
                f"vmess://{vmess}",
                f"ss://{ss}#SS",
                f"ssr://{ssr}",
                "vless://uuid@vless.example:443#VL",
                "trojan://secret@tr.example:443#TR",
                "hysteria://secret@hy.example:443#HY",
                "hy2://secret@hy2.example:443#HY2",
                "tuic://uuid:secret@tuic.example:443#TUIC",
                "socks5://user:pass@socks.example:1080#SOCKS",
                "http://user:pass@http.example:8080#HTTP",
            ]
        )
        report = SubscriptionParser().parse(b64(content))
        protocols = {node.protocol for node in report.nodes}
        self.assertTrue({"vmess", "ss", "ssr", "vless", "trojan", "hysteria", "hysteria2", "tuic", "socks5", "http"}.issubset(protocols))
        self.assertEqual(1, report.decoded_layers)

    def test_clash_yaml_provider_and_chain(self):
        content = """
proxy-providers:
  remote:
    type: http
    url: https://provider.example/sub?token=secret
proxies:
  - name: edge
    type: vless
    server: edge.example
    port: 443
    dialer-proxy: relay
  - {name: relay, type: ss, server: 1.1.1.1, port: 8388}
"""
        report = SubscriptionParser().parse(content)
        self.assertEqual(2, len(report.nodes))
        self.assertEqual(1, report.chain_references)
        self.assertEqual(1, len(report.provider_urls))
        public = report.public_dict()
        self.assertNotIn("token=secret", json.dumps(public))

    def test_sn_subscription_url(self):
        target = "https://example.com/fsl64?keep=raw-token"
        wrapped = "sn://subscription?url=" + target
        self.assertEqual(target, subscription_url_from_input(wrapped))
        self.assertEqual(target, subscription_url_from_input("sn://subscription/" + b64(target)))

    def test_fsl_format_swap_preserves_raw_query(self):
        original = "https://example.com/api/fsl64/path?token=a%2Fb&x=1&x=2"
        alternate = alternate_fsl_url(original)
        self.assertEqual("https://example.com/api/fslyaml/path?token=a%2Fb&x=1&x=2", alternate)
        self.assertEqual(original, alternate_fsl_url(alternate))


if __name__ == "__main__":
    unittest.main()
