import unittest
from unittest.mock import patch

from ipbatch_inspector.iptools import extract_ips, is_public_ip
from ipbatch_inspector.models import NodeEndpoint
from ipbatch_inspector.subscriptions import resolve_nodes


class IpToolsTest(unittest.TestCase):
    def test_extract_ipv4_ipv6_and_cidr(self):
        ips, warnings = extract_ips(["1.1.1.1, 2001:4860:4860::8888 192.0.2.0/30"])
        self.assertEqual("1.1.1.1", ips[0])
        self.assertIn("2001:4860:4860::8888", ips)
        self.assertIn("192.0.2.3", ips)
        self.assertEqual([], warnings)

    def test_public_policy(self):
        self.assertTrue(is_public_ip("1.1.1.1"))
        for value in ("127.0.0.1", "10.0.0.1", "100.64.0.1", "192.0.2.1", "::1", "fe80::1"):
            self.assertFalse(is_public_ip(value), value)

    @patch("ipbatch_inspector.subscriptions.resolve_node_host")
    def test_node_port_never_enters_resolver(self, resolver):
        resolver.return_value = (["1.1.1.1"], [])
        node = NodeEndpoint("vless", "demo", "node.example", 443)
        result = resolve_nodes([node])
        resolver.assert_called_once_with("node.example")
        self.assertEqual(["1.1.1.1"], result["public_ips"])


if __name__ == "__main__":
    unittest.main()
