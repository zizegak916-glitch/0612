from pathlib import Path
import unittest


SCRIPT = (Path(__file__).parents[1] / "userscript" / "IPBatchInspector.user.js").read_text(encoding="utf-8")


class UserscriptBoundaryTest(unittest.TestCase):
    def test_metadata_is_installable_and_updatable(self):
        self.assertIn("// ==UserScript==", SCRIPT)
        self.assertIn("// @version      4.1.0", SCRIPT)
        self.assertIn("// @downloadURL  https://raw.githubusercontent.com/", SCRIPT)
        self.assertIn("// @grant        GM_xmlhttpRequest", SCRIPT)

    def test_subscription_nodes_are_not_connected(self):
        for forbidden in ("new WebSocket", "RTCPeerConnection", "chrome.proxy", "browser.proxy"):
            self.assertNotIn(forbidden, SCRIPT)
        self.assertIn("resolveHost(host)", SCRIPT)
        self.assertNotIn("item.port)", SCRIPT)

    def test_private_redirect_and_size_guards_are_present(self):
        self.assertIn("redirect: 'manual'", SCRIPT)
        self.assertIn("isPrivateHost", SCRIPT)
        self.assertIn("MAX_BODY", SCRIPT)
        self.assertIn("跨站最终响应已丢弃", SCRIPT)

    def test_saved_urls_are_encrypted(self):
        self.assertIn("PBKDF2", SCRIPT)
        self.assertIn("AES-GCM", SCRIPT)
        self.assertIn("iterations: 210000", SCRIPT)
        self.assertNotIn("GM_setValue(STORAGE_KEY, rawUrl", SCRIPT)

    def test_major_subscription_families_are_declared(self):
        for protocol in ("ssr", "vmess", "vless", "trojan", "hysteria2", "tuic", "socks5", "anytls", "wireguard"):
            self.assertIn(f"'{protocol}'", SCRIPT)
        for wrapper in ("clash", "stash", "sing-box", "surge", "loon"):
            self.assertIn(wrapper, SCRIPT)


if __name__ == "__main__":
    unittest.main()
