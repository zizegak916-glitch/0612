import contextlib
import http.server
import threading
import unittest

from ipbatch_inspector.downloader import DownloadPolicyError, download_text


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/sub")
            self.end_headers()
            return
        body = b"dmxlc3M6Ly91dWlkQGV4YW1wbGUuY29tOjQ0Mw=="
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


@contextlib.contextmanager
def server():
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        thread.join()
        httpd.server_close()


class DownloaderTest(unittest.TestCase):
    def test_private_is_default_denied_and_explicitly_allowed(self):
        with server() as port:
            url = f"http://127.0.0.1:{port}/redirect"
            with self.assertRaises(DownloadPolicyError):
                download_text(url)
            result = download_text(url, allow_private=True)
            self.assertIn("dmxlc3M6", result.text)

    def test_public_http_is_always_denied(self):
        with self.assertRaisesRegex(DownloadPolicyError, "require HTTPS"):
            download_text("http://8.8.8.8/sub", allow_private=True)

    def test_userinfo_is_denied(self):
        with self.assertRaisesRegex(DownloadPolicyError, "userinfo"):
            download_text("https://user:pass@example.com/sub")


if __name__ == "__main__":
    unittest.main()
