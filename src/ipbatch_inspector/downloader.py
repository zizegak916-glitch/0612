from __future__ import annotations

import gzip
import http.client
import ipaddress
import io
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit


MAX_BODY = 5 * 1024 * 1024
MAX_REDIRECTS = 4
USER_AGENT = "IPBatchInspector/4.0 (+https://github.com/zizegak916-glitch/0612)"


class DownloadPolicyError(RuntimeError):
    pass


@dataclass(frozen=True)
class DownloadedText:
    text: str
    final_url: str
    content_type: str
    bytes_read: int


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, peer_ip: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._peer_ip = peer_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._peer_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, peer_ip: str, timeout: float):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._peer_ip = peer_ip

    def connect(self) -> None:
        raw = socket.create_connection((self._peer_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _classify(host: str) -> tuple[list[str], list[str]]:
    try:
        values = [ipaddress.ip_address(host.strip("[]")).compressed]
    except ValueError:
        try:
            values = list(
                dict.fromkeys(
                    ipaddress.ip_address(item[4][0]).compressed
                    for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                )
            )
        except socket.gaierror as exc:
            raise DownloadPolicyError(f"subscription host DNS failed: {exc}") from exc
    public = [value for value in values if ipaddress.ip_address(value).is_global]
    private = [value for value in values if not ipaddress.ip_address(value).is_global]
    if public and private:
        raise DownloadPolicyError("mixed public/private DNS answers rejected as rebinding risk")
    return public, private


def _validated_target(url: str, allow_private: bool) -> tuple[object, str, bool]:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise DownloadPolicyError("subscription URL must use HTTP or HTTPS")
    if not parts.hostname or parts.username is not None or parts.password is not None:
        raise DownloadPolicyError("subscription URL host is missing or contains userinfo")
    public, private = _classify(parts.hostname)
    is_private = bool(private)
    if is_private and not allow_private:
        raise DownloadPolicyError("private/local subscription is blocked unless explicitly allowed")
    if parts.scheme == "http" and not is_private:
        raise DownloadPolicyError("public subscription URLs require HTTPS")
    if not public and not private:
        raise DownloadPolicyError("subscription host resolved to no usable address")
    return parts, (private or public)[0], is_private


def download_text(url: str, *, allow_private: bool = False, timeout: float = 15.0) -> DownloadedText:
    current = url.strip()
    for redirect_count in range(MAX_REDIRECTS + 1):
        parts, peer_ip, _ = _validated_target(current, allow_private)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        connection: http.client.HTTPConnection
        if parts.scheme == "https":
            connection = _PinnedHTTPSConnection(parts.hostname, port, peer_ip, timeout)
        else:
            connection = _PinnedHTTPConnection(parts.hostname, port, peer_ip, timeout)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        default_port = 443 if parts.scheme == "https" else 80
        display_host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
        host_header = display_host if port == default_port else f"{display_host}:{port}"
        try:
            connection.request(
                "GET",
                path,
                headers={"Host": host_header, "User-Agent": USER_AGENT, "Accept-Encoding": "gzip"},
            )
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                response.read(1024)
                if not location:
                    raise DownloadPolicyError("redirect did not provide a Location header")
                if redirect_count >= MAX_REDIRECTS:
                    raise DownloadPolicyError(f"subscription exceeded {MAX_REDIRECTS} redirects")
                current = urljoin(current, location)
                continue
            if response.status < 200 or response.status >= 300:
                response.read(1024)
                raise DownloadPolicyError(f"subscription returned HTTP {response.status}")
            content_length = response.getheader("Content-Length")
            if content_length and int(content_length) > MAX_BODY:
                raise DownloadPolicyError("subscription body exceeds 5 MiB")
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise DownloadPolicyError("subscription body exceeds 5 MiB")
            if (response.getheader("Content-Encoding") or "").lower() == "gzip":
                with gzip.GzipFile(fileobj=io.BytesIO(body)) as compressed:
                    body = compressed.read(MAX_BODY + 1)
                if len(body) > MAX_BODY:
                    raise DownloadPolicyError("decompressed subscription exceeds 5 MiB")
            content_type = response.getheader("Content-Type") or ""
            charset = "utf-8"
            for part in content_type.split(";")[1:]:
                if "charset=" in part.lower():
                    charset = part.split("=", 1)[1].strip().strip('"')
            try:
                text = body.decode(charset, errors="strict")
            except (LookupError, UnicodeDecodeError):
                text = body.decode("utf-8", errors="replace")
            return DownloadedText(text=text, final_url=current, content_type=content_type, bytes_read=len(body))
        finally:
            connection.close()
    raise DownloadPolicyError("redirect processing failed")
