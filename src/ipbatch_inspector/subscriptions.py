from __future__ import annotations

import base64
import json
import re
from collections import Counter
from urllib.parse import parse_qs, unquote, urlsplit

from .iptools import resolve_node_host
from .models import NodeEndpoint, SubscriptionReport


MAX_NODES = 1500
MAX_PROVIDER_DOCUMENTS = 20
SUPPORTED = {
    "ss",
    "ssr",
    "vmess",
    "vless",
    "trojan",
    "hysteria",
    "hysteria2",
    "hy2",
    "tuic",
    "socks",
    "socks4",
    "socks5",
    "http",
    "https",
}
URI_RE = re.compile(
    r"(?i)(?:ssr?|vmess|vless|trojan|hysteria2?|hy2|tuic|socks5?|https?)://[^\s<>'\"]+"
)


def _decode_b64(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    compact += "=" * ((4 - len(compact) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(compact.encode("ascii"))
        text = raw.decode("utf-8")
    except (ValueError, UnicodeError):
        return None
    controls = sum(1 for char in text if ord(char) < 9 or 13 < ord(char) < 32)
    return None if controls > max(2, len(text) // 20) else text


def subscription_url_from_input(value: str) -> str:
    """Resolve the explicit URL inside sn://subscription without rewriting its query."""
    value = value.strip()
    if not value.lower().startswith("sn://subscription"):
        return value
    parts = urlsplit(value)
    query = parse_qs(parts.query, keep_blank_values=True)
    for key in ("url", "target", "subscription"):
        candidate = query.get(key, [""])[0]
        if candidate.startswith(("https://", "http://")):
            return candidate
        decoded = _decode_b64(candidate)
        if decoded and decoded.startswith(("https://", "http://")):
            return decoded
    tail = parts.path.lstrip("/")
    decoded = _decode_b64(tail)
    if decoded and decoded.startswith(("https://", "http://")):
        return decoded
    raise ValueError("sn://subscription does not contain an explicit HTTP(S) URL")


def alternate_fsl_url(value: str) -> str | None:
    """Swap one fsl64/fslyaml path segment while preserving the raw query exactly."""
    match = re.search(r"(?i)(^|/)(fsl64|fslyaml)(?=/|\?|#|$)", value)
    if not match:
        return None
    replacement = "fslyaml" if match.group(2).lower() == "fsl64" else "fsl64"
    return value[: match.start(2)] + replacement + value[match.end(2) :]


class SubscriptionParser:
    """Pure text parser. This class has no socket or HTTP dependency."""

    def __init__(self, max_nodes: int = MAX_NODES):
        self.max_nodes = max_nodes

    def parse(self, content: str, source: str = "subscription") -> SubscriptionReport:
        report = SubscriptionReport()
        seen: set[tuple[str, str, int | None]] = set()
        self._parse_layer(content.lstrip("\ufeff"), source, report, seen, depth=0)
        if not report.nodes:
            report.warnings.append("no supported node endpoint was found")
        return report

    def merge(self, target: SubscriptionReport, extra: SubscriptionReport) -> None:
        seen = {(n.protocol, n.host.lower(), n.port) for n in target.nodes}
        for node in extra.nodes:
            self._add(target, seen, node)
        for url in extra.provider_urls:
            if url not in target.provider_urls and len(target.provider_urls) < MAX_PROVIDER_DOCUMENTS:
                target.provider_urls.append(url)
        target.warnings.extend(extra.warnings)
        target.rejected += extra.rejected
        target.duplicates += extra.duplicates
        target.decoded_layers += extra.decoded_layers
        target.chain_references += extra.chain_references
        target.truncated = target.truncated or extra.truncated

    def _parse_layer(
        self,
        content: str,
        source: str,
        report: SubscriptionReport,
        seen: set[tuple[str, str, int | None]],
        depth: int,
    ) -> None:
        if depth > 2 or report.truncated:
            return
        stripped = content.strip()
        if 20 <= len(stripped) <= 8 * 1024 * 1024 and re.fullmatch(r"[A-Za-z0-9_+/=\s-]+", stripped):
            decoded = _decode_b64(stripped)
            if decoded and ("://" in decoded or "proxies:" in decoded.lower()):
                report.decoded_layers += 1
                self._parse_layer(decoded, source, report, seen, depth + 1)
                return
        self._parse_yaml(content, source, report, seen)
        for match in URI_RE.finditer(content):
            token = match.group(0).rstrip(",;])}")
            node = self._parse_uri(token, source)
            if node:
                self._add(report, seen, node)
            elif not token.lower().startswith(("http://", "https://")):
                report.rejected += 1

    def _parse_yaml(
        self,
        content: str,
        source: str,
        report: SubscriptionReport,
        seen: set[tuple[str, str, int | None]],
    ) -> None:
        lines = content.replace("\r", "").split("\n")
        in_proxies = False
        proxies_indent = -1
        current: dict[str, str] | None = None

        def flush() -> None:
            nonlocal current
            if not current:
                current = None
                return
            protocol = self._protocol(current.get("type", ""))
            host = self._clean_host(current.get("server", ""))
            port = self._port(current.get("port", ""))
            if protocol in SUPPORTED and host:
                chain = current.get("dialer-proxy", "")
                if chain:
                    report.chain_references += 1
                self._add(
                    report,
                    seen,
                    NodeEndpoint(protocol, current.get("name", ""), host, port, chain, source),
                )
            elif host or protocol:
                report.rejected += 1
            current = None

        for raw in lines:
            line = self._strip_yaml_comment(raw)
            stripped = line.strip()
            if not stripped:
                continue
            indent = len(line) - len(line.lstrip(" "))
            if re.match(r"(?i)^proxies\s*:\s*$", stripped):
                flush()
                in_proxies = True
                proxies_indent = indent
                continue
            if in_proxies and indent <= proxies_indent and not stripped.startswith("-"):
                flush()
                in_proxies = False
            if re.match(r"(?i)^proxy-providers\s*:\s*$", stripped):
                continue
            provider = re.search(r"(?i)(?:^|[, {])url\s*:\s*(['\"]?)(https?://[^\s,'\"}]+)\1", stripped)
            if provider:
                url = provider.group(2)
                if url not in report.provider_urls and len(report.provider_urls) < MAX_PROVIDER_DOCUMENTS:
                    report.provider_urls.append(url)
            if not in_proxies:
                continue
            if stripped.startswith("- {"):
                flush()
                inline = stripped[3:].rstrip("}").strip()
                current = self._inline_mapping(inline)
                flush()
            elif stripped.startswith("- "):
                flush()
                current = {}
                self._yaml_field(stripped[2:], current)
            elif current is not None:
                self._yaml_field(stripped, current)
        flush()

    @staticmethod
    def _strip_yaml_comment(line: str) -> str:
        quote = ""
        escaped = False
        for index, char in enumerate(line):
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
            elif char in {"'", '"'}:
                quote = "" if quote == char else (char if not quote else quote)
            elif char == "#" and not quote and (index == 0 or line[index - 1].isspace()):
                return line[:index]
        return line

    @staticmethod
    def _unquote(value: str) -> str:
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            return value[1:-1]
        return value

    def _yaml_field(self, line: str, target: dict[str, str]) -> None:
        if ":" not in line:
            return
        key, value = line.split(":", 1)
        key = key.strip().lower()
        if key in {"name", "type", "server", "port", "dialer-proxy"}:
            target[key] = self._unquote(value)

    def _inline_mapping(self, value: str) -> dict[str, str]:
        target: dict[str, str] = {}
        pattern = re.compile(r"(?:^|,)\s*([\w-]+)\s*:\s*(?:\"([^\"]*)\"|'([^']*)'|([^,}]+))")
        for match in pattern.finditer(value):
            target[match.group(1).lower()] = next(
                item.strip() for item in match.groups()[1:] if item is not None
            )
        return target

    def _parse_uri(self, token: str, source: str) -> NodeEndpoint | None:
        scheme, body = token.split("://", 1)
        scheme = self._protocol(scheme)
        try:
            if scheme == "vmess":
                decoded = _decode_b64(body.split("#", 1)[0].split("?", 1)[0])
                if not decoded:
                    return None
                data = json.loads(decoded)
                return NodeEndpoint("vmess", str(data.get("ps", "")), self._clean_host(str(data.get("add", ""))), self._port(data.get("port")), source=source)
            if scheme == "ssr":
                decoded = _decode_b64(body.split("#", 1)[0])
                if not decoded:
                    return None
                head, _, query = decoded.partition("/?")
                pieces = head.split(":", 5)
                if len(pieces) < 6:
                    return None
                params = parse_qs(query)
                name = params.get("remarks", [""])[0]
                name = _decode_b64(name) or unquote(name)
                return NodeEndpoint("ssr", name, self._clean_host(pieces[0]), self._port(pieces[1]), source=source)
            if scheme == "ss":
                return self._parse_ss(body, source)
            if scheme not in SUPPORTED:
                return None
            parsed = urlsplit(f"{scheme}://{body}")
            if scheme in {"http", "https"} and parsed.username is None:
                return None
            if not parsed.hostname:
                return None
            return NodeEndpoint(
                scheme,
                unquote(parsed.fragment),
                self._clean_host(parsed.hostname),
                parsed.port,
                source=source,
            )
        except (ValueError, TypeError, json.JSONDecodeError):
            return None

    def _parse_ss(self, body: str, source: str) -> NodeEndpoint | None:
        fragment = unquote(body.split("#", 1)[1].split("?", 1)[0]) if "#" in body else ""
        main = body.split("#", 1)[0].split("?", 1)[0]
        if "@" not in main:
            decoded = _decode_b64(main)
            if decoded:
                main = decoded
        else:
            user, at, authority = main.rpartition("@")
            if ":" not in user:
                user = _decode_b64(user) or user
            main = user + at + authority
        parsed = urlsplit("ss://" + main)
        if not parsed.hostname:
            return None
        return NodeEndpoint("ss", fragment, self._clean_host(parsed.hostname), parsed.port, source=source)

    def _add(
        self,
        report: SubscriptionReport,
        seen: set[tuple[str, str, int | None]],
        node: NodeEndpoint,
    ) -> None:
        if len(report.nodes) >= self.max_nodes:
            report.truncated = True
            return
        if not node.host:
            report.rejected += 1
            return
        key = (node.protocol, node.host.lower(), node.port)
        if key in seen:
            report.duplicates += 1
            return
        seen.add(key)
        report.nodes.append(node)

    @staticmethod
    def _protocol(value: str) -> str:
        lowered = value.strip().lower()
        return "hysteria2" if lowered == "hy2" else lowered

    @staticmethod
    def _clean_host(value: str) -> str:
        return unquote(value.strip().strip("[]").strip("'\""))

    @staticmethod
    def _port(value: object) -> int | None:
        try:
            port = int(str(value).strip().strip("'\""))
            return port if 1 <= port <= 65535 else None
        except (TypeError, ValueError):
            return None


def resolve_nodes(nodes: list[NodeEndpoint], max_ips: int = 500) -> dict[str, object]:
    """Map nodes to public IPs. Ports are deliberately never passed to the resolver."""
    origins: dict[str, list[dict[str, object]]] = {}
    local_addresses: dict[str, list[str]] = {}
    errors: dict[str, str] = {}
    for node in nodes:
        if len(origins) >= max_ips:
            break
        try:
            public, local = resolve_node_host(node.host)
        except OSError as exc:
            errors[node.host] = str(exc)
            continue
        if local:
            local_addresses[node.host] = local
        for ip in public:
            if len(origins) >= max_ips and ip not in origins:
                break
            origins.setdefault(ip, []).append(node.redacted_dict())
    return {
        "public_ips": list(origins),
        "origins": origins,
        "local_addresses": local_addresses,
        "dns_errors": errors,
        "truncated": len(origins) >= max_ips,
    }


def protocol_counts(nodes: list[NodeEndpoint]) -> dict[str, int]:
    return dict(Counter(node.protocol for node in nodes))
