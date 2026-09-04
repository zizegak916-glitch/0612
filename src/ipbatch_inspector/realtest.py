from __future__ import annotations

import ipaddress
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Iterable

from .providers import USER_AGENT, detect_exit_ips
from .service import inspect_subscription


MAX_CONTROLLER_RESPONSE = 4 * 1024 * 1024
MAX_TARGET_RESPONSE = 128 * 1024
MAX_REAL_TEST_NODES = 50

AI_CONVERSATION_TARGETS: dict[str, str] = {
    "chatgpt": "https://chatgpt.com/",
    "claude": "https://claude.ai/new",
    "gemini": "https://gemini.google.com/app",
    "aistudio": "https://aistudio.google.com/app/prompts/new_chat",
    "grok": "https://grok.com/",
    "perplexity": "https://www.perplexity.ai/",
    "copilot": "https://copilot.microsoft.com/",
    "deepseek": "https://chat.deepseek.com/",
    "qwen": "https://chat.qwen.ai/",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _controller_base(value: str) -> str:
    raw = value.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(raw)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme != "http" or host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("controller must be a loopback HTTP URL such as http://127.0.0.1:9090")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("controller URL must not contain credentials, query or fragment")
    if parsed.path not in {"", "/"}:
        raise ValueError("controller URL must not contain a path")
    if not parsed.port:
        raise ValueError("controller URL must include its local port")
    return raw


def _public_target(value: str, *, allow_http: bool = False) -> dict[str, Any]:
    raw = value.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urllib.parse.urlsplit(raw)
    schemes = {"https"} | ({"http"} if allow_http else set())
    if parsed.scheme not in schemes:
        raise ValueError(f"target must use {'HTTP(S)' if allow_http else 'HTTPS'}: {value}")
    if parsed.username or parsed.password:
        raise ValueError("target URL userinfo is not allowed")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("target URL has no hostname")
    if host in {"localhost"} or host.endswith((".localhost", ".local", ".internal")):
        raise ValueError("local/private target is not allowed")
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"target DNS failed for {host}: {exc}") from exc
    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    if not addresses:
        raise ValueError(f"target DNS returned no address for {host}")
    rejected = [address for address in addresses if not ipaddress.ip_address(address).is_global]
    if rejected:
        raise ValueError(f"target DNS contains non-public address(es): {', '.join(rejected[:4])}")
    normalized = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    return {"url": normalized, "host": host, "resolved_addresses": addresses[:16]}


class MihomoController:
    def __init__(self, base_url: str, secret: str = "", timeout: float = 5.0) -> None:
        self.base_url = _controller_base(base_url)
        self.secret = secret
        self.timeout = timeout

    def _request(self, path: str, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
        url = self.base_url + path
        headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
        if self.secret:
            headers["Authorization"] = "Bearer " + self.secret
        body = None
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
        try:
            with opener.open(request, timeout=self.timeout) as response:
                data = response.read(MAX_CONTROLLER_RESPONSE + 1)
                status = response.status
        except urllib.error.HTTPError as exc:
            data = exc.read(4096)
            message = data.decode("utf-8", "replace").strip()
            raise RuntimeError(f"local controller HTTP {exc.code}: {message[:500]}") from exc
        if len(data) > MAX_CONTROLLER_RESPONSE:
            raise ValueError("local controller response exceeded 4 MiB")
        if status == 204 or not data:
            return None
        return json.loads(data.decode("utf-8"))

    def version(self) -> dict[str, Any]:
        value = self._request("/version")
        return value if isinstance(value, dict) else {}

    def configs(self) -> dict[str, Any]:
        value = self._request("/configs")
        return value if isinstance(value, dict) else {}

    def proxies(self) -> dict[str, Any]:
        value = self._request("/proxies")
        proxies = value.get("proxies") if isinstance(value, dict) else None
        if not isinstance(proxies, dict):
            raise ValueError("local controller did not return a proxies object")
        return proxies

    def select(self, group: str, node: str) -> None:
        encoded = urllib.parse.quote(group, safe="")
        self._request(f"/proxies/{encoded}", "PUT", {"name": node})


def _tun_enabled(config: dict[str, Any]) -> bool:
    tun = config.get("tun")
    if isinstance(tun, dict):
        return bool(tun.get("enable"))
    return bool(tun)


def _pick_group(proxies: dict[str, Any], requested: str | None, subscription_names: set[str]) -> tuple[str, dict[str, Any]]:
    if requested:
        item = proxies.get(requested)
        if not isinstance(item, dict) or not isinstance(item.get("all"), list):
            raise ValueError(f"controller group not found or not selectable: {requested}")
        return requested, item
    candidates = []
    for name, item in proxies.items():
        if not isinstance(item, dict) or not isinstance(item.get("all"), list):
            continue
        overlap = sum(1 for node in item["all"] if node in subscription_names)
        if overlap:
            candidates.append((overlap, name, item))
    if not candidates:
        raise ValueError("no controller policy group contains node names parsed from this subscription")
    _, name, item = max(candidates, key=lambda row: (row[0], row[1]))
    return name, item


def _classify(status: int | None, location: str, body: str, error: str = "") -> tuple[str, str]:
    combined = (location + "\n" + body + "\n" + error).lower()
    geo_markers = (
        "unsupported country", "unsupported region", "not available in your country",
        "not available in your region", "country not supported", "地区不可用", "地区暂不支持",
    )
    if any(marker in combined for marker in geo_markers):
        return "geo_blocked", "response contains an explicit country/region restriction marker"
    if error:
        lowered = error.lower()
        if "timed out" in lowered or "timeout" in lowered:
            return "timeout", "connection timed out"
        if "certificate" in lowered or "ssl" in lowered or "tls" in lowered:
            return "tls_error", "TLS/certificate failure"
        if "name or service" in lowered or "getaddrinfo" in lowered or "nodename" in lowered:
            return "dns_error", "DNS resolution failed on the selected route"
        return "network_error", "network request failed"
    if status == 429:
        return "rate_limited", "target returned HTTP 429"
    if status is not None and status >= 500:
        return "upstream_error", f"target returned HTTP {status}"
    if status in {401, 407}:
        return "authentication_required", f"target was reached and returned HTTP {status}"
    if status in {403, 503} and any(marker in combined for marker in ("cloudflare", "captcha", "challenge", "cf-chl")):
        return "challenge", "target or CDN returned a browser/challenge page"
    if status is not None and 300 <= status < 400:
        if any(marker in location.lower() for marker in ("login", "signin", "auth", "account")):
            return "authentication_required", "conversation URL redirected to authentication without shared browser cookies"
        return "redirect", "target was reached and returned a non-login redirect"
    if status is not None and 200 <= status < 400:
        if any(marker in combined for marker in ("sign in", "log in", "登录")):
            return "reachable_auth_ui", "target loaded, but the probe session has no browser login cookies"
        return "reachable", "conversation URL returned a usable HTTP response"
    return "blocked_or_rejected", f"target returned HTTP {status}"


def _probe(target: dict[str, Any], timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.6",
        "Cache-Control": "no-cache",
        "User-Agent": "Mozilla/5.0 (IPBatchInspector real-route probe; +https://github.com/zizegak916-glitch/0612)",
    }
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(target["url"], headers=headers, method="GET")
    status: int | None = None
    response_headers: dict[str, str] = {}
    body = ""
    error = ""
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    except Exception as exc:
        error = (str(exc).replace("\n", " ") or exc.__class__.__name__)[:500]
        response = None
    if response is not None:
        with response:
            status = int(response.status)
            response_headers = {key.lower(): value[:1000] for key, value in response.headers.items()}
            content = response.read(MAX_TARGET_RESPONSE + 1)
            if len(content) > MAX_TARGET_RESPONSE:
                content = content[:MAX_TARGET_RESPONSE]
            body = content.decode("utf-8", "replace")
    location = response_headers.get("location", "")
    verdict, reason = _classify(status, location, body[:32768], error)
    return {
        "url": target["url"],
        "resolved_before_switch": target["resolved_addresses"],
        "status": status,
        "verdict": verdict,
        "reason": reason,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
        "location": location,
        "headers": {
            key: response_headers[key]
            for key in ("server", "content-type", "cf-ray", "x-request-id", "x-vercel-id", "via")
            if key in response_headers
        },
        "error": error or None,
        "body_excerpt": " ".join(body[:500].split()),
        "cookies_or_credentials_sent": False,
    }


def _target_list(presets: Iterable[str], custom: Iterable[str], allow_http: bool) -> list[dict[str, Any]]:
    raw: list[tuple[str, str]] = []
    for name in presets:
        key = name.strip().lower()
        if key == "all":
            raw.extend(AI_CONVERSATION_TARGETS.items())
        elif key in AI_CONVERSATION_TARGETS:
            raw.append((key, AI_CONVERSATION_TARGETS[key]))
        else:
            raise ValueError(f"unknown AI preset: {name}")
    raw.extend(("custom", value) for value in custom)
    targets = []
    seen = set()
    for name, value in raw:
        target = _public_target(value, allow_http=allow_http)
        if target["url"] in seen:
            continue
        seen.add(target["url"])
        target["name"] = name
        targets.append(target)
    if not targets:
        raise ValueError("select at least one AI preset or custom public URL/domain")
    if len(targets) > 24:
        raise ValueError("a real test accepts at most 24 target URLs")
    return targets


def real_subscription_test(
    subscription_url: str,
    *,
    controller_url: str = "http://127.0.0.1:9090",
    controller_secret: str = "",
    group: str | None = None,
    nodes: Iterable[str] = (),
    presets: Iterable[str] = ("all",),
    custom_targets: Iterable[str] = (),
    timeout: float = 12.0,
    settle_seconds: float = 1.5,
    max_nodes: int = 20,
    allow_http_targets: bool = False,
    open_browser: bool = False,
) -> dict[str, Any]:
    if max_nodes < 1 or max_nodes > MAX_REAL_TEST_NODES:
        raise ValueError(f"max_nodes must be between 1 and {MAX_REAL_TEST_NODES}")
    if settle_seconds < 0 or settle_seconds > 15:
        raise ValueError("settle_seconds must be between 0 and 15")
    controller = MihomoController(controller_url, controller_secret, min(timeout, 8.0))
    version = controller.version()
    config = controller.configs()
    if not _tun_enabled(config):
        raise RuntimeError("the local controller is reachable, but TUN/system VPN is not enabled; enable VPN in Clash/Mihomo/Clash Mate first")

    subscription = inspect_subscription(
        subscription_url,
        allow_private=False,
        resolve_only=True,
        timeout=timeout,
        workers=8,
    )
    parsed_nodes = subscription.get("parse", {}).get("nodes") or []
    subscription_names = {str(item.get("name") or "").strip() for item in parsed_nodes if item.get("name")}
    if not subscription_names:
        raise ValueError("subscription did not expose node names that can be matched to the local controller")

    proxies = controller.proxies()
    group_name, group_info = _pick_group(proxies, group, subscription_names)
    controller_nodes = [str(item) for item in group_info.get("all") or []]
    overlap = [name for name in controller_nodes if name in subscription_names]
    requested = list(dict.fromkeys(str(name).strip() for name in nodes if str(name).strip()))
    selected = requested or overlap
    missing = [name for name in selected if name not in overlap]
    if missing:
        raise ValueError("requested node(s) are not present in both the subscription and controller group: " + ", ".join(missing[:8]))
    selected = selected[:max_nodes]
    if not selected:
        raise ValueError("no matching subscription node is available in the selected controller group")
    if open_browser and len(selected) != 1:
        raise ValueError("open_browser is allowed only when exactly one node is tested")
    targets = _target_list(presets, custom_targets, allow_http_targets)
    original = str(group_info.get("now") or "")
    baseline_exit = detect_exit_ips(min(timeout, 8.0))
    results = []
    restored = False
    restore_error = ""
    try:
        for node in selected:
            switched_at = time.time()
            controller.select(group_name, node)
            if settle_seconds:
                time.sleep(settle_seconds)
            current_proxies = controller.proxies()
            actual = str((current_proxies.get(group_name) or {}).get("now") or "")
            if actual != node:
                results.append({"node": node, "switch_ok": False, "actual": actual, "error": "controller did not confirm selection"})
                continue
            exit_result = detect_exit_ips(min(timeout, 8.0))
            with ThreadPoolExecutor(max_workers=min(6, len(targets))) as pool:
                futures = {target["url"]: pool.submit(_probe, target, timeout) for target in targets}
                probes = [dict(futures[target["url"]].result(), name=target["name"]) for target in targets]
            results.append({
                "node": node,
                "switch_ok": True,
                "controller_confirmed": actual,
                "switched_at_epoch": switched_at,
                "exit": exit_result,
                "targets": probes,
                "summary": {
                    verdict: sum(1 for item in probes if item["verdict"] == verdict)
                    for verdict in sorted({item["verdict"] for item in probes})
                },
            })
    finally:
        if original and not open_browser:
            try:
                controller.select(group_name, original)
                restored = True
            except Exception as exc:
                restore_error = str(exc)[:500]

    if open_browser:
        for target in targets:
            webbrowser.open(target["url"], new=2)

    return {
        "mode": "real-subscription-system-vpn-test",
        "controller": {
            "url": _controller_base(controller_url),
            "version": version,
            "tun_enabled": True,
            "group": group_name,
            "original_node": original,
            "original_node_restored": restored,
            "left_test_node_selected_for_browser": bool(open_browser),
            "restore_error": restore_error or None,
            "secret_persisted": False,
        },
        "subscription": {
            "final_host": subscription.get("subscription", {}).get("final_host"),
            "parsed_node_count": subscription.get("parse", {}).get("node_count"),
            "matched_controller_nodes": len(overlap),
            "tested_nodes": len(selected),
            "url_or_content_persisted": False,
        },
        "baseline_exit": baseline_exit,
        "results": results,
        "test_semantics": {
            "conversation_urls_requested": True,
            "login_cookies_shared": False,
            "messages_sent": False,
            "browser_opened": bool(open_browser),
            "meaning": "HTTP reachability and block classification through the already-running system VPN; authentication redirects are reachability evidence, not geo-block evidence",
        },
        "warnings": [
            "Changing the selected controller group affects other traffic using that system VPN during the test.",
            "Split-tunnel rules can make the tester and browser use different routes; compare exit observations and verify in the opened browser.",
            "A successful HTTP response does not prove that an authenticated chat can send messages; this mode never sends a prompt or account cookie.",
            "If the process is killed before finally runs, the companion VPN may remain on the last selected node.",
            "When open_browser is requested, the tested node is intentionally left selected so the browser can use it; restore it in the companion client when finished.",
        ],
    }
