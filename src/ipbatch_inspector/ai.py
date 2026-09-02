from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any


POLICY_SNAPSHOT = "2026-09-02"
USER_AGENT = "Mozilla/5.0 IPBatchInspector/4.0"

ENDPOINTS = (
    ("ChatGPT web", "web", "https://chatgpt.com/"),
    ("OpenAI API", "api", "https://api.openai.com/v1/models"),
    ("Claude web", "web", "https://claude.ai/"),
    ("Anthropic API", "api", "https://api.anthropic.com/v1/models"),
    ("Gemini web", "web", "https://gemini.google.com/"),
    ("Gemini API", "api", "https://generativelanguage.googleapis.com/v1beta/models"),
    ("Grok web", "web", "https://grok.com/"),
    ("xAI API", "api", "https://api.x.ai/v1/models"),
    ("Google AI Studio", "web", "https://aistudio.google.com/"),
    ("Microsoft Copilot", "web", "https://copilot.microsoft.com/"),
    ("Perplexity", "web", "https://www.perplexity.ai/"),
)

COMMON_SUPPORTED = set(
    "US CA GB AU NZ JP KR TW SG IN ID MY TH VN PH DE FR NL BE LU CH AT IT ES PT IE DK SE NO FI IS PL CZ SK SI HR RO BG GR CY MT EE LV LT UA TR IL AE SA QA KW BH OM JO LB IQ EG MA TN DZ ZA NG KE GH BR AR CL CO PE MX UY PY BO EC CR PA DO JM".split()
)
OPENAI_UNSUPPORTED = set("CN HK MO RU BY IR KP CU SY VE".split())
CLAUDE_UNSUPPORTED = set("CN HK MO RU BY IR KP CU SY VE".split())
GEMINI_UNSUPPORTED = set("CN RU IR KP CU SY".split())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _classify(code: int, body: str, kind: str) -> tuple[str, str]:
    lower = body.lower()
    unsupported = any(phrase in lower for phrase in ("not available in your country", "unsupported country", "not available in your region"))
    if unsupported:
        return "region-blocked", "response explicitly reported an unsupported country/region"
    if 200 <= code < 400:
        return "reachable", "public entrance returned a normal response"
    if kind == "api" and code in {400, 401, 403}:
        return "reachable-auth-required", "API entrance responded; no credential was sent"
    if code == 403:
        return "restricted-or-challenged", "403 may be policy, anti-bot, WAF or IP reputation; it is not labeled as a proven geo-block"
    if code == 429:
        return "reachable-rate-limited", "entrance responded with rate limiting"
    return "failed", f"HTTP {code}"


def test_ai_entrances(timeout: float = 10.0) -> list[dict[str, Any]]:
    """Use the current system route; send no cookie, account, key, or prompt."""
    results: list[dict[str, Any]] = []
    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
    for name, kind, url in ENDPOINTS:
        start = time.monotonic()
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/json"})
        try:
            with opener.open(request, timeout=timeout) as response:
                code = response.status
                body = response.read(32768).decode("utf-8", errors="replace")
            status, detail = _classify(code, body, kind)
            results.append({"name": name, "kind": kind, "host": urllib.parse.urlparse(url).hostname, "http_code": code, "status": status, "detail": detail, "checked_at": _now(), "elapsed_ms": round((time.monotonic() - start) * 1000)})
        except urllib.error.HTTPError as exc:
            body = exc.read(32768).decode("utf-8", errors="replace")
            status, detail = _classify(exc.code, body, kind)
            results.append({"name": name, "kind": kind, "host": exc.url.split("/", 3)[2], "http_code": exc.code, "status": status, "detail": detail, "checked_at": _now(), "elapsed_ms": round((time.monotonic() - start) * 1000)})
        except Exception as exc:
            results.append({"name": name, "kind": kind, "host": url.split("/", 3)[2], "http_code": None, "status": "network-error", "detail": str(exc)[:240], "checked_at": _now(), "elapsed_ms": round((time.monotonic() - start) * 1000)})
    return results


def infer_ai_policy(country_code: str, *, proxy: bool = False, vpn: bool = False, tor: bool = False, datacenter: bool = False, risk_scores: dict[str, int] | None = None) -> dict[str, str]:
    code = country_code.strip().upper()

    def policy(unsupported: set[str], workspace_only: bool = False) -> str:
        if not code:
            return "country code unavailable; no official-region match"
        if workspace_only:
            return "consumer availability not listed; official documentation only notes a Workspace scenario"
        if code in unsupported:
            return "not present in the maintained official support snapshot; likely unavailable"
        if code in COMMON_SUPPORTED or code in {"HK", "MO"}:
            return "present in the maintained official support snapshot"
        return "country code is not covered by the local snapshot; check the live official list"

    highest = max((risk_scores or {}).values(), default=None)
    if tor or (highest is not None and highest >= 67):
        risk = "high-risk signal; authentication, rate limits or rejection remain possible even in a supported region"
    elif proxy or vpn or datacenter or (highest is not None and highest >= 34):
        risk = "proxy/VPN/datacenter or medium-risk signal may trigger platform controls"
    elif not risk_scores:
        risk = "no successful source supplied a risk score; low risk cannot be claimed"
    else:
        risk = "no strong risk signal observed; this does not guarantee account or model availability"
    return {
        "snapshot_date": POLICY_SNAPSHOT,
        "openai": policy(OPENAI_UNSUPPORTED),
        "claude": policy(CLAUDE_UNSUPPORTED),
        "gemini_web": policy(GEMINI_UNSUPPORTED, workspace_only=code == "CN"),
        "grok_xai_copilot_perplexity": "no equally detailed official region snapshot is maintained; use current-device entrance checks",
        "ip_risk_inference": risk,
        "boundary": "policy and IP-intelligence inference only; the subscription node was not connected or unlock-tested",
    }
