from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any


POLICY_REFERENCE_CHECKED = "2026-09-09"
OPENAI_API_POLICY_SOURCE = "https://developers.openai.com/api/docs/supported-countries"
USER_AGENT = "Mozilla/5.0 IPBatchInspector/6.0.0-alpha.2"

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

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _classify(code: int, body: str, kind: str) -> tuple[str, str]:
    lower = body.lower()
    unsupported = any(phrase in lower for phrase in ("not available in your country", "unsupported country", "not available in your region"))
    if unsupported:
        return "explicit-region-message-observed", "this anonymous response contained an unavailable-region phrase; it is a time-scoped observation, not a permanent country verdict"
    if 200 <= code < 300:
        return "http-response-observed", "the anonymous public entrance returned content; login and conversation capability were not tested"
    if 300 <= code < 400:
        return "redirect-observed", "the entrance returned a redirect; it was not followed and does not establish region or account availability"
    if kind == "api" and code in {400, 401, 403}:
        return "authentication-response-observed", "the API frontend responded without a credential; model access was not tested"
    if code == 403:
        return "denial-or-challenge-observed", "403 may be policy, anti-bot, WAF or IP reputation; the cause is unproven"
    if code == 429:
        return "rate-limit-response-observed", "the entrance returned rate limiting; account and model access were not tested"
    return "other-http-response-observed", f"HTTP {code}; it is not attributed to a country without explicit evidence"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def test_ai_entrances(timeout: float = 10.0) -> list[dict[str, Any]]:
    """Use the current system route; send no cookie, account, key, or prompt."""
    def check(endpoint: tuple[str, str, str]) -> dict[str, Any]:
        name, kind, url = endpoint
        start = time.monotonic()
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/json"})
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            with opener.open(request, timeout=timeout) as response:
                code = response.status
                body = response.read(32768).decode("utf-8", errors="replace")
            status, detail = _classify(code, body, kind)
            return {"name": name, "kind": kind, "host": urllib.parse.urlparse(url).hostname, "http_code": code, "status": status, "detail": detail, "checked_at": _now(), "elapsed_ms": round((time.monotonic() - start) * 1000)}
        except urllib.error.HTTPError as exc:
            body = exc.read(32768).decode("utf-8", errors="replace")
            status, detail = _classify(exc.code, body, kind)
            return {"name": name, "kind": kind, "host": exc.url.split("/", 3)[2], "http_code": exc.code, "status": status, "detail": detail, "checked_at": _now(), "elapsed_ms": round((time.monotonic() - start) * 1000)}
        except Exception as exc:
            return {"name": name, "kind": kind, "host": url.split("/", 3)[2], "http_code": None, "status": "transport-failure", "detail": str(exc)[:240], "checked_at": _now(), "elapsed_ms": round((time.monotonic() - start) * 1000)}

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(check, endpoint) for endpoint in ENDPOINTS]
        return [future.result() for future in futures]


def build_ai_assessment(country_code: str, *, proxy: bool = False, vpn: bool = False, tor: bool = False, datacenter: bool = False, risk_scores: dict[str, int] | None = None) -> dict[str, str]:
    """Describe evidence boundaries without turning IP metadata into service availability."""
    code = country_code.strip().upper()
    highest = max((risk_scores or {}).values(), default=None)
    if tor or (highest is not None and highest >= 67):
        risk = "providers reported a high-risk signal; this may correlate with extra verification but does not prove service unavailability"
    elif proxy or vpn or datacenter or (highest is not None and highest >= 34):
        risk = "providers reported proxy/VPN/datacenter or medium-risk evidence; this is not a blocking verdict"
    elif not risk_scores:
        risk = "no successful source supplied a risk score; low risk cannot be claimed"
    else:
        risk = "no strong risk signal was reported; this does not guarantee account or model availability"
    return {
        "availability_verdict": "not-tested",
        "route_observation": "this IP was investigated as data only; it was not selected as a route and no subscription node was connected",
        "geolocation_evidence": f"provider country code is {code}" if code else "provider country code is unavailable",
        "geolocation_boundary": "an IP country code is not a ChatGPT-web, API, account, billing, or model-availability result",
        "openai_api_policy_reference": "official API country policy is a separate scope; no automatic country allow/deny verdict is produced",
        "openai_api_policy_source": OPENAI_API_POLICY_SOURCE,
        "policy_reference_checked": POLICY_REFERENCE_CHECKED,
        "ip_risk_evidence": risk,
        "integration_rule": "preserve route observations, policy references, geolocation, and reputation as separate evidence; never let one overwrite another",
        "boundary": "no supported/unsupported conclusion can be made from this IP record; use timestamped current-route observations and a separate manual logged-in conversation test",
    }
