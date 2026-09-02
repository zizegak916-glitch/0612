from __future__ import annotations

import ipaddress
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable

from .iptools import is_public_ip
from .models import IntelResult, SourceEvidence


DEFAULT_SOURCES = ("ipapi", "proxycheck", "geojs", "rdap", "ripestat")
USER_AGENT = "IPBatchInspector/4.0 (+https://github.com/zizegak916-glitch/0612)"
MAX_RESPONSE = 2 * 1024 * 1024


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fetch_json(url: str, timeout: float = 12.0, headers: dict[str, str] | None = None) -> Any:
    request_headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    request_headers.update(headers or {})
    request = urllib.request.Request(url, headers=request_headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(MAX_RESPONSE + 1)
        if len(body) > MAX_RESPONSE:
            raise ValueError("response exceeded 2 MiB")
        return json.loads(body.decode("utf-8"))


def _error_text(exc: BaseException) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}"
    text = str(exc).replace("\n", " ").strip()
    return (text[:240] or exc.__class__.__name__).replace(os.environ.get("PING0_KEY", "\0"), "[redacted]")


def _source(name: str, call: Callable[[], dict[str, Any]]) -> SourceEvidence:
    start = time.monotonic()
    try:
        fields = call()
        return SourceEvidence(name, _utc_now(), round((time.monotonic() - start) * 1000), True, fields)
    except Exception as exc:  # provider failures are evidence, not fatal scan failures
        return SourceEvidence(name, _utc_now(), round((time.monotonic() - start) * 1000), False, error=_error_text(exc))


def _ipapi(ip: str, timeout: float) -> dict[str, Any]:
    query = {"q": ip}
    if os.environ.get("IPAPI_KEY"):
        query["key"] = os.environ["IPAPI_KEY"]
    root = _fetch_json("https://api.ipapi.is/?" + urllib.parse.urlencode(query), timeout)
    if root.get("error"):
        raise ValueError(root.get("message") or "upstream rejected the query")
    returned = str(root.get("ip") or "")
    if returned and ipaddress.ip_address(returned) != ipaddress.ip_address(ip):
        raise ValueError("provider returned a different target IP")
    location = root.get("location") if isinstance(root.get("location"), dict) else root
    asn = root.get("asn") if isinstance(root.get("asn"), dict) else {}
    company = root.get("company") if isinstance(root.get("company"), dict) else {}
    fields = {
        "country": location.get("country"),
        "country_code": location.get("country_code") or location.get("countryCode"),
        "region": location.get("state") or location.get("region"),
        "city": location.get("city"),
        "asn": asn.get("asn") or root.get("asn"),
        "organization": asn.get("org") or asn.get("name") or company.get("name") or root.get("company"),
        "network_type": asn.get("type") or company.get("type"),
    }
    for key in ("is_proxy", "is_vpn", "is_tor", "is_datacenter", "is_abuser"):
        if key in root:
            fields[key[3:]] = bool(root[key])
    return {key: value for key, value in fields.items() if value not in (None, "")}


def _proxycheck(ip: str, timeout: float) -> dict[str, Any]:
    query = {"vpn": "1", "asn": "1", "risk": "1"}
    if os.environ.get("PROXYCHECK_KEY"):
        query["key"] = os.environ["PROXYCHECK_KEY"]
    root = _fetch_json(f"https://proxycheck.io/v2/{urllib.parse.quote(ip, safe='')}?" + urllib.parse.urlencode(query), timeout)
    if str(root.get("status", "")).lower() != "ok":
        raise ValueError(root.get("message") or "upstream status was not ok")
    item = root.get(ip)
    if not isinstance(item, dict):
        for key, value in root.items():
            try:
                same = ipaddress.ip_address(key) == ipaddress.ip_address(ip)
            except ValueError:
                same = False
            if same and isinstance(value, dict):
                item = value
                break
    if not isinstance(item, dict):
        raise ValueError("response did not contain the target IP")
    kind = str(item.get("type") or "")
    fields = {
        "country": item.get("country"),
        "country_code": item.get("isocode") or item.get("country_code"),
        "region": item.get("region"),
        "city": item.get("city"),
        "asn": item.get("asn"),
        "organization": item.get("organisation") or item.get("provider"),
        "network_type": kind,
        "proxy": str(item.get("proxy", "")).lower() == "yes",
        "vpn": "vpn" in kind.lower(),
        "tor": "tor" in kind.lower(),
        "risk": int(item["risk"]) if str(item.get("risk", "")).isdigit() else None,
        "last_seen": item.get("last_seen") or item.get("last seen"),
    }
    return {key: value for key, value in fields.items() if value not in (None, "")}


def _geojs(ip: str, timeout: float) -> dict[str, Any]:
    root = _fetch_json(f"https://get.geojs.io/v1/ip/geo/{urllib.parse.quote(ip, safe='')}.json", timeout)
    returned = str(root.get("ip") or "")
    if returned and ipaddress.ip_address(returned) != ipaddress.ip_address(ip):
        raise ValueError("provider returned a different target IP")
    fields = {
        "country": root.get("country"),
        "country_code": root.get("country_code"),
        "region": root.get("region"),
        "city": root.get("city"),
        "asn": root.get("asn"),
        "organization": root.get("organization_name") or root.get("organization"),
        "latitude": root.get("latitude"),
        "longitude": root.get("longitude"),
        "timezone": root.get("timezone"),
    }
    return {key: value for key, value in fields.items() if value not in (None, "")}


def _rdap(ip: str, timeout: float) -> dict[str, Any]:
    root = _fetch_json(f"https://rdap.org/ip/{urllib.parse.quote(ip, safe='')}", timeout)
    fields = {
        "start_address": root.get("startAddress"),
        "end_address": root.get("endAddress"),
        "name": root.get("name") or root.get("handle"),
        "registration_country": root.get("country"),
        "registration_type": root.get("type"),
        "registration_status": root.get("status"),
        "events": root.get("events"),
    }
    return {key: value for key, value in fields.items() if value not in (None, "", [])}


def _ripestat(ip: str, timeout: float) -> dict[str, Any]:
    encoded = urllib.parse.quote(ip, safe="")
    root = _fetch_json(f"https://stat.ripe.net/data/routing-status/data.json?resource={encoded}", timeout)
    data = root.get("data") if isinstance(root, dict) else None
    if not isinstance(data, dict):
        raise ValueError("response did not contain routing data")
    last = data.get("last_seen") if isinstance(data.get("last_seen"), dict) else {}
    prefix = last.get("prefix")
    origin = str(last.get("origin") or "").lstrip("AS")
    fields: dict[str, Any] = {
        "announced": bool(last),
        "prefix": prefix,
        "origin_asn": f"AS{origin}" if origin else "",
        "last_seen": last.get("time"),
        "first_seen": (data.get("first_seen") or {}).get("time") if isinstance(data.get("first_seen"), dict) else None,
    }
    if prefix and origin:
        try:
            rpki_root = _fetch_json(
                "https://stat.ripe.net/data/rpki-validation/data.json?"
                + urllib.parse.urlencode({"resource": f"AS{origin}", "prefix": prefix}),
                timeout,
            )
            fields["rpki"] = (rpki_root.get("data") or {}).get("status")
        except Exception as exc:
            fields["rpki_error"] = _error_text(exc)
    return {key: value for key, value in fields.items() if value not in (None, "")}


def _ping0(ip: str, timeout: float) -> dict[str, Any]:
    key = os.environ.get("PING0_KEY", "").strip()
    if not key:
        raise ValueError("PING0_KEY is not configured")
    address = f"https://ping0.cc/apiloc/apikey({urllib.parse.quote(key, safe='')})/ip({urllib.parse.quote(ip, safe='')})"
    root = _fetch_json(address, timeout)
    return {
        key: value
        for key, value in {
            "country": root.get("country"),
            "country_code": root.get("country_code") or root.get("countrycode"),
            "region": root.get("province"),
            "city": root.get("city"),
            "asn": root.get("asn"),
            "organization": root.get("org") or root.get("asnname"),
            "network_type": root.get("orgtype") or root.get("asntype"),
            "datacenter": root.get("isidc"),
            "risk": root.get("iprisk"),
            "native": root.get("isnative"),
        }.items()
        if value not in (None, "")
    }


PROVIDERS: dict[str, Callable[[str, float], dict[str, Any]]] = {
    "ipapi": _ipapi,
    "proxycheck": _proxycheck,
    "geojs": _geojs,
    "rdap": _rdap,
    "ripestat": _ripestat,
    "ping0": _ping0,
}


def _format_asn(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    digits = "".join(char for char in text if char.isdigit())
    return f"AS{digits}" if digits else text


def _merge(result: IntelResult, evidence: SourceEvidence) -> None:
    result.evidence.append(evidence)
    if not evidence.ok:
        return
    fields = evidence.fields
    for attr, key in (
        ("country", "country"),
        ("country_code", "country_code"),
        ("region", "region"),
        ("city", "city"),
        ("organization", "organization"),
        ("network_type", "network_type"),
        ("prefix", "prefix"),
        ("rpki", "rpki"),
    ):
        if not getattr(result, attr) and fields.get(key) not in (None, ""):
            setattr(result, attr, str(fields[key]))
    if not result.asn:
        result.asn = _format_asn(fields.get("asn") or fields.get("origin_asn"))
    for flag in ("proxy", "vpn", "tor", "datacenter", "abuser"):
        setattr(result, flag, getattr(result, flag) or bool(fields.get(flag, False)))
    if fields.get("risk") is not None:
        try:
            result.risk_scores[evidence.source] = max(0, min(100, int(fields["risk"])))
        except (TypeError, ValueError):
            pass


def scan_ip(ip: str, sources: tuple[str, ...] = DEFAULT_SOURCES, timeout: float = 12.0) -> IntelResult:
    normalized = ipaddress.ip_address(ip).compressed
    result = IntelResult(normalized)
    if not is_public_ip(normalized):
        result.status = "local/reserved"
        result.evidence.append(SourceEvidence("local-rule", _utc_now(), 0, True, {"sent_to_providers": False}))
        return result
    for source in sources:
        provider = PROVIDERS.get(source)
        if provider is None:
            result.evidence.append(SourceEvidence(source, _utc_now(), 0, False, error="unknown source"))
            continue
        _merge(result, _source(source, lambda p=provider: p(normalized, timeout)))
    successes = sum(1 for evidence in result.evidence if evidence.ok)
    result.status = "ok" if successes else "failed"
    return result


def scan_many(
    ips: list[str],
    sources: tuple[str, ...] = DEFAULT_SOURCES,
    timeout: float = 12.0,
    workers: int = 4,
) -> list[IntelResult]:
    ordered: list[IntelResult | None] = [None] * len(ips)
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 16))) as pool:
        futures = {pool.submit(scan_ip, ip, sources, timeout): index for index, ip in enumerate(ips)}
        for future in as_completed(futures):
            ordered[futures[future]] = future.result()
    return [item for item in ordered if item is not None]


def detect_exit_ips(timeout: float = 8.0) -> dict[str, Any]:
    endpoints = {
        "ipify-v4": "https://api.ipify.org?format=json",
        "ipify-dual": "https://api64.ipify.org?format=json",
        "icanhazip": "https://icanhazip.com/",
    }
    observations: list[dict[str, Any]] = []

    def check(name: str, url: str) -> dict[str, Any]:
        start = time.monotonic()
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json,text/plain"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                text = response.read(4096).decode("utf-8", errors="replace").strip()
            if text.startswith("{"):
                value = str(json.loads(text).get("ip") or "")
            else:
                value = text.split()[0] if text else ""
            value = ipaddress.ip_address(value).compressed
            return {"source": name, "ok": True, "ip": value, "elapsed_ms": round((time.monotonic() - start) * 1000), "checked_at": _utc_now()}
        except Exception as exc:
            return {"source": name, "ok": False, "error": _error_text(exc), "elapsed_ms": round((time.monotonic() - start) * 1000), "checked_at": _utc_now()}

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(check, name, url) for name, url in endpoints.items()]
        observations = [future.result() for future in futures]
    unique = list(dict.fromkeys(item["ip"] for item in observations if item.get("ok")))
    return {
        "exit_ips": unique,
        "agreement": "all successful sources agree" if len(unique) == 1 else ("sources disagree or IPv4/IPv6 differ" if unique else "no successful source"),
        "observations": observations,
        "meaning": "addresses observed for this process over the operating system's current default route",
    }
