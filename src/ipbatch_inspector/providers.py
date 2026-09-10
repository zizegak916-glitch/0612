from __future__ import annotations

import ipaddress
import html
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter, defaultdict
from datetime import datetime, timezone
from threading import Lock, Semaphore
from typing import Any, Callable

from .cache import EvidenceCache, SOURCE_TTLS
from .iptools import is_public_ip
from .models import IntelResult, SourceEvidence


DEFAULT_SOURCES = ("ipapi", "proxycheck", "geojs", "rdap", "ripestat")
USER_AGENT = "IPBatchInspector/6.0.0-alpha.2 (+https://github.com/zizegak916-glitch/0612)"
MAX_RESPONSE = 2 * 1024 * 1024
SOURCE_CONCURRENCY = {"ipapi": 4, "proxycheck": 4, "geojs": 8, "rdap": 1, "ripestat": 8, "ping0": 4, "cngeo": 2}
SOURCE_INTERVALS = {"rdap": 1.05}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fetch_json(url: str, timeout: float = 12.0, headers: dict[str, str] | None = None) -> Any:
    request_headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    request_headers.update(headers or {})
    last_error: BaseException | None = None
    for attempt in range(2):
        request = urllib.request.Request(url, headers=request_headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read(MAX_RESPONSE + 1)
                if len(body) > MAX_RESPONSE:
                    raise ValueError("response exceeded 2 MiB")
                return json.loads(body.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            last_error = exc
            if attempt or exc.code not in {429, 500, 502, 503, 504}:
                raise
            retry_after = exc.headers.get("Retry-After", "")
            try:
                delay = min(2.0, max(0.2, float(retry_after)))
            except ValueError:
                delay = 0.35
            time.sleep(delay)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = exc
            if attempt:
                raise
            time.sleep(0.25)
    raise last_error or RuntimeError("request failed")


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
    query = {"vpn": "1", "asn": "1", "risk": "1", "seen": "1"}
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


def _cngeo(ip: str, timeout: float) -> dict[str, Any]:
    """Lower-trust mainland-accessible fallback. It is not queried while global geo sources are sufficient."""
    request = urllib.request.Request(
        "https://www.cip.cc/" + urllib.parse.quote(ip, safe=""),
        headers={"Accept": "text/html", "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(512 * 1024 + 1)
        if len(body) > 512 * 1024:
            raise ValueError("domestic fallback response exceeded 512 KiB")
    text = html.unescape(body.decode("utf-8", "replace"))
    match = re.search(r"<pre[^>]*>(.*?)</pre>", text, re.I | re.S)
    if not match:
        raise ValueError("domestic fallback did not contain a result block")
    plain = re.sub(r"<[^>]+>", "", match.group(1))
    values: dict[str, str] = {}
    for line in plain.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            values[key.strip()] = value.strip()
    returned = values.get("IP", "")
    if not returned or ipaddress.ip_address(returned) != ipaddress.ip_address(ip):
        raise ValueError("domestic fallback returned a different target IP")
    english = values.get("数据三", "").split()
    fields: dict[str, Any] = {
        "country": values.get("地址") or (english[0] if english else ""),
        "organization": values.get("运营商"),
        "domestic_secondary": values.get("数据二"),
        "english_location": values.get("数据三"),
        "trust_tier": "fallback-unverified",
        "confidence_effect": "cannot raise high confidence by itself",
    }
    return {key: value for key, value in fields.items() if value not in (None, "")}


PROVIDERS: dict[str, Callable[[str, float], dict[str, Any]]] = {
    "ipapi": _ipapi,
    "proxycheck": _proxycheck,
    "geojs": _geojs,
    "rdap": _rdap,
    "ripestat": _ripestat,
    "ping0": _ping0,
    "cngeo": _cngeo,
}


class _ProviderGate:
    def __init__(self) -> None:
        self.semaphores = {name: Semaphore(limit) for name, limit in SOURCE_CONCURRENCY.items()}
        self.interval_locks = {name: Lock() for name in SOURCE_INTERVALS}
        self.last_started = {name: 0.0 for name in SOURCE_INTERVALS}

    def call(self, source: str, function: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        semaphore = self.semaphores.get(source)
        if semaphore is None:
            return function()
        with semaphore:
            interval = SOURCE_INTERVALS.get(source)
            if interval:
                with self.interval_locks[source]:
                    delay = interval - (time.monotonic() - self.last_started[source])
                    if delay > 0:
                        time.sleep(delay)
                    self.last_started[source] = time.monotonic()
            return function()


_GATE = _ProviderGate()


def _format_asn(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    digits = "".join(char for char in text if char.isdigit())
    return f"AS{digits}" if digits else text


def _merge(result: IntelResult, evidence: SourceEvidence) -> None:
    result.evidence.append(evidence)


def _normal_value(field: str, value: object) -> str:
    text = " ".join(str(value or "").strip().split())
    if field == "country_code":
        return text.upper()
    if field == "asn":
        return _format_asn(text).upper()
    return text.casefold()


def _select_consensus(
    result: IntelResult,
    field: str,
    source_priority: tuple[str, ...],
    *,
    aliases: tuple[str, ...] = (),
) -> str:
    observations: list[tuple[str, str, str]] = []
    keys = (field,) + aliases
    for evidence in result.evidence:
        if not evidence.ok:
            continue
        value = next((evidence.fields.get(key) for key in keys if evidence.fields.get(key) not in (None, "")), None)
        if value is None:
            continue
        display = _format_asn(value) if field == "asn" else str(value).strip()
        observations.append((evidence.source, _normal_value(field, display), display))
    if not observations:
        return ""
    counts = Counter(normal for _, normal, _ in observations)
    highest = max(counts.values())
    candidates = {value for value, count in counts.items() if count == highest}
    chosen_normal = ""
    for source in source_priority:
        match = next((normal for observed_source, normal, _ in observations if observed_source == source and normal in candidates), None)
        if match:
            chosen_normal = match
            break
    if not chosen_normal:
        chosen_normal = sorted(candidates)[0]
    chosen_display = next(display for _, normal, display in observations if normal == chosen_normal)
    values: dict[str, list[str]] = defaultdict(list)
    displays: dict[str, str] = {}
    for source, normal, display in observations:
        values[normal].append(source)
        displays.setdefault(normal, display)
    result.consensus[field] = {
        "value": chosen_display,
        "agree": counts[chosen_normal],
        "observed": len(observations),
        "sources": [source for source, normal, _ in observations if normal == chosen_normal],
    }
    if len(values) > 1:
        result.conflicts.append(
            {"field": field, "values": {displays[value]: sources for value, sources in values.items()}}
        )
    return chosen_display


def _finalize(result: IntelResult) -> None:
    provider_evidence = [e for e in result.evidence if e.source != "local-rule"]
    successful = [e for e in provider_evidence if e.ok]
    if not successful:
        result.status = "failed"
        result.confidence = {
            "level": "none",
            "successful_sources": 0,
            "failed_sources": len(provider_evidence),
            "successful_source_names": [],
            "failed_source_names": [e.source for e in provider_evidence],
            "cached_sources": 0,
            "reason": "no provider returned usable evidence",
        }
        return

    geo_priority = ("ipapi", "geojs", "proxycheck", "ping0", "cngeo")
    result.country_code = _select_consensus(result, "country_code", geo_priority)
    result.country = _select_consensus(result, "country", geo_priority)
    result.region = _select_consensus(result, "region", geo_priority)
    result.city = _select_consensus(result, "city", geo_priority)
    result.asn = _select_consensus(result, "asn", ("ripestat", "ipapi", "geojs", "proxycheck", "ping0", "cngeo"), aliases=("origin_asn",))
    result.organization = _select_consensus(result, "organization", ("ipapi", "geojs", "proxycheck", "ping0", "cngeo"))
    result.network_type = _select_consensus(result, "network_type", ("ipapi", "proxycheck", "ping0"))
    result.prefix = _select_consensus(result, "prefix", ("ripestat",))
    result.rpki = _select_consensus(result, "rpki", ("ripestat",))

    for flag in ("proxy", "vpn", "tor", "datacenter", "abuser"):
        positives = [e.source for e in successful if flag in e.fields and bool(e.fields[flag])]
        negatives = [e.source for e in successful if flag in e.fields and not bool(e.fields[flag])]
        unknown = [e.source for e in provider_evidence if not e.ok or flag not in e.fields]
        if positives and negatives:
            state = "disputed"
        elif len(positives) >= 2 or (flag == "tor" and positives):
            state = "confirmed"
        elif positives:
            state = "reported"
        elif negatives:
            state = "not_reported"
        else:
            state = "unknown"
        result.signals[flag] = {
            "state": state,
            "positive_sources": positives,
            "negative_sources": negatives,
            "unknown_sources": unknown,
        }
        setattr(result, flag, bool(positives))
        if positives and negatives:
            result.conflicts.append({"field": flag, "values": {"true": positives, "false": negatives}})

    for evidence in successful:
        if evidence.fields.get("risk") is not None:
            try:
                result.risk_scores[evidence.source] = max(0, min(100, int(evidence.fields["risk"])))
            except (TypeError, ValueError):
                pass

    important_conflicts = {item["field"] for item in result.conflicts} & {"country_code", "asn"}
    country_vote = result.consensus.get("country_code", {})
    asn_vote = result.consensus.get("asn", {})
    key_fields_confirmed = country_vote.get("agree", 0) >= 2 and asn_vote.get("agree", 0) >= 2
    trusted_successful = [e for e in successful if e.source != "cngeo"]
    if len(trusted_successful) >= 3 and not important_conflicts and key_fields_confirmed:
        level, reason = "high", "at least three successful sources; country and ASN each agree across two or more sources"
    elif len(trusted_successful) >= 2:
        level, reason = "medium", "multiple sources returned evidence, but key-field agreement is incomplete or conflicts need review"
    elif len(trusted_successful) == 1:
        level, reason = "low", "only one trusted source returned usable evidence; the domestic fallback cannot raise confidence"
    else:
        level, reason = "none", "no trusted source returned usable evidence; only lower-trust fallback evidence may be present"
    result.status = "ok" if len(trusted_successful) >= 2 else "partial" if trusted_successful else "failed"
    result.confidence = {
        "level": level,
        "successful_sources": len(successful),
        "failed_sources": sum(1 for e in result.evidence if not e.ok),
        "successful_source_names": [e.source for e in successful],
        "failed_source_names": [e.source for e in provider_evidence if not e.ok],
        "cached_sources": sum(1 for e in successful if e.cache_hit),
        "reason": reason,
    }


def _query_source(
    ip: str,
    source: str,
    timeout: float,
    cache: EvidenceCache,
    fresh: bool,
    cache_ttl: int | None,
) -> SourceEvidence:
    provider = PROVIDERS.get(source)
    if provider is None:
        return SourceEvidence(source, _utc_now(), 0, False, error="unknown source")
    key_name = {"ipapi": "IPAPI_KEY", "proxycheck": "PROXYCHECK_KEY", "ping0": "PING0_KEY"}.get(source)
    variant = "keyed" if key_name and os.environ.get(key_name, "").strip() else "anonymous"
    cached = None if fresh else cache.get(source, ip, cache_ttl, variant=variant)
    if cached:
        return cached
    evidence = _source(source, lambda: _GATE.call(source, lambda: provider(ip, timeout)))
    evidence.ttl_seconds = SOURCE_TTLS.get(source, 3600) if cache_ttl is None else max(0, cache_ttl)
    cache.put(ip, evidence, variant=variant)
    return evidence


def scan_ip(
    ip: str,
    sources: tuple[str, ...] = DEFAULT_SOURCES,
    timeout: float = 12.0,
    *,
    fresh: bool = False,
    cache_ttl: int | None = None,
    domestic_fallback: bool = True,
) -> IntelResult:
    normalized = ipaddress.ip_address(ip).compressed
    result = IntelResult(normalized)
    if not is_public_ip(normalized):
        result.status = "local/reserved"
        result.evidence.append(SourceEvidence("local-rule", _utc_now(), 0, True, {"sent_to_providers": False}))
        result.confidence = {"level": "local-rule", "successful_sources": 0, "reason": "non-public address rejected locally"}
        return result
    cache = EvidenceCache()
    with ThreadPoolExecutor(max_workers=max(1, min(len(sources), 8))) as pool:
        futures = {
            source: pool.submit(_query_source, normalized, source, timeout, cache, fresh, cache_ttl)
            for source in sources
        }
        for source in sources:
            _merge(result, futures[source].result())
    geo_requested = {"ipapi", "geojs", "proxycheck", "ping0"}.intersection(sources)
    geo_ok = sum(1 for evidence in result.evidence if evidence.source in geo_requested and evidence.ok)
    if domestic_fallback and len(geo_requested) >= 2 and geo_ok < 2 and "cngeo" not in sources:
        _merge(result, _query_source(normalized, "cngeo", timeout, cache, fresh, cache_ttl))
    cache.save()
    _finalize(result)
    return result


def scan_many(
    ips: list[str],
    sources: tuple[str, ...] = DEFAULT_SOURCES,
    timeout: float = 12.0,
    workers: int = 4,
    *,
    fresh: bool = False,
    cache_ttl: int | None = None,
    domestic_fallback: bool = True,
) -> list[IntelResult]:
    ordered: list[IntelResult] = []
    public_indexes: list[int] = []
    for index, ip in enumerate(ips):
        normalized = ipaddress.ip_address(ip).compressed
        result = IntelResult(normalized)
        ordered.append(result)
        if is_public_ip(normalized):
            public_indexes.append(index)
        else:
            result.status = "local/reserved"
            result.evidence.append(SourceEvidence("local-rule", _utc_now(), 0, True, {"sent_to_providers": False}))
            result.confidence = {"level": "local-rule", "successful_sources": 0, "reason": "non-public address rejected locally"}

    cache = EvidenceCache()
    worker_count = max(1, min(64, max(workers, 1) * max(1, min(len(sources), 5))))
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = {}
        for index in public_indexes:
            for source_index, source in enumerate(sources):
                future = pool.submit(_query_source, ordered[index].ip, source, timeout, cache, fresh, cache_ttl)
                futures[future] = (index, source_index)
        evidence_by_result: dict[int, dict[int, SourceEvidence]] = defaultdict(dict)
        for future in as_completed(futures):
            index, source_index = futures[future]
            evidence_by_result[index][source_index] = future.result()

    for index in public_indexes:
        for source_index in range(len(sources)):
            _merge(ordered[index], evidence_by_result[index][source_index])
    geo_requested = {"ipapi", "geojs", "proxycheck", "ping0"}.intersection(sources)
    fallback_indexes = [
        index for index in public_indexes
        if domestic_fallback
        and len(geo_requested) >= 2
        and "cngeo" not in sources
        and sum(1 for evidence in ordered[index].evidence if evidence.source in geo_requested and evidence.ok) < 2
    ]
    if fallback_indexes:
        with ThreadPoolExecutor(max_workers=min(2, len(fallback_indexes))) as pool:
            fallback_futures = {
                index: pool.submit(_query_source, ordered[index].ip, "cngeo", timeout, cache, fresh, cache_ttl)
                for index in fallback_indexes
            }
            for index in fallback_indexes:
                _merge(ordered[index], fallback_futures[index].result())
    for index in public_indexes:
        _finalize(ordered[index])
    cache.save()
    return ordered


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
