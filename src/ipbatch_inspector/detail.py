from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import os
import re
import socket
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable

from .iptools import is_public_ip
from .providers import DEFAULT_SOURCES, USER_AGENT, scan_ip


MAX_DETAIL_RESPONSE = 2 * 1024 * 1024
MAX_TLS_NAMES = 4
DETAIL_SOURCE_URLS = {
    "rdap": "https://rdap.org/ip/{ip}",
    "ripestat-network": "https://stat.ripe.net/data/network-info/data.json?resource={ip}",
    "ripestat-whois": "https://stat.ripe.net/data/whois/data.json?resource={ip}",
    "ripestat-abuse": "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource={ip}",
    "ripestat-visibility": "https://stat.ripe.net/data/visibility/data.json?resource={ip}",
    "shodan-internetdb": "https://internetdb.shodan.io/{ip}",
    "greynoise-community": "https://api.greynoise.io/v3/community/{ip}",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _error_text(exc: BaseException) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}"
    return (str(exc).replace("\n", " ").strip() or exc.__class__.__name__)[:300]


def _request(
    url: str,
    timeout: float,
    *,
    headers: dict[str, str] | None = None,
    accepted_status: set[int] | None = None,
) -> tuple[int, Any]:
    request_headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    request_headers.update(headers or {})
    request = urllib.request.Request(url, headers=request_headers)
    try:
        response = urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if not accepted_status or exc.code not in accepted_status:
            raise
        response = exc
    with response:
        body = response.read(MAX_DETAIL_RESPONSE + 1)
        if len(body) > MAX_DETAIL_RESPONSE:
            raise ValueError("response exceeded 2 MiB")
        return int(response.status), json.loads(body.decode("utf-8"))


def _record(name: str, call: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    started = time.monotonic()
    queried_at = _utc_now()
    try:
        fields = call()
        return {
            "source": name,
            "ok": True,
            "queried_at": queried_at,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "fields": fields,
        }
    except Exception as exc:
        return {
            "source": name,
            "ok": False,
            "queried_at": queried_at,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "error": _error_text(exc),
        }


def _vcard_values(entity: dict[str, Any]) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    card = entity.get("vcardArray")
    rows = card[1] if isinstance(card, list) and len(card) > 1 and isinstance(card[1], list) else []
    for row in rows:
        if not isinstance(row, list) or len(row) < 4:
            continue
        key = str(row[0]).lower()
        raw = row[3]
        text = ", ".join(str(item) for item in raw) if isinstance(raw, list) else str(raw)
        if text and key in {"fn", "org", "email", "tel", "adr"}:
            values.setdefault(key, []).append(text[:500])
    return values


def _rdap_detail(ip: str, timeout: float) -> dict[str, Any]:
    _, root = _request(DETAIL_SOURCE_URLS["rdap"].format(ip=urllib.parse.quote(ip, safe="")), timeout)
    entities = []
    for entity in root.get("entities", []) if isinstance(root, dict) else []:
        if not isinstance(entity, dict):
            continue
        entities.append({
            "handle": entity.get("handle"),
            "roles": entity.get("roles") or [],
            "public_contact": _vcard_values(entity),
        })
    notices = []
    for item in root.get("notices", []) if isinstance(root, dict) else []:
        if isinstance(item, dict):
            notices.append({"title": item.get("title"), "links": item.get("links") or []})
    return {
        "handle": root.get("handle"),
        "name": root.get("name"),
        "type": root.get("type"),
        "country": root.get("country"),
        "start_address": root.get("startAddress"),
        "end_address": root.get("endAddress"),
        "ip_version": root.get("ipVersion"),
        "parent_handle": root.get("parentHandle"),
        "status": root.get("status") or [],
        "events": root.get("events") or [],
        "entities": entities,
        "port_43": root.get("port43"),
        "notices": notices[:12],
    }


def _ripestat(ip: str, timeout: float, source: str) -> dict[str, Any]:
    url = DETAIL_SOURCE_URLS[source].format(ip=urllib.parse.quote(ip, safe=""))
    _, root = _request(url, timeout)
    if not isinstance(root, dict) or not isinstance(root.get("data"), dict):
        raise ValueError("RIPEstat response did not contain data")
    data = root["data"]
    common = {
        "data_call_status": root.get("data_call_status"),
        "cached": root.get("cached"),
        "query_id": root.get("query_id"),
        "messages": root.get("messages") or [],
    }
    if source == "ripestat-network":
        common.update({"prefix": data.get("prefix"), "asns": data.get("asns") or []})
    elif source == "ripestat-abuse":
        common.update({
            "abuse_contacts": data.get("abuse_contacts") or [],
            "authoritative_rir": data.get("authoritative_rir"),
            "earliest_time": data.get("earliest_time"),
            "latest_time": data.get("latest_time"),
        })
    elif source == "ripestat-visibility":
        common.update({
            "visibility": data.get("visibility"),
            "full_table_peers_seeing": data.get("full_table_peers_seeing"),
            "ris_peers_seeing": data.get("ris_peers_seeing"),
            "total_ris_peers": data.get("total_ris_peers"),
        })
    else:
        records = []
        for record in (data.get("records") or [])[:30]:
            if not isinstance(record, list):
                continue
            normalized = []
            for field in record[:80]:
                if isinstance(field, dict):
                    normalized.append({
                        "key": field.get("key"),
                        "value": str(field.get("value") or "")[:1000],
                        "details_link": field.get("details_link"),
                    })
            if normalized:
                records.append(normalized)
        common.update({
            "authorities": data.get("authorities") or [],
            "query_time": data.get("query_time"),
            "records": records,
            "irr_records": (data.get("irr_records") or [])[:30],
        })
    return common


def _internetdb(ip: str, timeout: float) -> dict[str, Any]:
    status, root = _request(
        DETAIL_SOURCE_URLS["shodan-internetdb"].format(ip=urllib.parse.quote(ip, safe="")),
        timeout,
        accepted_status={404},
    )
    if status == 404:
        return {"found": False, "message": root.get("detail") if isinstance(root, dict) else "not found"}
    returned = str(root.get("ip") or "")
    if returned and ipaddress.ip_address(returned) != ipaddress.ip_address(ip):
        raise ValueError("InternetDB returned a different target IP")
    return {
        "found": True,
        "hostnames": (root.get("hostnames") or [])[:100],
        "ports": (root.get("ports") or [])[:1000],
        "cves": (root.get("vulns") or [])[:1000],
        "cpes": (root.get("cpes") or [])[:500],
        "tags": (root.get("tags") or [])[:100],
        "passive_observation": True,
    }


def _greynoise(ip: str, timeout: float) -> dict[str, Any]:
    key = os.environ.get("GREYNOISE_KEY", "").strip()
    if key:
        status, root = _request(
            f"https://api.greynoise.io/v3/ip/{urllib.parse.quote(ip, safe='')}",
            timeout,
            headers={"key": key},
            accepted_status={206, 404},
        )
        return {"found": status != 404, "status": status, "result": root}
    status, root = _request(
        DETAIL_SOURCE_URLS["greynoise-community"].format(ip=urllib.parse.quote(ip, safe="")),
        timeout,
        accepted_status={404},
    )
    if not isinstance(root, dict):
        raise ValueError("GreyNoise returned a non-object response")
    returned = str(root.get("ip") or "")
    if returned and ipaddress.ip_address(returned) != ipaddress.ip_address(ip):
        raise ValueError("GreyNoise returned a different target IP")
    return {
        "found": status != 404,
        "noise": root.get("noise"),
        "riot": root.get("riot"),
        "classification": root.get("classification"),
        "name": root.get("name"),
        "last_seen": root.get("last_seen"),
        "link": root.get("link"),
        "message": root.get("message"),
    }


def _shodan_keyed(ip: str, timeout: float) -> dict[str, Any]:
    key = os.environ.get("SHODAN_KEY", "").strip()
    if not key:
        return {"enabled": False, "reason": "SHODAN_KEY is not configured"}
    _, root = _request(
        "https://api.shodan.io/shodan/host/" + urllib.parse.quote(ip, safe="") + "?" + urllib.parse.urlencode({"key": key}),
        timeout,
        accepted_status={404},
    )
    banners = []
    for item in (root.get("data") or [])[:100]:
        if not isinstance(item, dict):
            continue
        banners.append({
            "port": item.get("port"),
            "transport": item.get("transport"),
            "product": item.get("product"),
            "version": item.get("version"),
            "timestamp": item.get("timestamp"),
            "hostnames": item.get("hostnames") or [],
            "ssl": item.get("ssl"),
        })
    return {
        "enabled": True,
        "last_update": root.get("last_update"),
        "asn": root.get("asn"),
        "org": root.get("org"),
        "isp": root.get("isp"),
        "os": root.get("os"),
        "ports": root.get("ports") or [],
        "hostnames": root.get("hostnames") or [],
        "domains": root.get("domains") or [],
        "tags": root.get("tags") or [],
        "vulns": root.get("vulns") or [],
        "banners": banners,
    }


def _virustotal(ip: str, timeout: float) -> dict[str, Any]:
    key = os.environ.get("VIRUSTOTAL_KEY", "").strip()
    if not key:
        return {"enabled": False, "reason": "VIRUSTOTAL_KEY is not configured"}
    _, root = _request(
        "https://www.virustotal.com/api/v3/ip_addresses/" + urllib.parse.quote(ip, safe=""),
        timeout,
        headers={"x-apikey": key},
    )
    data = root.get("data") if isinstance(root, dict) else None
    attributes = data.get("attributes") if isinstance(data, dict) else None
    if not isinstance(attributes, dict):
        raise ValueError("VirusTotal response did not contain attributes")
    return {
        "enabled": True,
        "network": attributes.get("network"),
        "asn": attributes.get("asn"),
        "as_owner": attributes.get("as_owner"),
        "country": attributes.get("country"),
        "continent": attributes.get("continent"),
        "reputation": attributes.get("reputation"),
        "last_analysis_stats": attributes.get("last_analysis_stats"),
        "total_votes": attributes.get("total_votes"),
        "tags": attributes.get("tags") or [],
        "last_modification_date": attributes.get("last_modification_date"),
        "last_https_certificate_date": attributes.get("last_https_certificate_date"),
        "last_https_certificate": attributes.get("last_https_certificate"),
    }


def _reverse_dns(ip: str) -> dict[str, Any]:
    name, aliases, addresses = socket.gethostbyaddr(ip)
    return {"primary": name.rstrip("."), "aliases": aliases, "addresses": addresses}


def _dn(value: Any) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for group in value or []:
        for pair in group if isinstance(group, tuple) else []:
            if isinstance(pair, tuple) and len(pair) == 2:
                result.setdefault(str(pair[0]), []).append(str(pair[1]))
    return result


def _decode_certificate(der: bytes) -> dict[str, Any]:
    pem = ssl.DER_cert_to_PEM_cert(der)
    path = ""
    try:
        with tempfile.NamedTemporaryFile("w", encoding="ascii", suffix=".pem", delete=False) as handle:
            handle.write(pem)
            path = handle.name
        decoded = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
    sans = [{"type": kind, "value": value} for kind, value in decoded.get("subjectAltName", ())]
    return {
        "subject": _dn(decoded.get("subject")),
        "issuer": _dn(decoded.get("issuer")),
        "serial_number": decoded.get("serialNumber"),
        "version": decoded.get("version"),
        "not_before": decoded.get("notBefore"),
        "not_after": decoded.get("notAfter"),
        "subject_alt_names": sans[:250],
        "ocsp": decoded.get("OCSP") or [],
        "ca_issuers": decoded.get("caIssuers") or [],
        "crl_distribution_points": decoded.get("crlDistributionPoints") or [],
        "sha256": hashlib.sha256(der).hexdigest(),
        "sha1": hashlib.sha1(der).hexdigest(),  # certificate identifier only, not a trust decision
    }


def _tls_certificate(ip: str, port: int, server_name: str | None, timeout: float) -> dict[str, Any]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=server_name or ip) as tls:
            der = tls.getpeercert(binary_form=True)
            if not der:
                raise ValueError("peer did not provide a certificate")
            return {
                "target_ip": ip,
                "port": port,
                "sni": server_name or ip,
                "tls_version": tls.version(),
                "cipher": tls.cipher(),
                "alpn": tls.selected_alpn_protocol(),
                "certificate": _decode_certificate(der),
                "verification": "certificate captured without CA/hostname validation; inspect names and validity separately",
            }


def _host_points_to_ip(host: str, ip: str) -> bool:
    try:
        answers = {item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
    except OSError:
        return False
    target = ipaddress.ip_address(ip)
    return any(ipaddress.ip_address(value) == target for value in answers)


def _cip_fallback(ip: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        "https://www.cip.cc/" + urllib.parse.quote(ip, safe=""),
        headers={"Accept": "text/html", "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(512 * 1024 + 1)
        if len(body) > 512 * 1024:
            raise ValueError("cip.cc response exceeded 512 KiB")
    text = html.unescape(body.decode("utf-8", "replace"))
    match = re.search(r"<pre[^>]*>(.*?)</pre>", text, re.I | re.S)
    if not match:
        raise ValueError("cip.cc response did not contain a result block")
    plain = re.sub(r"<[^>]+>", "", match.group(1))
    fields: dict[str, str] = {}
    mapping = {"IP": "ip", "地址": "location", "运营商": "operator", "数据二": "secondary", "数据三": "english_location"}
    for line in plain.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() in mapping:
            fields[mapping[key.strip()]] = value.strip()
    returned = fields.get("ip", "")
    if not returned or ipaddress.ip_address(returned) != ipaddress.ip_address(ip):
        raise ValueError("domestic fallback did not echo the target IP")
    fields["trust_tier"] = "fallback-unverified"
    fields["warning"] = "domestic alternative source, not an authoritative registry and not used to raise confidence by itself"
    return fields


def detailed_investigation(
    ip: str,
    *,
    timeout: float = 12.0,
    tls_ports: tuple[int, ...] = (443,),
    fresh: bool = False,
    domestic_fallback: bool = True,
) -> dict[str, Any]:
    normalized = ipaddress.ip_address(ip).compressed
    if not is_public_ip(normalized):
        raise ValueError("detailed mode accepts exactly one public IP; local, reserved and documentation ranges are rejected")
    ports = tuple(dict.fromkeys(int(port) for port in tls_ports))
    if not ports or len(ports) > 8 or any(port < 1 or port > 65535 for port in ports):
        raise ValueError("provide between one and eight valid TLS ports")

    started = time.monotonic()
    standard = scan_ip(
        normalized,
        DEFAULT_SOURCES,
        timeout,
        fresh=fresh,
        domestic_fallback=domestic_fallback,
    ).as_dict()
    tasks: dict[str, Callable[[], dict[str, Any]]] = {
        "rdap-detail": lambda: _rdap_detail(normalized, timeout),
        "ripestat-network": lambda: _ripestat(normalized, timeout, "ripestat-network"),
        "ripestat-whois": lambda: _ripestat(normalized, timeout, "ripestat-whois"),
        "ripestat-abuse": lambda: _ripestat(normalized, timeout, "ripestat-abuse"),
        "ripestat-visibility": lambda: _ripestat(normalized, timeout, "ripestat-visibility"),
        "shodan-internetdb": lambda: _internetdb(normalized, timeout),
        "greynoise": lambda: _greynoise(normalized, timeout),
        "reverse-dns": lambda: _reverse_dns(normalized),
    }
    if os.environ.get("SHODAN_KEY", "").strip():
        tasks["shodan-keyed"] = lambda: _shodan_keyed(normalized, timeout)
    if os.environ.get("VIRUSTOTAL_KEY", "").strip():
        tasks["virustotal"] = lambda: _virustotal(normalized, timeout)
    with ThreadPoolExecutor(max_workers=min(8, len(tasks))) as pool:
        futures = {name: pool.submit(_record, name, call) for name, call in tasks.items()}
        evidence = [futures[name].result() for name in tasks]

    by_name = {item["source"]: item for item in evidence}
    names: list[str] = []
    reverse = by_name.get("reverse-dns", {})
    if reverse.get("ok") and reverse.get("fields", {}).get("primary"):
        names.append(reverse["fields"]["primary"])
    internetdb = by_name.get("shodan-internetdb", {})
    if internetdb.get("ok"):
        names.extend(internetdb.get("fields", {}).get("hostnames") or [])
    keyed = by_name.get("shodan-keyed", {})
    if keyed.get("ok"):
        names.extend(keyed.get("fields", {}).get("hostnames") or [])
    validated_names = []
    for name in dict.fromkeys(str(value).strip().lower().rstrip(".") for value in names if value):
        if len(validated_names) >= MAX_TLS_NAMES - 1:
            break
        if _host_points_to_ip(name, normalized):
            validated_names.append(name)

    tls_targets = [(port, None) for port in ports]
    if 443 in ports:
        tls_targets.extend((443, name) for name in validated_names)
    with ThreadPoolExecutor(max_workers=min(4, len(tls_targets))) as pool:
        tls_futures = {
            (port, name): pool.submit(_record, f"tls:{port}:{name or normalized}", lambda p=port, n=name: _tls_certificate(normalized, p, n, timeout))
            for port, name in tls_targets
        }
        tls_evidence = [tls_futures[key].result() for key in tls_futures]

    global_geo_ok = sum(
        1 for item in standard.get("evidence", [])
        if item.get("source") in {"ipapi", "geojs", "proxycheck", "ping0"} and item.get("ok")
    )
    fallback: list[dict[str, Any]] = []
    standard_cngeo = next(
        (item for item in standard.get("evidence", []) if item.get("source") == "cngeo"),
        None,
    )
    if domestic_fallback and global_geo_ok < 2:
        # Normal scans also perform this fallback. Reuse its evidence so detailed
        # mode never sends the same lower-trust lookup twice.
        if standard_cngeo:
            fallback.append(dict(standard_cngeo, source="cn-fallback-cip.cc"))
        else:
            fallback.append(_record("cn-fallback-cip.cc", lambda: _cip_fallback(normalized, timeout)))

    return {
        "mode": "single-ip-detailed-investigation",
        "ip": normalized,
        "queried_at": _utc_now(),
        "standard_intelligence": standard,
        "detail_evidence": evidence,
        "tls_evidence": tls_evidence,
        "domestic_fallback": {
            "triggered": bool(fallback),
            "reason": "fewer than two global geolocation sources succeeded" if fallback else "global sources were sufficient or fallback disabled",
            "evidence": fallback,
        },
        "optional_sources": {
            "SHODAN_KEY": "enabled" if os.environ.get("SHODAN_KEY", "").strip() else "not configured",
            "GREYNOISE_KEY": "enabled" if os.environ.get("GREYNOISE_KEY", "").strip() else "anonymous community endpoint",
            "VIRUSTOTAL_KEY": "enabled" if os.environ.get("VIRUSTOTAL_KEY", "").strip() else "not configured",
            "PING0_KEY": "enabled" if os.environ.get("PING0_KEY", "").strip() else "not configured",
        },
        "timing_ms": round((time.monotonic() - started) * 1000),
        "network_actions": {
            "passive_databases": ["RDAP", "RIPEstat", "Shodan InternetDB", "GreyNoise", "configured keyed sources"],
            "active_target_connections": [{"ip": normalized, "port": port, "purpose": "TLS certificate capture"} for port in ports],
            "port_scan_performed": False,
        },
        "limitations": [
            "No finite client can retrieve literally every public record; the report lists every source actually queried and every failure.",
            "Shodan ports/CVEs and GreyNoise classifications are passive third-party observations and may be old, incomplete or wrong.",
            "Only explicitly requested TLS ports are contacted; shared hosting can serve different certificates for unknown SNI names.",
            "RDAP registration country is not physical server location, and abuse contacts can be missing or stale.",
            "The domestic fallback is lower-trust corroboration and never raises confidence by itself.",
        ],
    }
