from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from .ai import infer_ai_policy
from .downloader import download_text
from .models import SubscriptionReport
from .providers import DEFAULT_SOURCES, scan_many
from .subscriptions import MAX_PROVIDER_DOCUMENTS, SubscriptionParser, alternate_fsl_url, resolve_nodes, subscription_url_from_input


def inspect_subscription(
    url: str,
    *,
    allow_private: bool = False,
    resolve_only: bool = False,
    sources: tuple[str, ...] = DEFAULT_SOURCES,
    timeout: float = 12.0,
    workers: int = 4,
    fresh: bool = False,
    cache_ttl: int | None = None,
) -> dict[str, Any]:
    """Download, parse, DNS-resolve and optionally enrich. It never uses node ports."""
    normalized_url = subscription_url_from_input(url)
    used_format_fallback = False
    started = time.monotonic()
    try:
        downloaded = download_text(normalized_url, allow_private=allow_private, timeout=timeout)
    except Exception as first_error:
        alternate = alternate_fsl_url(normalized_url)
        if not alternate:
            raise
        try:
            downloaded = download_text(alternate, allow_private=allow_private, timeout=timeout)
            used_format_fallback = True
        except Exception as second_error:
            raise RuntimeError(f"primary format failed: {first_error}; alternate fsl format failed: {second_error}") from second_error
    download_ms = round((time.monotonic() - started) * 1000)
    parser = SubscriptionParser()
    report = parser.parse(downloaded.text, source="main subscription")

    provider_failures: list[str] = []
    provider_urls = list(report.provider_urls[:MAX_PROVIDER_DOCUMENTS])
    provider_documents: dict[int, object] = {}
    provider_errors: dict[int, str] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(8, len(provider_urls) or 1))) as pool:
        futures = {
            pool.submit(download_text, provider_url, allow_private=allow_private, timeout=timeout): index
            for index, provider_url in enumerate(provider_urls, start=1)
        }
        for future in as_completed(futures):
            index = futures[future]
            try:
                provider_documents[index] = future.result()
            except Exception as exc:
                provider_errors[index] = str(exc)[:200]
    for index in range(1, len(provider_urls) + 1):
        if index in provider_errors:
            provider_failures.append(f"proxy-provider-{index}: {provider_errors[index]}")
        else:
            provider_doc = provider_documents[index]
            parser.merge(report, parser.parse(provider_doc.text, source=f"proxy-provider-{index}"))

    parsed_ms = round((time.monotonic() - started) * 1000) - download_ms
    resolution_started = time.monotonic()
    resolution = resolve_nodes(report.nodes, workers=max(8, workers * 4))
    resolution_ms = round((time.monotonic() - resolution_started) * 1000)
    intelligence_started = time.monotonic()
    results = [] if resolve_only else scan_many(
        resolution["public_ips"], sources, timeout, workers, fresh=fresh, cache_ttl=cache_ttl
    )
    intelligence_ms = round((time.monotonic() - intelligence_started) * 1000)
    for item in results:
        item.ai_policy = infer_ai_policy(
            item.country_code,
            proxy=item.proxy,
            vpn=item.vpn,
            tor=item.tor,
            datacenter=item.datacenter,
            risk_scores=item.risk_scores,
        )
    public_report = report.public_dict(include_nodes=True)
    public_report["provider_failures"] = provider_failures
    return {
        "subscription": {
            "scheme": normalized_url.split(":", 1)[0].lower(),
            "final_host": urlsplit(downloaded.final_url).hostname or "",
            "bytes_read": downloaded.bytes_read,
            "content_type": downloaded.content_type,
            "raw_content_persisted": False,
            "fsl_format_fallback_used": used_format_fallback,
        },
        "parse": public_report,
        "resolution": resolution,
        "results": [item.as_dict() for item in results],
        "timings_ms": {
            "subscription_download": download_ms,
            "parse_and_provider_documents": parsed_ms,
            "dns_resolution": resolution_ms,
            "intelligence": intelligence_ms,
            "total": round((time.monotonic() - started) * 1000),
        },
        "network_boundary": "subscription documents + OS DNS + public-IP intelligence only; no node port was connected",
    }
