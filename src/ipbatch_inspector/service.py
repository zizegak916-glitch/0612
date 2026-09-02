from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

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
) -> dict[str, Any]:
    """Download, parse, DNS-resolve and optionally enrich. It never uses node ports."""
    normalized_url = subscription_url_from_input(url)
    used_format_fallback = False
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
    parser = SubscriptionParser()
    report = parser.parse(downloaded.text, source="main subscription")

    provider_failures: list[str] = []
    provider_urls = list(report.provider_urls[:MAX_PROVIDER_DOCUMENTS])
    for index, provider_url in enumerate(provider_urls, start=1):
        try:
            provider_doc = download_text(provider_url, allow_private=allow_private, timeout=timeout)
            parser.merge(report, parser.parse(provider_doc.text, source=f"proxy-provider-{index}"))
        except Exception as exc:
            provider_failures.append(f"proxy-provider-{index}: {str(exc)[:200]}")

    resolution = resolve_nodes(report.nodes)
    results = [] if resolve_only else scan_many(resolution["public_ips"], sources, timeout, workers)
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
        "network_boundary": "subscription documents + OS DNS + public-IP intelligence only; no node port was connected",
    }
