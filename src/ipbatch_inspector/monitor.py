from __future__ import annotations

import json
import os
import signal
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .ai import infer_ai_policy, test_ai_entrances
from .detail import detailed_investigation
from .iptools import extract_ips
from .providers import DEFAULT_SOURCES, detect_exit_ips, scan_many
from .saved import load as load_saved
from .service import inspect_subscription
from .realtest import real_subscription_test


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _signature(mode: str, result: Any) -> Any:
    if mode == "exit":
        return result.get("exit_ips", [])
    if mode in {"scan", "subscription"}:
        rows = result if mode == "scan" else result.get("results", [])
        return {row.get("ip"): (row.get("status"), row.get("country_code"), row.get("asn"), row.get("risk_scores")) for row in rows}
    if mode == "ai":
        return {row.get("name"): (row.get("status"), row.get("http_code")) for row in result}
    if mode == "detail":
        return {
            "ip": result.get("ip"),
            "standard": result.get("standard_intelligence", {}).get("confidence"),
            "tls": [(row.get("source"), row.get("ok"), row.get("fields", {}).get("certificate", {}).get("sha256")) for row in result.get("tls_evidence", [])],
        }
    if mode == "realtest":
        return {
            row.get("node"): {
                target.get("url"): (target.get("verdict"), target.get("status"))
                for target in row.get("targets", [])
            }
            for row in result.get("results", [])
        }
    return result


def run_action(config: dict[str, Any]) -> Any:
    mode = str(config.get("mode", "exit")).lower()
    timeout = float(config.get("timeout", 12))
    if mode == "exit":
        return detect_exit_ips(timeout)
    if mode == "ai":
        return test_ai_entrances(timeout)
    if mode == "scan":
        ips, warnings = extract_ips([str(value) for value in config.get("targets", [])])
        results = scan_many(ips, tuple(config.get("sources", DEFAULT_SOURCES)), timeout, int(config.get("workers", 4)))
        for item in results:
            item.ai_policy = infer_ai_policy(item.country_code, proxy=item.proxy, vpn=item.vpn, tor=item.tor, datacenter=item.datacenter, risk_scores=item.risk_scores)
        return {"warnings": warnings, "results": [item.as_dict() for item in results]}
    if mode == "subscription":
        saved_name = str(config.get("saved_subscription", "")).strip()
        if not saved_name:
            raise ValueError("monitor subscription mode requires saved_subscription; raw secret URLs are not accepted in config")
        return inspect_subscription(
            load_saved(saved_name),
            allow_private=bool(config.get("allow_private_subscription", False)),
            resolve_only=bool(config.get("resolve_only", False)),
            sources=tuple(config.get("sources", DEFAULT_SOURCES)),
            timeout=timeout,
            workers=int(config.get("workers", 4)),
        )
    if mode == "detail":
        targets = [str(value).strip() for value in config.get("targets", []) if str(value).strip()]
        if len(targets) != 1:
            raise ValueError("monitor detail mode requires exactly one public IP in targets")
        return detailed_investigation(
            targets[0], timeout=timeout,
            tls_ports=tuple(int(value) for value in config.get("tls_ports", [443])),
            fresh=bool(config.get("fresh", False)),
            domestic_fallback=bool(config.get("domestic_fallback", True)),
        )
    if mode == "realtest":
        saved_name = str(config.get("saved_subscription", "")).strip()
        if not saved_name:
            raise ValueError("monitor realtest mode requires saved_subscription; raw secret URLs are not accepted in config")
        if bool(config.get("open_browser", False)):
            raise ValueError("background realtest does not allow open_browser")
        secret = os.environ.get("MIHOMO_SECRET", "")
        secret_file = str(config.get("controller_secret_file", "")).strip()
        if secret_file:
            secret = Path(secret_file).expanduser().read_text("utf-8").splitlines()[0].strip()
        return real_subscription_test(
            load_saved(saved_name),
            controller_url=str(config.get("controller", "http://127.0.0.1:9090")),
            controller_secret=secret,
            group=str(config.get("group", "")).strip() or None,
            nodes=tuple(str(value) for value in config.get("nodes", [])),
            presets=tuple(str(value) for value in config.get("targets", ["all"])),
            custom_targets=tuple(str(value) for value in config.get("custom_urls", [])),
            timeout=timeout,
            settle_seconds=float(config.get("settle_seconds", 1.5)),
            max_nodes=int(config.get("max_nodes", 20)),
            open_browser=False,
        )
    raise ValueError("monitor mode must be exit, ai, scan, subscription, detail, or realtest")


def run_once(config: dict[str, Any], output_directory: Path) -> dict[str, Any]:
    mode = str(config.get("mode", "exit")).lower()
    output_directory.mkdir(parents=True, exist_ok=True)
    history = output_directory / "history"
    history.mkdir(exist_ok=True)
    previous: dict[str, Any] | None = None
    latest = output_directory / "latest.json"
    try:
        previous = json.loads(latest.read_text("utf-8"))
    except (OSError, ValueError):
        pass
    result = run_action(config)
    document = {
        "mode": mode,
        "checked_at": _now(),
        "result": result,
        "changed": previous is None or _signature(mode, previous.get("result")) != _signature(mode, result),
        "previous_checked_at": previous.get("checked_at") if previous else None,
    }
    timestamp = document["checked_at"].replace(":", "-")
    rendered = json.dumps(document, ensure_ascii=False, indent=2, default=str)
    temporary = output_directory / "latest.tmp"
    temporary.write_text(rendered, "utf-8")
    temporary.replace(latest)
    (history / f"{timestamp}.json").write_text(rendered, "utf-8")
    keep = max(1, min(100, int(config.get("history_limit", 10))))
    for stale in sorted(history.glob("*.json"), reverse=True)[keep:]:
        stale.unlink()
    return document


def monitor(config_path: str, once: bool = False) -> int:
    path = Path(config_path).expanduser().resolve()
    config = json.loads(path.read_text("utf-8"))
    interval = max(60, int(config.get("interval_seconds", 900)))
    output = Path(config.get("output_directory", path.parent / "monitor-results")).expanduser()
    stopped = threading.Event()

    def stop(*_: object) -> None:
        stopped.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    while not stopped.is_set():
        document = run_once(config, output)
        print(json.dumps({"checked_at": document["checked_at"], "changed": document["changed"], "mode": document["mode"]}), flush=True)
        if once:
            return 0
        stopped.wait(interval)
    return 0
