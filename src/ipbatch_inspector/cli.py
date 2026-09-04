from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from . import __version__
from .ai import infer_ai_policy, test_ai_entrances
from .detail import detailed_investigation
from .iptools import extract_ips
from .providers import DEFAULT_SOURCES, PROVIDERS, detect_exit_ips, scan_many
from .saved import delete as delete_saved
from .saved import list_redacted, load as load_saved, save as save_subscription
from .service import inspect_subscription
from .monitor import monitor
from .realtest import AI_CONVERSATION_TARGETS, real_subscription_test


def _json(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def _table(results: list[dict[str, Any]]) -> None:
    columns = ("ip", "status", "confidence", "country_code", "country", "asn", "organization")
    def display(row: dict[str, Any], column: str) -> str:
        value = row.get(column, "")
        return str(value.get("level", "")) if column == "confidence" and isinstance(value, dict) else str(value)
    widths = {column: len(column) for column in columns}
    for row in results:
        for column in columns:
            widths[column] = min(36, max(widths[column], len(display(row, column))))
    print("  ".join(column.upper().ljust(widths[column]) for column in columns))
    print("  ".join("-" * widths[column] for column in columns))
    for row in results:
        print("  ".join(display(row, column)[: widths[column]].ljust(widths[column]) for column in columns))


def _csv(path: str, results: list[dict[str, Any]]) -> None:
    fields = [
        "ip", "status", "country", "country_code", "region", "city", "asn", "organization",
        "network_type", "prefix", "rpki", "proxy", "vpn", "tor", "datacenter", "abuser",
        "risk_scores", "signals", "consensus", "conflicts", "confidence", "ai_policy", "evidence",
    ]
    with Path(path).open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for result in results:
            row = {key: result.get(key, "") for key in fields}
            for key in ("risk_scores", "signals", "consensus", "conflicts", "confidence", "ai_policy", "evidence"):
                row[key] = json.dumps(row[key], ensure_ascii=False, default=str)
            writer.writerow(row)


def _sources(value: str) -> tuple[str, ...]:
    names = tuple(dict.fromkeys(item.strip().lower() for item in value.split(",") if item.strip()))
    unknown = [name for name in names if name not in PROVIDERS]
    if unknown:
        raise argparse.ArgumentTypeError("unknown sources: " + ", ".join(unknown))
    return names


def _scan(args: argparse.Namespace) -> int:
    values = list(args.values)
    if args.file:
        values.append(Path(args.file).read_text("utf-8"))
    ips, warnings = extract_ips(values)
    if not ips:
        print("No valid IP address was found.", file=sys.stderr)
        return 2
    results = scan_many(
        ips, args.sources, args.timeout, args.workers, fresh=args.fresh, cache_ttl=args.cache_ttl
    )
    for result in results:
        result.ai_policy = infer_ai_policy(result.country_code, proxy=result.proxy, vpn=result.vpn, tor=result.tor, datacenter=result.datacenter, risk_scores=result.risk_scores)
    rows = [item.as_dict() for item in results]
    if args.csv:
        _csv(args.csv, rows)
    if args.json:
        _json({"warnings": warnings, "results": rows})
    else:
        for warning in warnings:
            print("warning:", warning, file=sys.stderr)
        _table(rows)
        if args.csv:
            print(f"CSV written: {args.csv}")
    return 0 if any(row["status"] == "ok" for row in rows) else 1


def _subscription(args: argparse.Namespace) -> int:
    if args.saved:
        url = load_saved(args.saved)
    elif args.url_file:
        url = Path(args.url_file).read_text("utf-8").splitlines()[0].strip()
    elif args.url:
        url = args.url
    else:
        print("Provide URL, --url-file, or --saved.", file=sys.stderr)
        return 2
    data = inspect_subscription(
        url,
        allow_private=args.allow_private_subscription,
        resolve_only=args.resolve_only,
        sources=args.sources,
        timeout=args.timeout,
        workers=args.workers,
        fresh=args.fresh,
        cache_ttl=args.cache_ttl,
    )
    if args.csv and data["results"]:
        _csv(args.csv, data["results"])
    if args.json:
        if not args.list_nodes:
            data["parse"].pop("nodes", None)
        _json(data)
    else:
        parse = data["parse"]
        print(f"Nodes: {parse['node_count']} | protocols: {parse['protocols']} | public IPs: {len(data['resolution']['public_ips'])}")
        print(data["network_boundary"])
        for warning in parse["warnings"]:
            print("warning:", warning)
        if args.list_nodes:
            for node in parse.get("nodes", []):
                chain = f" via {node['chain']}" if node.get("chain") else ""
                print(f"{node['protocol'].upper():10} {node['name'][:30]:30} {node['host']}:{node.get('port') or '-'}{chain}")
        if data["results"]:
            _table(data["results"])
        if args.csv:
            print(f"CSV written: {args.csv}")
    return 0


def _subscription_value(args: argparse.Namespace) -> str:
    if getattr(args, "saved", None):
        return load_saved(args.saved)
    if getattr(args, "url_file", None):
        return Path(args.url_file).read_text("utf-8").splitlines()[0].strip()
    if getattr(args, "subscription_url", None):
        return args.subscription_url
    raise ValueError("provide a subscription URL, --url-file, or --saved")


def _detail(args: argparse.Namespace) -> int:
    _json(detailed_investigation(
        args.ip,
        timeout=args.timeout,
        tls_ports=tuple(args.tls_port),
        fresh=args.fresh,
        domestic_fallback=not args.no_domestic_fallback,
    ))
    return 0


def _realtest(args: argparse.Namespace) -> int:
    secret = os.environ.get("MIHOMO_SECRET", "")
    if args.controller_secret_file:
        secret = Path(args.controller_secret_file).read_text("utf-8").splitlines()[0].strip()
    presets = tuple(item.strip() for item in args.targets.split(",") if item.strip())
    data = real_subscription_test(
        _subscription_value(args),
        controller_url=args.controller,
        controller_secret=secret,
        group=args.group,
        nodes=args.node,
        presets=presets,
        custom_targets=args.custom_url,
        timeout=args.timeout,
        settle_seconds=args.settle,
        max_nodes=args.max_nodes,
        allow_http_targets=args.allow_http_target,
        open_browser=args.open_browser,
    )
    _json(data)
    return 0


def _saved(args: argparse.Namespace) -> int:
    if args.saved_action == "add":
        value = Path(args.url_file).read_text("utf-8").splitlines()[0].strip() if args.url_file else args.url
        if not value:
            raise ValueError("provide a URL or --url-file")
        save_subscription(args.name, value)
        print(f"Saved '{args.name}' in the operating-system credential store.")
    elif args.saved_action == "delete":
        delete_saved(args.name)
        print(f"Deleted '{args.name}'.")
    else:
        _json(list_redacted()) if args.json else [print(f"{row['name']}: {row['scheme']}://{row['host']}") for row in list_redacted()]
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipbatch",
        description="Evidence-first IP inspector with separate read-only subscription and explicit real system-VPN test modes",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan IPs, CIDRs, or mixed text")
    scan.add_argument("values", nargs="*")
    scan.add_argument("--file")
    scan.add_argument("--sources", type=_sources, default=DEFAULT_SOURCES)
    scan.add_argument("--timeout", type=float, default=12.0)
    scan.add_argument("--workers", type=int, default=4)
    scan.add_argument("--fresh", action="store_true", help="bypass the provider-evidence cache")
    scan.add_argument("--cache-ttl", type=int, help="override every source cache TTL in seconds")
    scan.add_argument("--json", action="store_true")
    scan.add_argument("--csv")
    scan.set_defaults(func=_scan)

    detail = sub.add_parser("detail", help="investigate exactly one public IP using registration, routing, passive-security and TLS evidence")
    detail.add_argument("ip")
    detail.add_argument("--timeout", type=float, default=12.0)
    detail.add_argument("--tls-port", type=int, action="append", default=[443], help="TLS port to contact; repeatable, default 443")
    detail.add_argument("--fresh", action="store_true", help="bypass the standard provider cache")
    detail.add_argument("--no-domestic-fallback", action="store_true")
    detail.set_defaults(func=_detail)

    exit_parser = sub.add_parser("exit", help="detect this process's current exit IP")
    exit_parser.add_argument("--timeout", type=float, default=8.0)
    exit_parser.add_argument("--json", action="store_true")
    exit_parser.set_defaults(func=lambda args: (_json(detect_exit_ips(args.timeout)) or 0))

    subscription = sub.add_parser("subscription", help="download and inspect a subscription without connecting nodes")
    subscription.add_argument("url", nargs="?")
    subscription.add_argument("--url-file")
    subscription.add_argument("--saved")
    subscription.add_argument("--allow-private-subscription", action="store_true")
    subscription.add_argument("--resolve-only", action="store_true")
    subscription.add_argument("--list-nodes", action="store_true")
    subscription.add_argument("--sources", type=_sources, default=DEFAULT_SOURCES)
    subscription.add_argument("--timeout", type=float, default=12.0)
    subscription.add_argument("--workers", type=int, default=4)
    subscription.add_argument("--fresh", action="store_true", help="bypass the provider-evidence cache")
    subscription.add_argument("--cache-ttl", type=int, help="override every source cache TTL in seconds")
    subscription.add_argument("--json", action="store_true")
    subscription.add_argument("--csv")
    subscription.set_defaults(func=_subscription)

    ai = sub.add_parser("ai", help="test public AI entrances over the current system route")
    ai.add_argument("--timeout", type=float, default=10.0)
    ai.add_argument("--json", action="store_true")
    ai.set_defaults(func=lambda args: (_json(test_ai_entrances(args.timeout)) or 0))

    realtest = sub.add_parser("realtest", help="switch matching subscription nodes through a local Mihomo controller and test real conversation URLs")
    realtest.add_argument("subscription_url", nargs="?")
    realtest.add_argument("--url-file")
    realtest.add_argument("--saved")
    realtest.add_argument("--controller", default="http://127.0.0.1:9090")
    realtest.add_argument("--controller-secret-file", help="read the local controller secret from a file; MIHOMO_SECRET is also supported")
    realtest.add_argument("--group", help="Mihomo/Clash selector group; auto-detected when omitted")
    realtest.add_argument("--node", action="append", default=[], help="exact subscription node name; repeatable; default tests matching nodes")
    realtest.add_argument("--targets", default="all", help="comma-separated preset names or 'all' (default: all built-in conversation URLs)")
    realtest.add_argument("--custom-url", action="append", default=[], help="custom public HTTPS domain or URL; repeatable")
    realtest.add_argument("--max-nodes", type=int, default=20, help="safety cap, 1-50")
    realtest.add_argument("--settle", type=float, default=1.5, help="seconds to wait after switching a node")
    realtest.add_argument("--timeout", type=float, default=12.0)
    realtest.add_argument("--allow-http-target", action="store_true", help="allow explicit public HTTP custom targets")
    realtest.add_argument("--open-browser", action="store_true", help="only with one node; leave it selected and open conversation pages")
    realtest.set_defaults(func=_realtest)

    formats = sub.add_parser("formats", help="show supported subscription formats")
    formats.set_defaults(func=lambda args: (print(
        "Clash/Mihomo YAML, Base64, SS, SSR, VMess, VLESS, Trojan, Hysteria, Hysteria2/Hy2, "
        "TUIC, SOCKS4/5, HTTP(S) proxy URI, dialer-proxy, proxy-providers, sn://subscription, "
        "fsl64/fslyaml passthrough; realtest presets: " + ", ".join(AI_CONVERSATION_TARGETS)
    ) or 0))

    saved = sub.add_parser("saved", help="manage subscription URLs in the OS credential store")
    saved_sub = saved.add_subparsers(dest="saved_action", required=True)
    saved_list = saved_sub.add_parser("list")
    saved_list.add_argument("--json", action="store_true")
    saved_list.set_defaults(func=_saved)
    saved_add = saved_sub.add_parser("add")
    saved_add.add_argument("name")
    saved_add.add_argument("url", nargs="?")
    saved_add.add_argument("--url-file")
    saved_add.set_defaults(func=_saved)
    saved_delete = saved_sub.add_parser("delete")
    saved_delete.add_argument("name")
    saved_delete.set_defaults(func=_saved)

    monitor_parser = sub.add_parser("monitor", help="run a repeatable background check from a non-secret JSON config")
    monitor_parser.add_argument("--config", required=True)
    monitor_parser.add_argument("--once", action="store_true", help="run one cycle for validation")
    monitor_parser.set_defaults(func=lambda args: monitor(args.config, args.once))
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"error: {str(exc)[:400]}", file=sys.stderr)
        return 1
