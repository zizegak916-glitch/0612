from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Iterable


MAX_IPS = 500
MAX_CIDR_ADDRESSES = 4096


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def normalize_ip(value: str) -> str:
    return ipaddress.ip_address(value.strip().strip("[]")).compressed


def extract_ips(values: Iterable[str], max_ips: int = MAX_IPS) -> tuple[list[str], list[str]]:
    """Extract unique addresses/CIDRs without ever doing network I/O."""
    found: list[str] = []
    seen: set[str] = set()
    warnings: list[str] = []

    def add(ip: str) -> None:
        normalized = normalize_ip(ip)
        if normalized not in seen and len(found) < max_ips:
            seen.add(normalized)
            found.append(normalized)

    for original in values:
        for token in re.split(r"[\s,;|]+", original):
            candidate = token.strip("(){}<>\"'")
            if not candidate:
                continue
            if "/" in candidate:
                try:
                    network = ipaddress.ip_network(candidate, strict=False)
                except ValueError:
                    pass
                else:
                    if network.num_addresses > MAX_CIDR_ADDRESSES:
                        warnings.append(f"CIDR {candidate} exceeds {MAX_CIDR_ADDRESSES} addresses and was skipped")
                        continue
                    for address in network:
                        if len(found) >= max_ips:
                            break
                        add(str(address))
                    continue
            try:
                add(candidate)
                continue
            except ValueError:
                pass
            for embedded in re.findall(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])", candidate):
                try:
                    add(embedded)
                except ValueError:
                    continue
        if len(found) >= max_ips:
            warnings.append(f"input truncated at {max_ips} unique addresses")
            break
    return found, warnings


def resolve_node_host(host: str) -> tuple[list[str], list[str]]:
    """Resolve a node hostname only. The node's declared port is intentionally absent."""
    try:
        literal = normalize_ip(host)
        return ([literal], []) if is_public_ip(literal) else ([], [literal])
    except ValueError:
        pass
    public: list[str] = []
    local: list[str] = []
    for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
        ip = normalize_ip(info[4][0])
        bucket = public if is_public_ip(ip) else local
        if ip not in bucket:
            bucket.append(ip)
    return public, local
