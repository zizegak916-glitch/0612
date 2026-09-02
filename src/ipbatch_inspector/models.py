from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class NodeEndpoint:
    protocol: str
    name: str
    host: str
    port: int | None = None
    chain: str = ""
    source: str = "subscription"

    def redacted_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "chain": self.chain,
            "source": self.source,
        }


@dataclass
class SubscriptionReport:
    nodes: list[NodeEndpoint] = field(default_factory=list)
    provider_urls: list[str] = field(default_factory=list, repr=False)
    warnings: list[str] = field(default_factory=list)
    rejected: int = 0
    duplicates: int = 0
    decoded_layers: int = 0
    chain_references: int = 0
    truncated: bool = False

    def public_dict(self, include_nodes: bool = True) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for node in self.nodes:
            counts[node.protocol] = counts.get(node.protocol, 0) + 1
        result: dict[str, Any] = {
            "node_count": len(self.nodes),
            "protocols": counts,
            "remote_provider_count": len(self.provider_urls),
            "rejected": self.rejected,
            "duplicates": self.duplicates,
            "decoded_layers": self.decoded_layers,
            "chain_references": self.chain_references,
            "truncated": self.truncated,
            "warnings": self.warnings,
        }
        if include_nodes:
            result["nodes"] = [node.redacted_dict() for node in self.nodes]
        return result


@dataclass
class SourceEvidence:
    source: str
    fetched_at: str
    elapsed_ms: int
    ok: bool
    fields: dict[str, Any] = field(default_factory=dict)
    error: str = ""


@dataclass
class IntelResult:
    ip: str
    status: str = "unknown"
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    asn: str = ""
    organization: str = ""
    network_type: str = ""
    prefix: str = ""
    rpki: str = ""
    proxy: bool = False
    vpn: bool = False
    tor: bool = False
    datacenter: bool = False
    abuser: bool = False
    risk_scores: dict[str, int] = field(default_factory=dict)
    evidence: list[SourceEvidence] = field(default_factory=list)
    ai_policy: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
