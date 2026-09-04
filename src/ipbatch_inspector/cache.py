from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from .models import SourceEvidence


SOURCE_TTLS = {
    "ipapi": 6 * 60 * 60,
    "proxycheck": 30 * 60,
    "geojs": 24 * 60 * 60,
    "rdap": 7 * 24 * 60 * 60,
    "ripestat": 15 * 60,
    "ping0": 30 * 60,
    "cngeo": 24 * 60 * 60,
}
MAX_CACHE_ENTRIES = 20_000
ERROR_BACKOFF_SECONDS = 60


def default_cache_path() -> Path:
    explicit = os.environ.get("IPBATCH_CACHE_DIR", "").strip()
    if explicit:
        root = Path(explicit)
    elif os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        root = Path(os.environ["LOCALAPPDATA"]) / "IPBatchInspector"
    else:
        root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "ipbatch-inspector"
    return root / "provider-evidence-v1.json"


class EvidenceCache:
    """Thread-safe evidence cache with short failure backoff; subscription URLs are never stored."""

    def __init__(self, path: Path | None = None, *, enabled: bool = True):
        self.path = path or default_cache_path()
        self.enabled = enabled
        self._lock = threading.Lock()
        self._dirty = False
        self._items: dict[str, dict[str, Any]] = {}
        if enabled:
            self._load()

    @staticmethod
    def _key(source: str, ip: str, variant: str = "") -> str:
        return f"{source}:{variant}|{ip}"

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text("utf-8"))
            if isinstance(data, dict) and data.get("version") == 1 and isinstance(data.get("items"), dict):
                self._items = data["items"]
        except (OSError, ValueError, TypeError):
            self._items = {}

    def get(self, source: str, ip: str, ttl_override: int | None = None, *, variant: str = "") -> SourceEvidence | None:
        if not self.enabled:
            return None
        ttl = SOURCE_TTLS.get(source, 3600) if ttl_override is None else max(0, ttl_override)
        with self._lock:
            item = self._items.get(self._key(source, ip, variant))
            if not isinstance(item, dict):
                return None
            age = max(0, int(time.time() - float(item.get("stored_at", 0))))
            ok = bool(item.get("ok", True))
            effective_ttl = ttl if ok else ERROR_BACKOFF_SECONDS
            if age > effective_ttl or not isinstance(item.get("fields"), dict):
                return None
            return SourceEvidence(
                source=source,
                fetched_at=str(item.get("fetched_at") or ""),
                elapsed_ms=0,
                ok=ok,
                fields=item["fields"],
                error=str(item.get("error") or ""),
                cache_hit=True,
                cache_age_seconds=age,
                ttl_seconds=effective_ttl,
            )

    def put(self, ip: str, evidence: SourceEvidence, *, variant: str = "") -> None:
        if not self.enabled or evidence.cache_hit:
            return
        with self._lock:
            self._items[self._key(evidence.source, ip, variant)] = {
                "stored_at": time.time(),
                "fetched_at": evidence.fetched_at,
                "ok": evidence.ok,
                "fields": evidence.fields,
                "error": evidence.error,
            }
            self._dirty = True

    def save(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            if not self._dirty:
                return
            if len(self._items) > MAX_CACHE_ENTRIES:
                newest = sorted(
                    self._items.items(), key=lambda pair: float(pair[1].get("stored_at", 0)), reverse=True
                )[:MAX_CACHE_ENTRIES]
                self._items = dict(newest)
            payload = json.dumps({"version": 1, "items": self._items}, ensure_ascii=False, separators=(",", ":"))
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                temporary = self.path.with_suffix(self.path.suffix + ".tmp")
                temporary.write_text(payload, "utf-8")
                temporary.replace(self.path)
                self._dirty = False
            except OSError:
                # Cache failures must never fail a scan.
                return
