from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlsplit


SERVICE = "IPBatchInspector"
MAX_SAVED = 20


class SecureStoreUnavailable(RuntimeError):
    pass


def _keyring():
    try:
        import keyring  # type: ignore
    except ImportError as exc:
        raise SecureStoreUnavailable("install ipbatch-inspector[secure-store] to save URLs") from exc
    return keyring


def _index_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home()))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "ipbatch-inspector" / "subscriptions.json"


def _load_index() -> list[str]:
    path = _index_path()
    try:
        data = json.loads(path.read_text("utf-8"))
        return [str(item) for item in data if isinstance(item, str)][:MAX_SAVED]
    except (OSError, ValueError, TypeError):
        return []


def _save_index(names: list[str]) -> None:
    path = _index_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(names, ensure_ascii=False, indent=2), "utf-8")
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    temporary.replace(path)


def save(name: str, url: str) -> None:
    name = name.strip()
    if not name or len(name) > 80:
        raise ValueError("name must contain 1-80 characters")
    if urlsplit(url).scheme.lower() not in {"http", "https"} and not url.lower().startswith("sn://subscription"):
        raise ValueError("saved value must be a subscription URL")
    names = _load_index()
    if name not in names and len(names) >= MAX_SAVED:
        raise ValueError(f"at most {MAX_SAVED} subscriptions may be saved")
    _keyring().set_password(SERVICE, name, url)
    if name not in names:
        names.append(name)
        _save_index(names)


def load(name: str) -> str:
    value = _keyring().get_password(SERVICE, name)
    if not value:
        raise KeyError(name)
    return value


def delete(name: str) -> None:
    keyring = _keyring()
    try:
        keyring.delete_password(SERVICE, name)
    except Exception:
        pass
    _save_index([item for item in _load_index() if item != name])


def list_redacted() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for name in _load_index():
        try:
            value = load(name)
            parts = urlsplit(value if not value.lower().startswith("sn://") else "")
            host = parts.hostname or "sn://subscription"
            scheme = parts.scheme or "sn"
        except Exception:
            host, scheme = "unavailable", "unknown"
        rows.append({"name": name, "scheme": scheme, "host": host})
    return rows
