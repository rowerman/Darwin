"""Cross-task credential memory.

CTEG's credential channel matched on host plus an *optional* port/service
check, which is unsafe on benchmark targets: every scenario runs on
``localhost`` and the same ports are reused across unrelated challenges, so a
credential from challenge A could be replayed against challenge B.

This module requires the whole identity quad to match — scope, host, port and
service type — and keeps the same 14-day half-life as the behaviour it
replaces.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

log = logging.getLogger(__name__)

DEFAULT_PATH = "memory/credentials.json"
HALF_LIFE_DAYS = 14


class CredentialMemory:
    """Persistent credentials keyed by (scope, host, port, service_type)."""

    def __init__(self, storage_path: str = DEFAULT_PATH):
        self.storage_path = storage_path
        self._lock = threading.RLock()
        self._entries: List[Dict[str, Any]] = []
        self._load()

    def record(
        self,
        *,
        host: str,
        port: int | str,
        service_type: str,
        username: str,
        password: str,
        source: str = "discovered",
        scope: str = "",
        environment: str = "",
    ) -> None:
        if not host or not service_type or not username:
            return
        entry = {
            "host": str(host),
            "port": str(port),
            "service_type": str(service_type).lower(),
            "username": str(username),
            "password": str(password),
            "source": str(source),
            "scope": str(scope),
            "environment": str(environment),
            "successes": 1,
            "last_success": datetime.now().isoformat(),
        }
        with self._lock:
            for existing in self._entries:
                if self._identity(existing) == self._identity(entry):
                    existing.update({
                        "password": entry["password"],
                        "successes": int(existing.get("successes", 0)) + 1,
                        "last_success": entry["last_success"],
                    })
                    self._persist()
                    return
            self._entries.append(entry)
            self._persist()

    def lookup(
        self,
        *,
        host: str,
        port: int | str,
        service_type: str,
        scope: str = "",
        environment: str = "",
    ) -> List[Dict[str, Any]]:
        """Credentials whose full identity matches the current target."""
        wanted = (
            str(host), str(port), str(service_type).lower(),
            str(scope), str(environment),
        )
        matches = []
        with self._lock:
            for entry in self._entries:
                if self._identity(entry) != wanted:
                    continue
                if not self._is_active(entry):
                    continue
                matches.append(dict(entry))
        matches.sort(key=lambda item: int(item.get("successes", 0)), reverse=True)
        return matches

    @staticmethod
    def _identity(entry: Dict[str, Any]) -> tuple:
        return (
            str(entry.get("host", "")),
            str(entry.get("port", "")),
            str(entry.get("service_type", "")).lower(),
            str(entry.get("scope", "")),
            str(entry.get("environment", "")),
        )

    @staticmethod
    def _is_active(entry: Dict[str, Any]) -> bool:
        try:
            age_days = (
                datetime.now() - datetime.fromisoformat(str(entry.get("last_success", "")))
            ).days
        except (TypeError, ValueError):
            return True
        return age_days <= HALF_LIFE_DAYS

    def _load(self) -> None:
        path = Path(self.storage_path)
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("CredentialMemory: cannot read %s (%s)", self.storage_path, exc)
            return
        if isinstance(data, dict):
            data = data.get("credentials", [])
        self._entries = [item for item in data if isinstance(item, dict)]

    def _persist(self) -> None:
        path = Path(self.storage_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps({"credentials": self._entries}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            log.warning("CredentialMemory: cannot write %s (%s)", self.storage_path, exc)

    def count(self) -> int:
        with self._lock:
            return len(self._entries)
