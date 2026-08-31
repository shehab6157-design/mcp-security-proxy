"""
run_log.py
-------------
Append-only, hash-chained log of red-team engine actions (logs/red_runs.jsonl)
- the Phase 4 counterpart to proxy/audit_log.py's tool-call log. Same
tamper-evident design (each entry embeds the SHA-256 hash of the previous
entry's canonical JSON) so the run history can be trusted when Phase 5's
purple-team scoring reads it back to check what red actually attempted
against what blue detected.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


@dataclass
class RunLogEntry:
    trace_id: str
    timestamp: str
    technique_id: str
    technique_name: str
    target: str
    executor: str
    status: str
    detail: str
    prev_hash: str
    entry_hash: str = field(init=False, default="")

    def canonical_body(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "timestamp": self.timestamp,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "target": self.target,
            "executor": self.executor,
            "status": self.status,
            "detail": self.detail,
            "prev_hash": self.prev_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self.canonical_body()
        d["entry_hash"] = self.entry_hash
        return d


def _canonical_json(body: dict[str, Any]) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


class HashChainRunLog:
    """Not thread-safe by design - the red-team orchestrator is a one-shot
    on-demand CLI run (PROJECT_SPEC.md: "NOT 24/7 autonomous"), never a
    concurrent server like proxy/server.py, so there's no concurrent-writer
    case to guard against here."""

    def __init__(self, log_path: str | Path):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.log_path.exists():
            return GENESIS_HASH
        last_hash = GENESIS_HASH
        with self.log_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                last_hash = json.loads(line)["entry_hash"]
        return last_hash

    def append(
        self,
        *,
        technique_id: str,
        technique_name: str,
        target: str,
        executor: str,
        status: str,
        detail: str,
    ) -> RunLogEntry:
        entry = RunLogEntry(
            trace_id=uuid.uuid4().hex,
            timestamp=datetime.now(timezone.utc).isoformat(),
            technique_id=technique_id,
            technique_name=technique_name,
            target=target,
            executor=executor,
            status=status,
            detail=detail,
            prev_hash=self._last_hash,
        )
        body_json = _canonical_json(entry.canonical_body())
        entry.entry_hash = hashlib.sha256(
            (entry.prev_hash + body_json).encode("utf-8")
        ).hexdigest()

        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")

        self._last_hash = entry.entry_hash
        return entry
