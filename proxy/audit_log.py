"""Append-only, hash-chained audit log for MCP tool calls.

Each entry embeds the SHA-256 hash of the previous entry's canonical JSON, so any
edit or deletion of a prior line breaks the chain for every entry after it. This
is the equivalent of lateral-movement-detector's real_traffic.csv: the raw data
source the anomaly detector (Phase 2) will baseline against.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


@dataclass
class LogEntry:
    trace_id: str
    timestamp: str
    agent_id: str
    tool_name: str
    target_resource: str
    payload_size: int
    reasoning_summary: str
    prev_hash: str
    entry_hash: str = field(init=False, default="")

    def canonical_body(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "tool_name": self.tool_name,
            "target_resource": self.target_resource,
            "payload_size": self.payload_size,
            "reasoning_summary": self.reasoning_summary,
            "prev_hash": self.prev_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self.canonical_body()
        d["entry_hash"] = self.entry_hash
        return d


def _canonical_json(body: dict[str, Any]) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


class HashChainAuditLog:
    """Thread-safe, append-only JSONL writer with a running SHA-256 hash chain.

    On construction it reads the last line of an existing log file (if any) and
    resumes the chain from that entry's hash, so the chain survives process
    restarts instead of resetting to genesis every run.
    """

    def __init__(self, log_path: str | Path):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
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
        agent_id: str,
        tool_name: str,
        target_resource: str,
        payload_size: int,
        reasoning_summary: str,
    ) -> LogEntry:
        with self._lock:
            entry = LogEntry(
                trace_id=uuid.uuid4().hex,
                timestamp=datetime.now(timezone.utc).isoformat(),
                agent_id=agent_id,
                tool_name=tool_name,
                target_resource=target_resource,
                payload_size=payload_size,
                reasoning_summary=reasoning_summary,
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


def verify_chain(log_path: str | Path) -> tuple[bool, int, str | None]:
    """Recompute the hash chain over an existing log file.

    Returns (ok, entries_checked, error_message). Used to detect tampering:
    any edited, reordered, or deleted line breaks the chain from that point on.
    """
    path = Path(log_path)
    if not path.exists():
        return True, 0, None

    expected_prev = GENESIS_HASH
    checked = 0
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record["prev_hash"] != expected_prev:
                return False, i, f"line {i}: prev_hash mismatch (chain broken)"
            body = {k: v for k, v in record.items() if k != "entry_hash"}
            recomputed = hashlib.sha256(
                (record["prev_hash"] + _canonical_json(body)).encode("utf-8")
            ).hexdigest()
            if recomputed != record["entry_hash"]:
                return False, i, f"line {i}: entry_hash mismatch (tampered content)"
            expected_prev = record["entry_hash"]
            checked = i

    return True, checked, None
