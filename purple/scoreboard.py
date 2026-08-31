"""
scoreboard.py
-------------
Phase 5: append-only, hash-chained log of purple-team round results
(logs/purple_runs.jsonl) - same tamper-evident design as proxy/audit_log.py
and red/run_log.py (each entry embeds the SHA-256 hash of the previous
entry's canonical JSON), applied here to "what did blue do when red did X"
so a purple run's scoring can be trusted and replayed later, per
PROJECT_SPEC.md Phase 5 ("logs results using the Phase 1 audit schema
(trace ID, reasoning, replayable)").
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
class ScoreboardEntry:
    trace_id: str
    timestamp: str
    round_no: int
    technique_id: str
    technique_name: str
    target: str
    impersonated_agent: str
    injected_call_trace_id: str
    tool_name: str
    blue_tier: str
    blue_signals: list
    outcome: str  # "alert" | "observation" | "suppressed" | "missed"
    prev_hash: str
    entry_hash: str = field(init=False, default="")

    def canonical_body(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "timestamp": self.timestamp,
            "round_no": self.round_no,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "target": self.target,
            "impersonated_agent": self.impersonated_agent,
            "injected_call_trace_id": self.injected_call_trace_id,
            "tool_name": self.tool_name,
            "blue_tier": self.blue_tier,
            "blue_signals": self.blue_signals,
            "outcome": self.outcome,
            "prev_hash": self.prev_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self.canonical_body()
        d["entry_hash"] = self.entry_hash
        return d


def _canonical_json(body: dict[str, Any]) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


class PurpleScoreboard:
    """Not thread-safe by design - see red/run_log.py's HashChainRunLog for
    why: this is a one-shot on-demand CLI loop, never a concurrent server."""

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
        round_no: int,
        technique_id: str,
        technique_name: str,
        target: str,
        impersonated_agent: str,
        injected_call_trace_id: str,
        tool_name: str,
        blue_tier: str,
        blue_signals: list,
        outcome: str,
    ) -> ScoreboardEntry:
        entry = ScoreboardEntry(
            trace_id=uuid.uuid4().hex,
            timestamp=datetime.now(timezone.utc).isoformat(),
            round_no=round_no,
            technique_id=technique_id,
            technique_name=technique_name,
            target=target,
            impersonated_agent=impersonated_agent,
            injected_call_trace_id=injected_call_trace_id,
            tool_name=tool_name,
            blue_tier=blue_tier,
            blue_signals=list(blue_signals),
            outcome=outcome,
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
