"""
drift.py
-------------
Phase 7: baseline drift detection - the meta-signal that catches a slow,
evasive adversary who stays inside every individual call's normal-looking
range while gradually dragging an agent's baseline itself somewhere new
(e.g. active hours creeping later, payload sizes creeping up, tool mix
shifting) over many legitimate-looking calls.

detector.detector.detect() can only ever compare ONE call against a FIXED
baseline snapshot. It has no memory of its own history, so it is
structurally blind to a baseline that drifts slowly enough that every
single call along the way still looks normal against that fixed reference.
This module closes that gap by comparing the baseline ITSELF, snapshotted
periodically, against an earlier snapshot of the same agent - independent
of whether any individual call was ever flagged.

Reuses detector/baseline.py's build_baseline() for the numeric/set stats
(avg/std payload size, avg/std fan-out, active hours) so a snapshot is
built the exact same way the Phase 2 baseline is, just scoped to one
period's rows instead of the whole log. Two distributions are tracked per
snapshot that build_baseline() doesn't compute - a call-count-by-tool
histogram and a call-count-by-hour-of-day histogram - so composition and
timing shifts can be measured with an actual distributional distance
(Jensen-Shannon divergence: bounded, symmetric, KL-divergence-style, and -
unlike raw KL - stays finite when a tool/hour that appeared in one period
never appears in the other) rather than just set membership. Set
membership is exactly what Phase 2's NEW_TOOL/OFF_PATTERN checks already
do, and it's exactly what a slow drift *within* an already-known set of
tools/hours slips past.

New signal: BASELINE_DRIFT - fires when any one of these four components
crosses its threshold between two snapshots of the same agent:
    payload_drift_z   |zscore(curr mean payload, prev mean/std payload)|
    fanout_drift_z    |zscore(curr mean fanout,  prev mean/std fanout)|
    hours_jsd         Jensen-Shannon divergence between the two periods'
                      call-count-by-hour-of-day histograms (bits, 0-1)
    tools_jsd         Jensen-Shannon divergence between the two periods'
                      call-count-by-tool histograms (bits, 0-1)
This is a signal about the BASELINE, not about any one call - it has no
trace_id/tool_name/payload_size of its own, so it is reported separately
from detector.py's per-call alert stream rather than folded into it.

Snapshots are appended to a hash-chained log (logs/baseline_snapshots.jsonl,
same tamper-evident pattern as proxy/audit_log.py and red/run_log.py - an
independent implementation on purpose, per README.md's "Architecture"
section) so a claimed drift result can be verified/replayed against the
recorded snapshots, not just trusted as a one-off computation.

Comparison mode: by default each run compares the CURRENT period's
snapshot against the OLDEST retained snapshot for that agent, not the
immediately previous one. Comparing only to "last week" every time is
exactly the boiling-frog blind spot this phase exists to close - a
sufficiently slow, steady drift can make every week-over-week delta small
even while the cumulative drift from where the agent started is enormous.
Pass --compare-to previous for the tighter week-over-week comparison
instead (cheaper to explain, but reopens that blind spot for slow-enough
drift).

Explicit non-goal: this does NOT detect file-level tampering of any actual
agent config/memory files - it has no visibility into agent internals,
only into the tool calls a proxied agent happens to make. It detects drift
as reflected in observable tool-call behavior over time, nothing more.

Usage:
    python3 -m detector.drift [logs/calls.jsonl] [--period-days 7]
    (needs enough call history to span at least two periods for a given
    agent; the first period recorded for that agent has nothing yet to
    compare against, and is just stored)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from detector.baseline import DEFAULT_WINDOW_SECONDS, build_baseline, load_calls
from detector.detector import zscore

SNAPSHOT_LOG_PATH = "logs/baseline_snapshots.jsonl"
DEFAULT_PERIOD_DAYS = 7
GENESIS_HASH = "0" * 64

PAYLOAD_DRIFT_ZSCORE_THRESHOLD = 2.0   # mean payload shift, in prior-period std-devs
FANOUT_DRIFT_ZSCORE_THRESHOLD = 2.0    # mean fan-out shift, in prior-period std-devs
HOURS_JSD_THRESHOLD = 0.4              # call-hour histogram JSD (bits, 0-1)
TOOLS_JSD_THRESHOLD = 0.15             # tool-usage histogram JSD (bits, 0-1)


# ---------------------------------------------------------------------------
# Distributional distance
# ---------------------------------------------------------------------------

def js_divergence(counts_a: dict, counts_b: dict) -> float:
    """Jensen-Shannon divergence (base-2, bounded to [0, 1]) between two
    frequency-count distributions given as {key: count}. Symmetric, and -
    unlike raw KL divergence - never blows up to infinity when a key
    present in one distribution is absent from the other, since the
    reference ("M") distribution is the average of both and so is always
    >0 wherever either input is >0.
    """
    keys = set(counts_a) | set(counts_b)
    if not keys:
        return 0.0

    total_a = sum(counts_a.values()) or 1
    total_b = sum(counts_b.values()) or 1
    p = {k: counts_a.get(k, 0) / total_a for k in keys}
    q = {k: counts_b.get(k, 0) / total_b for k in keys}
    m = {k: (p[k] + q[k]) / 2 for k in keys}

    def kl(x, y):
        return sum(x[k] * math.log2(x[k] / y[k]) for k in keys if x[k] > 0)

    return 0.5 * kl(p, m) + 0.5 * kl(q, m)


# ---------------------------------------------------------------------------
# Snapshot construction
# ---------------------------------------------------------------------------

def build_snapshot(rows, period_start, period_end, window_seconds=DEFAULT_WINDOW_SECONDS):
    """Builds one baseline snapshot per agent from rows falling in
    [period_start, period_end). Reuses build_baseline() for the numeric/set
    stats and adds the two histograms build_baseline() doesn't compute.
    Agents with no rows in this period simply don't appear, same convention
    as build_baseline().
    """
    period_rows = [r for r in rows if period_start <= r["timestamp"] < period_end]
    stats = build_baseline(period_rows, window_seconds=window_seconds)

    tool_counts = defaultdict(Counter)
    hour_counts = defaultdict(Counter)
    for row in period_rows:
        agent = row["agent_id"]
        tool_counts[agent][row["tool_name"]] += 1
        hour_counts[agent][row["timestamp"].hour] += 1

    snapshot = {}
    for agent, profile in stats.items():
        snapshot[agent] = {
            **profile,
            "tool_call_counts": dict(tool_counts[agent]),
            "hour_call_counts": {str(h): c for h, c in hour_counts[agent].items()},
            "call_count": sum(tool_counts[agent].values()),
        }
    return snapshot


# ---------------------------------------------------------------------------
# Drift comparison
# ---------------------------------------------------------------------------

def compute_drift(prev: dict, curr: dict) -> dict:
    """Compares two single-agent snapshot dicts (as produced by
    build_snapshot()[agent], or read back from the hash-chained snapshot
    log) and returns the four component measures plus whether
    BASELINE_DRIFT fires and a plain-English reason for each component
    that crossed its threshold - same explainability ethos as detector.py's
    per-call signals.
    """
    payload_z = abs(
        zscore(curr["avg_payload_size"], prev["avg_payload_size"], prev["std_payload_size"])
    )
    fanout_z = abs(
        zscore(curr["avg_fanout_per_window"], prev["avg_fanout_per_window"], prev["std_fanout_per_window"])
    )
    hours_jsd = js_divergence(
        {int(h): c for h, c in prev["hour_call_counts"].items()},
        {int(h): c for h, c in curr["hour_call_counts"].items()},
    )
    tools_jsd = js_divergence(prev["tool_call_counts"], curr["tool_call_counts"])

    reasons = []
    if payload_z >= PAYLOAD_DRIFT_ZSCORE_THRESHOLD:
        reasons.append(
            f"avg payload drifted {prev['avg_payload_size']} -> {curr['avg_payload_size']} "
            f"(|z|={payload_z:.2f} >= {PAYLOAD_DRIFT_ZSCORE_THRESHOLD})"
        )
    if fanout_z >= FANOUT_DRIFT_ZSCORE_THRESHOLD:
        reasons.append(
            f"avg fan-out/window drifted {prev['avg_fanout_per_window']} -> {curr['avg_fanout_per_window']} "
            f"(|z|={fanout_z:.2f} >= {FANOUT_DRIFT_ZSCORE_THRESHOLD})"
        )
    if hours_jsd >= HOURS_JSD_THRESHOLD:
        reasons.append(
            f"call-hour distribution shifted (JSD={hours_jsd:.3f} >= {HOURS_JSD_THRESHOLD}) - "
            f"active_hours set may be unchanged, this is a WHEN-within-the-set shift"
        )
    if tools_jsd >= TOOLS_JSD_THRESHOLD:
        reasons.append(
            f"tool-usage mix shifted (JSD={tools_jsd:.3f} >= {TOOLS_JSD_THRESHOLD}) - "
            f"known_tools set may be unchanged, this is a usage-composition shift"
        )

    return {
        "payload_drift_z": round(payload_z, 3),
        "fanout_drift_z": round(fanout_z, 3),
        "hours_jsd": round(hours_jsd, 3),
        "tools_jsd": round(tools_jsd, 3),
        "fired": bool(reasons),
        "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# Hash-chained snapshot log (independent implementation - see module
# docstring / README.md's "Architecture" note on why each log is its own
# implementation rather than shared code)
# ---------------------------------------------------------------------------

@dataclass
class SnapshotLogEntry:
    trace_id: str
    timestamp: str
    agent_id: str
    period_start: str
    period_end: str
    known_tools: list
    active_hours: list
    avg_payload_size: float
    std_payload_size: float
    avg_fanout_per_window: float
    std_fanout_per_window: float
    tool_call_counts: dict
    hour_call_counts: dict
    call_count: int
    prev_hash: str
    entry_hash: str = field(init=False, default="")

    def canonical_body(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "known_tools": self.known_tools,
            "active_hours": self.active_hours,
            "avg_payload_size": self.avg_payload_size,
            "std_payload_size": self.std_payload_size,
            "avg_fanout_per_window": self.avg_fanout_per_window,
            "std_fanout_per_window": self.std_fanout_per_window,
            "tool_call_counts": self.tool_call_counts,
            "hour_call_counts": self.hour_call_counts,
            "call_count": self.call_count,
            "prev_hash": self.prev_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self.canonical_body()
        d["entry_hash"] = self.entry_hash
        return d


def _canonical_json(body: dict[str, Any]) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


class HashChainSnapshotLog:
    """Append-only, hash-chained JSONL log of baseline snapshots - the
    Phase 7 counterpart to proxy/audit_log.py's call log and
    red/run_log.py's run log. One entry per (agent, period).

    Not thread-safe, by the same reasoning as red/run_log.py: drift.py is a
    one-shot on-demand/cron CLI run, never a concurrent server like
    proxy/server.py, so there's no concurrent-writer case to guard against.
    """

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

    def append(self, *, agent_id: str, period_start: datetime, period_end: datetime, snapshot: dict) -> SnapshotLogEntry:
        entry = SnapshotLogEntry(
            trace_id=uuid.uuid4().hex,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=agent_id,
            period_start=period_start.isoformat(),
            period_end=period_end.isoformat(),
            known_tools=snapshot["known_tools"],
            active_hours=snapshot["active_hours"],
            avg_payload_size=snapshot["avg_payload_size"],
            std_payload_size=snapshot["std_payload_size"],
            avg_fanout_per_window=snapshot["avg_fanout_per_window"],
            std_fanout_per_window=snapshot["std_fanout_per_window"],
            tool_call_counts=snapshot["tool_call_counts"],
            hour_call_counts=snapshot["hour_call_counts"],
            call_count=snapshot["call_count"],
            prev_hash=self._last_hash,
        )
        body_json = _canonical_json(entry.canonical_body())
        entry.entry_hash = hashlib.sha256((entry.prev_hash + body_json).encode("utf-8")).hexdigest()

        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")

        self._last_hash = entry.entry_hash
        return entry


def read_snapshots(log_path: str | Path) -> list:
    path = Path(log_path)
    if not path.exists():
        return []
    entries = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
    return entries


def verify_chain(log_path: str | Path) -> tuple[bool, int, str | None]:
    """Recomputes the hash chain over an existing snapshot log. Same
    tamper-evidence check as proxy/audit_log.py's verify_chain(), applied
    to snapshot entries instead of call entries: any edited, reordered, or
    deleted line breaks the chain from that point on.
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


# ---------------------------------------------------------------------------
# Periodic run: snapshot the current period, compare to a prior one, append
# ---------------------------------------------------------------------------

def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def pick_comparison_snapshot(existing_entries, agent_id, period_start, mode="oldest"):
    """From previously recorded snapshot entries, picks which one to
    compare this agent's new snapshot against - the OLDEST retained one for
    that agent by default (see module docstring for why), or the most
    recent one strictly before this run's period if mode="previous".
    """
    candidates = [
        e for e in existing_entries
        if e["agent_id"] == agent_id and _parse_iso(e["period_end"]) <= period_start
    ]
    if not candidates:
        return None
    if mode == "oldest":
        return min(candidates, key=lambda e: _parse_iso(e["period_start"]))
    return max(candidates, key=lambda e: _parse_iso(e["period_end"]))


def run_drift_check(
    rows,
    period_end: datetime,
    period_days: int = DEFAULT_PERIOD_DAYS,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    snapshot_log_path: str | Path = SNAPSHOT_LOG_PATH,
    compare_to: str = "oldest",
) -> dict:
    """One periodic drift-check run: snapshots [period_end - period_days,
    period_end) for every agent seen in `rows`, compares each against its
    prior snapshot (per `compare_to`), appends the new snapshots to the
    hash-chained log, and returns {agent_id: compute_drift() result} for
    every agent that had a prior snapshot to compare against.
    """
    period_start = period_end - timedelta(days=period_days)
    curr_snapshot = build_snapshot(rows, period_start, period_end, window_seconds=window_seconds)

    existing_entries = read_snapshots(snapshot_log_path)
    log = HashChainSnapshotLog(snapshot_log_path)

    results = {}
    for agent, snap in curr_snapshot.items():
        prior_entry = pick_comparison_snapshot(existing_entries, agent, period_start, mode=compare_to)
        if prior_entry is not None:
            results[agent] = compute_drift(prior_entry, snap)
        log.append(agent_id=agent, period_start=period_start, period_end=period_end, snapshot=snap)

    return results


def explain(agent_id, result):
    lines = [f"{agent_id}: BASELINE_DRIFT {'FIRED' if result['fired'] else 'not fired'}"]
    lines.append(
        f"    payload_drift_z={result['payload_drift_z']} fanout_drift_z={result['fanout_drift_z']} "
        f"hours_jsd={result['hours_jsd']} tools_jsd={result['tools_jsd']}"
    )
    for r in result["reasons"]:
        lines.append(f"    - {r}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Detect baseline drift between periodic snapshots")
    parser.add_argument("log_path", nargs="?", default="logs/calls.jsonl")
    parser.add_argument("--period-days", type=int, default=DEFAULT_PERIOD_DAYS)
    parser.add_argument("--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS)
    parser.add_argument("--snapshot-log", default=SNAPSHOT_LOG_PATH)
    parser.add_argument("--compare-to", choices=["oldest", "previous"], default="oldest")
    parser.add_argument(
        "--as-of",
        default=None,
        help="ISO timestamp to treat as the period end (default: latest call timestamp in the log)",
    )
    args = parser.parse_args()

    rows = load_calls(args.log_path)
    if not rows:
        print(f"No calls found in {args.log_path}")
        return

    period_end = _parse_iso(args.as_of) if args.as_of else max(r["timestamp"] for r in rows)

    results = run_drift_check(
        rows,
        period_end,
        period_days=args.period_days,
        window_seconds=args.window_seconds,
        snapshot_log_path=args.snapshot_log,
        compare_to=args.compare_to,
    )

    print(
        f"Snapshotted period ending {period_end.isoformat()} ({args.period_days}d window) "
        f"to {args.snapshot_log}, compared against '{args.compare_to}' prior snapshot\n"
    )
    if not results:
        print("No agent had a prior snapshot to compare against yet (first run for all agents).")
        return

    fired = {a: r for a, r in results.items() if r["fired"]}
    print(f"=== {len(fired)} BASELINE_DRIFT alert(s) ===\n")
    for agent, result in fired.items():
        print(explain(agent, result))
        print()

    quiet = {a: r for a, r in results.items() if not r["fired"]}
    print(f"=== {len(quiet)} agent(s) with no significant drift ===\n")
    for agent, result in quiet.items():
        print(explain(agent, result))
        print()


if __name__ == "__main__":
    main()
