"""
detector.py
-------------
Compares new MCP tool calls against the learned baseline.json and flags 4
types of anomaly, each individually explainable (no ML black box). This is a
direct port of the original lateral-movement-detector's detector.py, with the
signal set renamed for the tool-call domain:

    NEW_PEER       -> NEW_TOOL       agent is calling a tool it has never
                                     used before
    OFF_HOURS      -> OFF_PATTERN    agent is calling tools outside its
                                     normal hours-of-day
    VOLUME_OUTLIER -> PAYLOAD_OUTLIER  a single call's payload is far outside
                                     this agent's typical size (z-score based)
    FANOUT_SPIKE   -> SEQUENCE_SPIKE  agent is calling far more distinct
                                     tools within one window than it normally
                                     does - the strongest single signal,
                                     since a compromised/confused agent
                                     touching many tools in a short burst
                                     looks a lot like lateral movement does
                                     on a network

A 5th check sits outside that 4-signal set: UNKNOWN_AGENT fires when
agent_id has no baseline profile at all. Earlier versions silently skipped
these rows on the reasoning that the 4 core checks need a profile to
compare against - but that made "call through an identity blue has never
profiled" a free pass, which is exactly the wrong property for a detector
whose whole premise is baselining identity behavior. An unbaselined agent
now always raises UNKNOWN_AGENT (and only that - the profile-dependent
checks still can't run without a profile), which tiers as an observation
by the same rule as any other single signal.

Each call can trigger more than one signal at once. Per PROJECT_SPEC.md
Phase 2, confidence is tiered on that count:
    1 signal   -> "observation" tier: logged, not alerted (too noisy alone)
    2+ signals -> "alert" tier: correlated signals are what make it worth a
                  human looking at it

Per PROJECT_SPEC.md Phase 3, signals are checked against
config/known_jobs.yaml (see detector/suppression.py) before tiering. Any
signal a known job explains is pulled out of the count; if that leaves the
call with no signals, it's recorded as "suppressed" tier - still visible in
output, just not raised as a false positive. Unmatched anomalies tier
exactly as before.

Usage:
    python3 -m detector.detector [logs/calls.jsonl]
    (requires detector/baseline.json - run detector/baseline.py first)
"""

import argparse
import json
from collections import defaultdict

from detector.baseline import BASELINE_PATH, load_calls, window_bucket
from detector.suppression import KNOWN_JOBS_PATH, apply_suppression, load_known_jobs

VOLUME_ZSCORE_THRESHOLD = 3.0    # flags payloads this many std-devs above normal
FANOUT_ZSCORE_THRESHOLD = 2.0    # flags per-window fan-out this many std-devs above normal


def load_baseline(path=BASELINE_PATH):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["agents"], data["_meta"]["window_seconds"]


def zscore(value, mean, std):
    if std == 0:
        return 0.0
    return (value - mean) / std


def detect(rows, baseline, window_seconds, jobs=()):
    """
    Returns a list of alert dicts. Fan-out is evaluated per (agent,
    window-bucket) across the whole log first, since it depends on ALL of an
    agent's calls within that window, not just one call at a time.
    """
    alerts = []

    # Pre-compute per-agent, per-window-bucket distinct tool counts
    window_tools = defaultdict(lambda: defaultdict(set))
    for row in rows:
        bucket = window_bucket(row["timestamp"], window_seconds)
        window_tools[row["agent_id"]][bucket].add(row["tool_name"])

    # Track which (agent, bucket) combos already raised a SEQUENCE_SPIKE, so
    # we don't repeat it once per call.
    fanout_alerted = set()

    for row in rows:
        agent = row["agent_id"]
        tool = row["tool_name"]
        hour = row["timestamp"].hour
        bucket = window_bucket(row["timestamp"], window_seconds)

        profile = baseline.get(agent)
        if profile is None:
            # Agent has no baseline at all - that absence is itself the
            # anomaly, not a reason to skip. The 4 checks below all compare
            # against profile stats, so none of them can run without one;
            # this is the only signal an unbaselined agent can raise.
            signals = ["UNKNOWN_AGENT"]
        else:
            signals = []

            # 1. NEW_TOOL
            if tool not in profile["known_tools"]:
                signals.append("NEW_TOOL")

            # 2. OFF_PATTERN
            if hour not in profile["active_hours"]:
                signals.append("OFF_PATTERN")

            # 3. PAYLOAD_OUTLIER
            z = zscore(row["payload_size"], profile["avg_payload_size"], profile["std_payload_size"])
            if z >= VOLUME_ZSCORE_THRESHOLD:
                signals.append("PAYLOAD_OUTLIER")

            # 4. SEQUENCE_SPIKE (evaluated once per agent/bucket, not per call)
            fanout_key = (agent, bucket)
            if fanout_key not in fanout_alerted:
                current_fanout = len(window_tools[agent][bucket])
                fz = zscore(
                    current_fanout, profile["avg_fanout_per_window"], profile["std_fanout_per_window"]
                )
                if fz >= FANOUT_ZSCORE_THRESHOLD:
                    signals.append("SEQUENCE_SPIKE")
                    fanout_alerted.add(fanout_key)

        if not signals:
            continue

        remaining, suppressed = apply_suppression(row, signals, jobs)

        if remaining:
            tier = "alert" if len(remaining) >= 2 else "observation"
        else:
            tier = "suppressed"

        alerts.append(
            {
                "trace_id": row["trace_id"],
                "timestamp": row["timestamp"].isoformat(),
                "agent_id": agent,
                "tool_name": tool,
                "target_resource": row["target_resource"],
                "payload_size": row["payload_size"],
                "signals": remaining,
                "suppressed_signals": suppressed,
                "tier": tier,
            }
        )

    return alerts


def explain(alert):
    line = (
        f"[{alert['timestamp']}] {alert['agent_id']} -> {alert['tool_name']}"
        f"({alert['target_resource']}) {alert['payload_size']}B "
        f"| {', '.join(alert['signals']) or '(none remaining)'} | tier={alert['tier']}"
    )
    suppressed = alert.get("suppressed_signals")
    if suppressed:
        parts = ", ".join(f"{s['signal']} (known job: {s['job']})" for s in suppressed)
        line += f"\n    suppressed: {parts}"
    return line


def main():
    parser = argparse.ArgumentParser(description="Detect anomalous MCP tool calls against a baseline")
    parser.add_argument("log_path", nargs="?", default="logs/calls.jsonl")
    parser.add_argument(
        "--known-jobs",
        default=KNOWN_JOBS_PATH,
        help=f"Path to the Phase 3 suppression config (default: {KNOWN_JOBS_PATH})",
    )
    args = parser.parse_args()

    baseline, window_seconds = load_baseline()
    rows = load_calls(args.log_path)
    jobs = load_known_jobs(args.known_jobs)
    print(
        f"Loaded baseline for {len(baseline)} agent(s) (window={window_seconds}s), "
        f"{len(rows)} calls from {args.log_path}, {len(jobs)} known job(s) from {args.known_jobs}\n"
    )

    results = detect(rows, baseline, window_seconds, jobs=jobs)
    alerts = [r for r in results if r["tier"] == "alert"]
    observations = [r for r in results if r["tier"] == "observation"]
    suppressed = [r for r in results if r["tier"] == "suppressed"]

    print(f"=== {len(alerts)} alert(s) (2+ correlated signals) ===\n")
    for a in alerts:
        print(explain(a))

    print(f"\n=== {len(observations)} observation(s) (single signal, logged only) ===\n")
    for o in observations:
        print(explain(o))

    print(
        f"\n=== {len(suppressed)} suppressed (matched a known job in {args.known_jobs}, not alerted) ===\n"
    )
    for s in suppressed:
        print(explain(s))


if __name__ == "__main__":
    main()
