"""
baseline.py
-------------
Learns a per-agent behavioral baseline from the MCP proxy's hash-chained call
log (logs/calls.jsonl) - no ML black box, just descriptive statistics so every
flagged anomaly can be explained in plain terms ("this agent normally uses 3
tools, this call used a 4th it's never touched before").

This is a direct port of the original lateral-movement-detector's baseline.py,
re-targeted at MCP tool calls instead of network flows:

    src_ip (device)      -> agent_id
    dst_ip (peer)        -> tool_name
    bytes (flow size)    -> payload_size
    hourly peer fan-out  -> distinct-tools-per-window fan-out (window is
                             configurable - see --window-seconds - since tool
                             calls burst much faster than network flows do)

For each agent_id that appears in the log, this learns:
    known_tools:                the set of tool_names it has called before
    active_hours:                the set of hours-of-day (0-23) it's normally
                                 active in
    avg_payload_size / std_payload_size:   typical single-call payload size
    avg_fanout_per_window / std_fanout_per_window:
        typical number of DISTINCT tools called within one window (default
        60s)

Saves everything to baseline.json (plus a "_meta.window_seconds" key so
detector.py always buckets fan-out the same way the baseline was built with),
which detector.py loads to compare new calls against.

Usage:
    python3 -m detector.baseline [logs/calls.jsonl] [--window-seconds 60]
"""

import argparse
import json
import statistics
from collections import defaultdict
from datetime import datetime

BASELINE_PATH = "detector/baseline.json"
DEFAULT_WINDOW_SECONDS = 60


def load_calls(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            entry["timestamp"] = datetime.fromisoformat(entry["timestamp"])
            entry["payload_size"] = int(entry["payload_size"])
            rows.append(entry)
    return rows


def window_bucket(ts, window_seconds):
    return int(ts.timestamp() // window_seconds)


def build_baseline(rows, window_seconds=DEFAULT_WINDOW_SECONDS):
    per_agent_tools = defaultdict(set)
    per_agent_hours = defaultdict(set)
    per_agent_payloads = defaultdict(list)
    # fan-out: per agent, per window bucket -> set of distinct tools called
    per_agent_window_tools = defaultdict(lambda: defaultdict(set))

    for row in rows:
        agent = row["agent_id"]
        tool = row["tool_name"]
        ts = row["timestamp"]
        bucket = window_bucket(ts, window_seconds)

        per_agent_tools[agent].add(tool)
        per_agent_hours[agent].add(ts.hour)
        per_agent_payloads[agent].append(row["payload_size"])
        per_agent_window_tools[agent][bucket].add(tool)

    baseline = {}
    for agent in per_agent_tools:
        payload_values = per_agent_payloads[agent]
        fanout_values = [len(tools) for tools in per_agent_window_tools[agent].values()]

        avg_payload = statistics.mean(payload_values)
        std_payload = (
            statistics.stdev(payload_values) if len(payload_values) > 1 else avg_payload * 0.3
        )

        avg_fanout = statistics.mean(fanout_values)
        raw_std_fanout = (
            statistics.stdev(fanout_values) if len(fanout_values) > 1 else avg_fanout * 0.5
        )
        # Floor of 1.0: an agent's normal per-window fan-out is often just 1-2
        # tools, which makes the natural std tiny. Without a floor, a
        # completely normal +1 tool in one window turns into a huge z-score
        # and floods the detector with false positives.
        std_fanout = max(raw_std_fanout, 1.0)

        baseline[agent] = {
            "known_tools": sorted(per_agent_tools[agent]),
            "active_hours": sorted(per_agent_hours[agent]),
            "avg_payload_size": round(avg_payload, 1),
            "std_payload_size": round(std_payload, 1),
            "avg_fanout_per_window": round(avg_fanout, 2),
            "std_fanout_per_window": round(std_fanout, 2),
        }

    return baseline


def save_baseline(baseline, window_seconds, path=BASELINE_PATH):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"_meta": {"window_seconds": window_seconds}, "agents": baseline}, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Build a per-agent baseline from the MCP call log")
    parser.add_argument("log_path", nargs="?", default="logs/calls.jsonl")
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=DEFAULT_WINDOW_SECONDS,
        help="Fan-out bucket size in seconds (default: 60)",
    )
    args = parser.parse_args()

    rows = load_calls(args.log_path)
    print(f"Loaded {len(rows)} calls from {args.log_path}")

    baseline = build_baseline(rows, window_seconds=args.window_seconds)
    print(f"Learned baseline for {len(baseline)} agent(s) (window={args.window_seconds}s):\n")
    for agent, profile in baseline.items():
        print(f"  {agent}:")
        print(f"    known tools: {profile['known_tools']}")
        print(f"    active hours: {profile['active_hours']}")
        print(f"    avg payload size: {profile['avg_payload_size']} (std {profile['std_payload_size']})")
        print(
            f"    avg fan-out/window: {profile['avg_fanout_per_window']} "
            f"(std {profile['std_fanout_per_window']})"
        )
        print()

    save_baseline(baseline, args.window_seconds)
    print(f"Saved baseline to {BASELINE_PATH}")


if __name__ == "__main__":
    main()
