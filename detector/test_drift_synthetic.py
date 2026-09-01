"""
test_drift_synthetic.py
-------------
Phase 7 verification, per PROJECT_SPEC.md's Phase 7 "Verification approach":
a synthetic agent whose calls slowly shift over many days - active hours
creeping from a broad late-morning/afternoon spread to a single fixed late
hour, payload sizes creeping up - while every individual call stays within
its era's normal-looking range (no call is ever a per-call outlier). Confirms:

  1. detector.detector.detect(), run over 28 days of drift-period calls
     against a FIXED baseline built only from the 14-day training period,
     raises ZERO signals for this agent - Phase 2 alone is structurally
     blind to the whole thing, exactly the documented limitation.
  2. detector.drift's BASELINE_DRIFT fires when comparing the agent's
     oldest recorded snapshot (training) against its most recent one
     (fully drifted) - Phase 7 catches what Phase 2 missed.
  3. BASELINE_DRIFT does NOT fire between two genuinely stable training
     weeks (a sanity check against false-positiving on ordinary variation).
  4. The snapshot log's hash chain verifies clean end to end.

Not a pytest suite (this project has none yet - see proxy/test_client.py
for the same "standalone smoke script" convention) - asserts and prints
PASS/FAIL, runnable via:
    python3 -m detector.test_drift_synthetic
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from detector import drift
from detector.baseline import DEFAULT_WINDOW_SECONDS, build_baseline
from detector.detector import detect

AGENT = "slow-drift-agent"
TOOL = "read_file"
GENESIS = datetime(2026, 1, 1, tzinfo=timezone.utc)
SNAPSHOT_LOG_PATH = Path(
    "/tmp/claude-1000/-home-shehab-shibli-mcp-security-proxy/"
    "6342313c-ba96-42c3-9e3c-6dd3f213a5dd/scratchpad/baseline_snapshots_test.jsonl"
)

# Training weeks (0, 1): stable behaviour. Together they establish a baseline
# whose active_hours already spans the FULL 9-17 range the drift period will
# stay inside of, and whose payload std is wide enough that the drift period's
# creep never trips a single-call PAYLOAD_OUTLIER (z >= 3.0) against it.
TRAINING_PAYLOAD_CYCLE = [460, 500, 540, 500, 470, 530, 500]  # mean 500, std ~28.9
TRAINING_HOURS = {
    0: [9, 10, 11, 12, 13, 14, 15],   # week1
    1: [9, 10, 11, 12, 13, 16, 17],   # week2 - union with week1 covers 9..17
}

# Drift weeks (2-5): hours creep from mid-day toward a single fixed late
# hour, and payload creeps upward - both stay inside the training envelope.
DRIFT_HOURS = {
    2: [11, 12, 13, 14, 11, 12, 13],  # week3 - centered ~12
    3: [13, 14, 15, 14, 13, 15, 14],  # week4 - centered ~14
    4: [15, 16, 17, 16, 15, 17, 16],  # week5 - centered ~16
    5: [17, 17, 17, 17, 17, 17, 17],  # week6 - fully concentrated at 17
}
DRIFT_PAYLOAD_BASE = {2: 515, 3: 530, 4: 545, 5: 560}
DRIFT_PAYLOAD_JITTER = [-10, 0, 10, 5, -5, 10, 0]


def hours_for(week):
    return TRAINING_HOURS.get(week, DRIFT_HOURS.get(week))


def payload_for(week, day_in_week):
    if week in TRAINING_HOURS:
        return TRAINING_PAYLOAD_CYCLE[day_in_week]
    return DRIFT_PAYLOAD_BASE[week] + DRIFT_PAYLOAD_JITTER[day_in_week]


def make_row(i, day, hour, payload):
    return {
        "trace_id": f"synthetic-{i:04d}",
        "timestamp": GENESIS + timedelta(days=day, hours=hour),
        "agent_id": AGENT,
        "tool_name": TOOL,
        "target_resource": "/data/file.txt",
        "payload_size": payload,
        "reasoning_summary": "synthetic slow-drift verification call",
    }


def generate_rows():
    rows = []
    i = 0
    for week in range(6):
        hours = hours_for(week)
        for day_in_week in range(7):
            day = week * 7 + day_in_week
            hour = hours[day_in_week]
            payload = payload_for(week, day_in_week)
            rows.append(make_row(i, day, hour, payload))
            i += 1
    return rows


def main():
    failures = []

    def check(condition, message):
        status = "PASS" if condition else "FAIL"
        print(f"[{status}] {message}")
        if not condition:
            failures.append(message)

    rows = generate_rows()
    training_cutoff = GENESIS + timedelta(days=14)
    training_rows = [r for r in rows if r["timestamp"] < training_cutoff]
    drift_rows = [r for r in rows if r["timestamp"] >= training_cutoff]

    print(f"Generated {len(rows)} synthetic calls for '{AGENT}': "
          f"{len(training_rows)} training (weeks 1-2), {len(drift_rows)} drift-period (weeks 3-6)\n")

    # --- 1. Phase 2 alone, over the whole 28-day drift period -------------
    phase2_baseline = build_baseline(training_rows, window_seconds=DEFAULT_WINDOW_SECONDS)
    print(f"Phase 2 baseline (from training only): {phase2_baseline[AGENT]}\n")

    phase2_alerts = detect(drift_rows, phase2_baseline, DEFAULT_WINDOW_SECONDS, jobs=[])
    check(
        phase2_alerts == [],
        f"Phase 2 detector.detect() raised 0 signals over all {len(drift_rows)} drift-period calls "
        f"(got {len(phase2_alerts)}: {phase2_alerts[:3]})",
    )

    # --- 2. Phase 7: weekly snapshots + drift comparison -------------------
    if SNAPSHOT_LOG_PATH.exists():
        SNAPSHOT_LOG_PATH.unlink()

    results_by_week = {}
    for week in range(6):
        period_end = GENESIS + timedelta(days=7 * (week + 1))
        results_by_week[week] = drift.run_drift_check(
            rows,
            period_end,
            period_days=7,
            window_seconds=DEFAULT_WINDOW_SECONDS,
            snapshot_log_path=SNAPSHOT_LOG_PATH,
            compare_to="oldest",
        )

    check(
        results_by_week[0] == {},
        "week1's snapshot run has no prior snapshot to compare against (correctly empty result)",
    )

    week2_vs_oldest = results_by_week[1][AGENT]
    print("\n" + drift.explain(AGENT, week2_vs_oldest))
    check(
        week2_vs_oldest["fired"] is False,
        "BASELINE_DRIFT does NOT fire between two stable training weeks (week2 vs week1)",
    )

    print("\n--- gradual drift, each week compared against the oldest (week1) snapshot ---")
    for week in (2, 3, 4):
        result = results_by_week[week][AGENT]
        print(drift.explain(AGENT, result))

    week6_vs_oldest = results_by_week[5][AGENT]
    print("\n" + drift.explain(AGENT, week6_vs_oldest))
    check(
        week6_vs_oldest["fired"] is True,
        "BASELINE_DRIFT FIRES between week1 (oldest) and week6 (fully drifted)",
    )
    check(
        any("payload" in r for r in week6_vs_oldest["reasons"]),
        "week6 drift reasons include the payload creep",
    )
    check(
        any("hour" in r for r in week6_vs_oldest["reasons"]),
        "week6 drift reasons include the active-hour creep",
    )

    ok, checked, err = drift.verify_chain(SNAPSHOT_LOG_PATH)
    check(ok and checked == 6, f"snapshot hash chain verifies clean over 6 entries (ok={ok}, checked={checked}, err={err})")

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)

    print(
        "ALL CHECKS PASSED - Phase 2's per-call detector stayed silent for all 28 drift-period days, "
        "Phase 7's BASELINE_DRIFT caught the shift by comparing snapshots."
    )


if __name__ == "__main__":
    main()
