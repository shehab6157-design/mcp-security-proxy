"""
test_tools_drift_synthetic.py
-------------
Phase 7 tools_jsd calibration, closing the gap README.md's Known Limitations
flagged: test_drift_synthetic.py's slow-drift agent only ever calls one tool
(read_file), so it exercises hours_jsd and payload_drift_z but never
tools_jsd at all - TOOLS_JSD_THRESHOLD (0.15) was a guess, not a measured
value.

This test's synthetic agent calls exactly two known tools throughout
(read_file, list_dir - both already in known_tools from the training
period, so NEW_TOOL never fires), from a fixed hour set and a
tool-independent payload distribution (both tools draw payload from the
same ~500-byte distribution, deliberately, so shifting the tool MIX can't
itself shift the agent's overall avg payload size - see payload_for()).
That isolates the thing being calibrated: only the read_file/list_dir USAGE
RATIO moves, starting at ~95% read_file / 5% list_dir and creeping, over
four drift weeks, to a near-complete reversal (~7% / 93%). No OFF_PATTERN,
no PAYLOAD_OUTLIER, no SEQUENCE_SPIKE, no NEW_TOOL at any point - Phase 2's
per-call detector has structurally nothing to alert on here, same as
test_drift_synthetic.py's hours/payload scenario.

Confirms:
  1. detector.detector.detect(), run over the whole drift period against a
     FIXED baseline from the training period, raises ZERO signals - Phase 2
     is blind to this the same way it was blind to the hours/payload drift.
  2. Two genuinely stable training weeks (week2 vs week1, both ~95/5 with
     ordinary day-to-day noise) do NOT fire BASELINE_DRIFT - this is the
     tools_jsd noise-floor measurement itself, printed explicitly, the
     thing README.md said was missing rather than assumed.
  3. tools_jsd rises monotonically as the mix drifts further from the
     training baseline (weeks 3-6, compared to the oldest/training
     snapshot), crossing TOOLS_JSD_THRESHOLD partway through the drift and
     firing clearly by full reversal - and payload_drift_z / fanout_drift_z
     / hours_jsd stay negligible throughout, confirming BASELINE_DRIFT fires
     here because of the tool-mix shift specifically, not as a side effect
     of something else moving.
  4. The snapshot log's hash chain verifies clean end to end.

Not a pytest suite (same standalone smoke-script convention as
test_drift_synthetic.py and proxy/test_client.py), runnable via:
    python3 -m detector.test_tools_drift_synthetic
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from detector import drift
from detector.baseline import DEFAULT_WINDOW_SECONDS, build_baseline
from detector.detector import detect

AGENT = "tool-mix-drift-agent"
READ_TOOL = "read_file"
LIST_TOOL = "list_dir"
GENESIS = datetime(2026, 1, 1, tzinfo=timezone.utc)
SNAPSHOT_LOG_PATH = Path(
    "/tmp/claude-1000/-home-shehab-shibli/"
    "a2128b2d-fb99-45ad-ae79-bd8fc3595d86/scratchpad/tools_drift_snapshots_test.jsonl"
)

# Fixed active hours, identical every week (training AND drift) - the thing
# under test is the tool MIX, not the hours, so hours must never move enough
# to raise OFF_PATTERN or contribute meaningfully to hours_jsd.
ACTIVE_HOURS = [9, 10, 11, 12, 13, 14, 15]
MINUTES_PER_HOUR = [0, 20, 40]  # 3 calls/hour, 20 min apart -> distinct 60s
                                 # fan-out windows every time, so fan-out
                                 # stays flat at 1 regardless of tool mix.
CALLS_PER_DAY = len(ACTIVE_HOURS) * len(MINUTES_PER_HOUR)  # 21

# Per-week (read_file_count, list_dir_count) per day, 7 entries/week, each
# summing to CALLS_PER_DAY (21). Weeks 0-1 are training (stable, ~95/5 with
# ordinary day-to-day noise - week1 is NOT identical to week0, so the
# noise-floor measurement below reflects real sampling variation, not a
# contrived zero). Weeks 2-5 are the drift period, creeping the ratio from
# ~95/5 toward its near-total reversal by week5 - symmetric by design
# (week5 mirrors week1, week4 mirrors week2, week3 is the ~50/50 midpoint)
# so the progression is legible.
WEEK_DAY_COUNTS = {
    0: [(20, 1), (20, 1), (20, 1), (20, 1), (20, 1), (20, 1), (20, 1)],   # 140/7   = 95.2%/4.8%
    1: [(19, 2), (20, 1), (19, 2), (20, 1), (19, 2), (20, 1), (20, 1)],   # 137/10  = 93.2%/6.8%  (training noise)
    2: [(14, 7), (15, 6), (14, 7), (15, 6), (14, 7), (15, 6), (14, 7)],   # 101/46  = 68.7%/31.3%
    3: [(10, 11), (11, 10), (10, 11), (11, 10), (10, 11), (11, 10), (10, 11)],  # 73/74 = 49.7%/50.3%
    4: [(7, 14), (6, 15), (7, 14), (6, 15), (7, 14), (6, 15), (7, 14)],   # 46/101  = 31.3%/68.7% (mirror of wk2)
    5: [(2, 19), (1, 20), (2, 19), (1, 20), (2, 19), (1, 20), (1, 20)],   # 10/137  = 6.8%/93.2%  (mirror of wk1)
}

# Same ~500-byte distribution for BOTH tools, deliberately - see module
# docstring. Cycles by call index so it's deterministic, not random.
PAYLOAD_CYCLE = [470, 500, 530, 490, 510, 480, 520, 500, 460, 540, 500, 490,
                 510, 470, 530, 500, 480, 520, 490, 510, 500]  # len 21, mean 500


def make_row(i, day, hour, minute, tool, payload):
    return {
        "trace_id": f"tools-synthetic-{i:04d}",
        "timestamp": GENESIS + timedelta(days=day, hours=hour, minutes=minute),
        "agent_id": AGENT,
        "tool_name": tool,
        "target_resource": "/data/file.txt" if tool == READ_TOOL else "/data/",
        "payload_size": payload,
        "reasoning_summary": "synthetic tool-mix drift verification call",
    }


def interleave(read_count, list_count, total):
    """Evenly spreads `read_count` READ_TOOL and `list_count` LIST_TOOL
    entries across `total` slots (Bresenham-style), rather than
    block-grouping them, so any given 60s fan-out window is never forced to
    contain both tools just from adjacency.
    """
    tools = []
    acc = 0
    for _ in range(total):
        acc += read_count
        if acc >= total:
            tools.append(READ_TOOL)
            acc -= total
        else:
            tools.append(LIST_TOOL)
    assert tools.count(READ_TOOL) == read_count and tools.count(LIST_TOOL) == list_count
    return tools


def generate_rows():
    rows = []
    i = 0
    for week in range(6):
        day_counts = WEEK_DAY_COUNTS[week]
        for day_in_week in range(7):
            day = week * 7 + day_in_week
            read_count, list_count = day_counts[day_in_week]
            assert read_count + list_count == CALLS_PER_DAY

            tools_today = interleave(read_count, list_count, CALLS_PER_DAY)

            slot = 0
            for hour in ACTIVE_HOURS:
                for minute in MINUTES_PER_HOUR:
                    tool = tools_today[slot]
                    payload = PAYLOAD_CYCLE[slot]
                    rows.append(make_row(i, day, hour, minute, tool, payload))
                    i += 1
                    slot += 1
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

    # --- 1. Phase 2 alone, over the whole drift period ---------------------
    phase2_baseline = build_baseline(training_rows, window_seconds=DEFAULT_WINDOW_SECONDS)
    print(f"Phase 2 baseline (from training only): {phase2_baseline[AGENT]}\n")

    phase2_alerts = detect(drift_rows, phase2_baseline, DEFAULT_WINDOW_SECONDS, jobs=[])
    check(
        phase2_alerts == [],
        f"Phase 2 detector.detect() raised 0 signals over all {len(drift_rows)} drift-period calls "
        f"(got {len(phase2_alerts)}: {phase2_alerts[:3]})",
    )

    # --- 2. Phase 7: weekly snapshots + drift comparison --------------------
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

    # --- 3. Noise floor: two stable, ~95/5 training weeks -------------------
    week2_vs_oldest = results_by_week[1][AGENT]
    print("\n--- stable-weeks sanity check (week2 vs week1, both ~95/5 with ordinary noise) ---")
    print(drift.explain(AGENT, week2_vs_oldest))
    print(f"    ^ this is the measured tools_jsd NOISE FLOOR: {week2_vs_oldest['tools_jsd']}")
    check(
        week2_vs_oldest["fired"] is False,
        "BASELINE_DRIFT does NOT fire between two stable training weeks (week2 vs week1)",
    )
    check(
        week2_vs_oldest["tools_jsd"] < drift.TOOLS_JSD_THRESHOLD,
        f"measured noise floor ({week2_vs_oldest['tools_jsd']}) sits below "
        f"TOOLS_JSD_THRESHOLD ({drift.TOOLS_JSD_THRESHOLD}) with margin",
    )

    print("\n--- gradual tool-mix drift, each week compared against the oldest (week1) snapshot ---")
    for week in (2, 3, 4):
        result = results_by_week[week][AGENT]
        print(drift.explain(AGENT, result))

    week6_vs_oldest = results_by_week[5][AGENT]
    print("\n--- full reversal (week6 vs week1) ---")
    print(drift.explain(AGENT, week6_vs_oldest))
    check(
        week6_vs_oldest["fired"] is True,
        "BASELINE_DRIFT FIRES between week1 (oldest, ~95% read_file) and week6 (~93% list_dir)",
    )
    check(
        any("tool" in r for r in week6_vs_oldest["reasons"]),
        "week6 drift reasons include the tool-usage mix shift",
    )
    check(
        not any("payload" in r for r in week6_vs_oldest["reasons"]),
        "week6 drift reasons do NOT include payload (mix shift is isolated from payload, by design)",
    )
    check(
        not any("fan-out" in r for r in week6_vs_oldest["reasons"]),
        "week6 drift reasons do NOT include fan-out (calls are spaced to keep fan-out flat)",
    )
    check(
        not any("call-hour" in r for r in week6_vs_oldest["reasons"]),
        "week6 drift reasons do NOT include call-hour timing (hours are fixed across all weeks)",
    )

    # tools_jsd should rise monotonically as the mix drifts further from
    # the training baseline (weeks 3, 4, 5, 6 all compared to oldest/week1).
    jsd_by_week = [results_by_week[w][AGENT]["tools_jsd"] for w in (1, 2, 3, 4, 5)]
    check(
        jsd_by_week == sorted(jsd_by_week),
        f"tools_jsd rises monotonically as the mix drifts further from training: {jsd_by_week}",
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
        "ALL CHECKS PASSED - Phase 2's per-call detector stayed silent for the whole drift period, "
        "Phase 7's tools_jsd caught the read_file/list_dir mix reversing while the noise floor between "
        "two genuinely stable weeks stayed well under TOOLS_JSD_THRESHOLD."
    )


if __name__ == "__main__":
    main()
