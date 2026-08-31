"""
orchestrator.py
-------------
Phase 5: runs red and blue in the same loop and scores blue's detection
rate against red's variations (PROJECT_SPEC.md Phase 5).

How red and blue meet: this calls red/orchestrator.py's own run() function
directly (same scope-gated mock executor as Phase 4, unchanged) to get a
batch of ExecutionResults, then purple/mapping.py translates each one into
what it would look like as an MCP tool call FROM THE IMPERSONATED AGENT'S
IDENTITY and appends it to the real call log (logs/calls.jsonl) using
Phase 1's own hash-chained audit log (proxy/audit_log.py) - so blue sees it
exactly the way it would see a real compromised-agent call, not a separate
synthetic feed. This models the scenario this project's own differentiator
is about: an attacker operating through an identity blue already has a
baseline for, not a brand-new identity appearing from nowhere (see
purple/mapping.py's docstring for why).

detector.detector.detect() then runs ONCE over the whole updated log (so
cross-round signals like SEQUENCE_SPIKE, which depend on the full time
window rather than one call, evaluate correctly), and each round's outcome
is read back off the trace_id of the call it injected.

Requires a baseline already built for --impersonate-agent (see
detector/baseline.py) - this module does not fabricate baseline history;
scoring detection against an identity blue has never profiled isn't a
meaningful test.

The round-trip itself lives in run_purple_round_trip() so Phase 6's
on-demand trigger (trigger/run.py) can drive the same red+blue loop and
narrate each round to Telegram as it happens, instead of only getting a
final printed report the way this module's own CLI does.

Usage:
    python3 -m purple.orchestrator --rounds 5 --impersonate-agent dev-test-agent
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field

from detector.baseline import BASELINE_PATH, load_calls
from detector.detector import KNOWN_JOBS_PATH, detect, load_baseline
from detector.suppression import load_known_jobs
from proxy.audit_log import HashChainAuditLog
from purple.mapping import to_call_fields
from purple.scoreboard import PurpleScoreboard
from red.executor import Executor, MockExecutor
from red.orchestrator import RUN_LOG_PATH as RED_RUN_LOG_PATH
from red.orchestrator import run as run_red
from red.run_log import HashChainRunLog
from red.scope import SCOPE_PATH, load_scope

SCOREBOARD_PATH = "logs/purple_runs.jsonl"

OUTCOME_KINDS = ("alert", "observation", "suppressed", "missed")


@dataclass
class RoundOutcome:
    round_no: int
    technique_id: str
    technique_name: str
    target: str
    tool_name: str
    trace_id: str
    tier: str
    signals: list = field(default_factory=list)
    suppressed_signals: list = field(default_factory=list)
    outcome: str = "missed"


def run_purple_round_trip(
    *,
    scope,
    baseline,
    window_seconds,
    jobs,
    executor: Executor,
    rounds: int,
    impersonate_agent: str,
    call_log: HashChainAuditLog,
    red_log: HashChainRunLog,
    scoreboard: PurpleScoreboard,
) -> list[RoundOutcome]:
    """Runs `rounds` red-team actions (via red/orchestrator.py's run()),
    injects each as an MCP call under impersonate_agent's identity, scores
    all of them against blue in one detect() pass, and records each round
    to `scoreboard`. Returns the per-round outcomes for the caller to
    report however it likes (printed, sent to Telegram, etc.)."""
    red_results = run_red(executor, scope, rounds, red_log)

    injected = []
    for round_no, result in enumerate(red_results, start=1):
        fields = to_call_fields(result.technique_id, result.target)
        call_entry = call_log.append(
            agent_id=impersonate_agent,
            tool_name=fields["tool_name"],
            target_resource=fields["target_resource"],
            payload_size=fields["payload_size"],
            reasoning_summary=f"[red-team simulation, round {round_no}] {result.detail}",
        )
        injected.append((round_no, result, call_entry))

    rows = load_calls(str(call_log.log_path))
    detections = detect(rows, baseline, window_seconds, jobs=jobs)
    by_trace = {d["trace_id"]: d for d in detections}

    outcomes = []
    for round_no, result, call_entry in injected:
        blue = by_trace.get(call_entry.trace_id)
        if blue is None:
            tier, signals, suppressed_signals, outcome = "none", [], [], "missed"
        else:
            tier = blue["tier"]
            signals = blue["signals"]
            suppressed_signals = blue.get("suppressed_signals", [])
            outcome = tier if tier in OUTCOME_KINDS else "missed"

        scoreboard.append(
            round_no=round_no,
            technique_id=result.technique_id,
            technique_name=result.technique_name,
            target=result.target,
            impersonated_agent=impersonate_agent,
            injected_call_trace_id=call_entry.trace_id,
            tool_name=call_entry.tool_name,
            blue_tier=tier,
            blue_signals=signals,
            outcome=outcome,
        )

        outcomes.append(
            RoundOutcome(
                round_no=round_no,
                technique_id=result.technique_id,
                technique_name=result.technique_name,
                target=result.target,
                tool_name=call_entry.tool_name,
                trace_id=call_entry.trace_id,
                tier=tier,
                signals=signals,
                suppressed_signals=suppressed_signals,
                outcome=outcome,
            )
        )

    return outcomes


def main():
    parser = argparse.ArgumentParser(description="Run red + blue together and score blue's detection rate")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument(
        "--impersonate-agent",
        default="dev-test-agent",
        help="agent identity the red-team run impersonates - must already have a learned baseline",
    )
    parser.add_argument("--scope", default=SCOPE_PATH)
    parser.add_argument("--calls-log", default="logs/calls.jsonl")
    parser.add_argument("--baseline", default=BASELINE_PATH)
    parser.add_argument("--known-jobs", default=KNOWN_JOBS_PATH)
    parser.add_argument("--red-log", default=RED_RUN_LOG_PATH)
    parser.add_argument("--scoreboard", default=SCOREBOARD_PATH)
    args = parser.parse_args()

    scope = load_scope(args.scope)
    if not scope:
        print(f"Scope is empty - refusing to run (see {args.scope}).")
        return

    try:
        baseline, window_seconds = load_baseline(args.baseline)
    except FileNotFoundError:
        print(f"No baseline at {args.baseline} - run `python3 -m detector.baseline` first.")
        return

    if args.impersonate_agent not in baseline:
        print(
            f"'{args.impersonate_agent}' has no learned baseline in {args.baseline} - "
            "blue can't score detection for an identity it has never profiled. "
            "Build call history for this agent and run detector.baseline first."
        )
        return

    jobs = load_known_jobs(args.known_jobs)
    executor = MockExecutor(scope_path=args.scope)
    red_log = HashChainRunLog(args.red_log)
    call_log = HashChainAuditLog(args.calls_log)
    scoreboard = PurpleScoreboard(args.scoreboard)

    outcomes = run_purple_round_trip(
        scope=scope,
        baseline=baseline,
        window_seconds=window_seconds,
        jobs=jobs,
        executor=executor,
        rounds=args.rounds,
        impersonate_agent=args.impersonate_agent,
        call_log=call_log,
        red_log=red_log,
        scoreboard=scoreboard,
    )

    print(
        f"\n=== Purple round results ({len(outcomes)} round(s), "
        f"impersonating '{args.impersonate_agent}') ===\n"
    )
    outcome_counts = {k: 0 for k in OUTCOME_KINDS}

    for o in outcomes:
        outcome_counts[o.outcome] += 1

        flag = ""
        if o.outcome == "suppressed":
            suppressed_by = ", ".join(
                f"{s['signal']} (known job: {s['job']})" for s in o.suppressed_signals
            )
            flag = (
                f"  <-- SUPPRESSED [{suppressed_by}]: verify this wasn't "
                "a real attack matching a documented pattern"
            )
        print(
            f"round {o.round_no}: {o.technique_id} ({o.technique_name}) -> {o.target} "
            f"as {o.tool_name} | blue tier={o.tier} signals={o.signals or '(none)'}{flag}"
        )

    total = len(outcomes) or 1
    hard_rate = outcome_counts["alert"] / total
    any_signal_rate = (outcome_counts["alert"] + outcome_counts["observation"]) / total

    print(f"\n=== Score: {args.impersonate_agent} over {len(outcomes)} round(s) ===")
    print(f"  alert (caught, correlated signals):  {outcome_counts['alert']}")
    print(f"  observation (logged, single signal): {outcome_counts['observation']}")
    print(f"  suppressed (known-job match):         {outcome_counts['suppressed']}")
    print(f"  missed (no signal at all):            {outcome_counts['missed']}")
    print(f"  hard detection rate (alert only):    {hard_rate:.0%}")
    print(f"  any-signal rate (alert+observation): {any_signal_rate:.0%}")
    print(f"\nRed actions logged to {args.red_log}")
    print(f"Injected calls appended to {args.calls_log}")
    print(f"Round scoring logged to {args.scoreboard}")


if __name__ == "__main__":
    main()
