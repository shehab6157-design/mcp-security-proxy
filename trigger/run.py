"""
run.py
-------------
Phase 6: the on-demand trigger. No daemon - this is what a manual command
or a cron schedule runs: one purple-team round-trip (red + blue, Phase 5),
narrated to Telegram at each stage (PROJECT_SPEC.md Phase 6: "run started,
technique attempted, detected/missed, containment action taken, run
summary"). It exits when the round-trip is done; nothing here keeps
running afterward.

Telegram credentials are read from the environment (see
trigger/telegram.py) - if unset, notifications print to stdout instead, so
this is fully runnable without Telegram configured.

Usage:
    python3 -m trigger.run --rounds 5 --impersonate-agent dev-test-agent

    # on a cron schedule (crontab -e), e.g. once a day at 03:00:
    0 3 * * * cd /home/shehab-shibli/mcp-security-proxy && venv/bin/python3 -m trigger.run
"""

from __future__ import annotations

import argparse

from detector.baseline import BASELINE_PATH
from detector.detector import KNOWN_JOBS_PATH, load_baseline
from detector.suppression import load_known_jobs
from proxy.audit_log import HashChainAuditLog
from purple.orchestrator import SCOREBOARD_PATH, run_purple_round_trip
from purple.scoreboard import PurpleScoreboard
from red.executor import MockExecutor
from red.orchestrator import RUN_LOG_PATH as RED_RUN_LOG_PATH
from red.run_log import HashChainRunLog
from red.scope import SCOPE_PATH, load_scope
from trigger.containment import recommend_containment
from trigger.telegram import TelegramNotifier

OUTCOME_EMOJI = {
    "alert": "\U0001F6A8",  # rotating light
    "observation": "\U0001F440",  # eyes
    "suppressed": "\U0001F515",  # muted bell
    "missed": "❌",  # cross mark
}


def main():
    parser = argparse.ArgumentParser(description="On-demand trigger: run red+blue and notify Telegram")
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

    notifier = TelegramNotifier()

    scope = load_scope(args.scope)
    if not scope:
        notifier.notify(f"Purple run ABORTED: lab scope is empty ({args.scope}).")
        return

    try:
        baseline, window_seconds = load_baseline(args.baseline)
    except FileNotFoundError:
        notifier.notify(f"Purple run ABORTED: no baseline at {args.baseline}.")
        return

    if args.impersonate_agent not in baseline:
        notifier.notify(
            f"Purple run ABORTED: '{args.impersonate_agent}' has no learned baseline - "
            "run detector.baseline first."
        )
        return

    jobs = load_known_jobs(args.known_jobs)
    executor = MockExecutor(scope_path=args.scope)
    red_log = HashChainRunLog(args.red_log)
    call_log = HashChainAuditLog(args.calls_log)
    scoreboard = PurpleScoreboard(args.scoreboard)

    notifier.notify(
        f"Purple run started: {args.rounds} round(s), impersonating "
        f"'{args.impersonate_agent}', scope={sorted(scope)}"
    )

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

    counts = {"alert": 0, "observation": 0, "suppressed": 0, "missed": 0}
    for o in outcomes:
        counts[o.outcome] += 1

        notifier.notify(
            f"round {o.round_no}: attempted {o.technique_id} ({o.technique_name}) "
            f"-> {o.target} as '{o.tool_name}'"
        )

        emoji = OUTCOME_EMOJI[o.outcome]
        if o.outcome == "alert":
            notifier.notify(f"round {o.round_no}: {emoji} DETECTED - signals: {', '.join(o.signals)}")
            rec = recommend_containment(o.tier, args.impersonate_agent, o.trace_id, o.signals)
            if rec:
                notifier.notify(f"round {o.round_no}: containment - {rec}")
        elif o.outcome == "observation":
            notifier.notify(
                f"round {o.round_no}: {emoji} logged (observation) - signal: {', '.join(o.signals)}"
            )
        elif o.outcome == "suppressed":
            jobs_hit = ", ".join(s["job"] for s in o.suppressed_signals) or "unknown job"
            notifier.notify(
                f"round {o.round_no}: {emoji} suppressed by known job(s) [{jobs_hit}] - verify this "
                "wasn't a real attack matching a documented pattern"
            )
        else:
            notifier.notify(f"round {o.round_no}: {emoji} MISSED - no signal triggered")

    total = len(outcomes) or 1
    hard_rate = counts["alert"] / total
    any_signal_rate = (counts["alert"] + counts["observation"]) / total

    notifier.notify(
        f"Purple run summary: {counts['alert']} alert, {counts['observation']} observation, "
        f"{counts['suppressed']} suppressed, {counts['missed']} missed out of {len(outcomes)} "
        f"round(s) - hard detection rate {hard_rate:.0%}, any-signal rate {any_signal_rate:.0%}"
    )


if __name__ == "__main__":
    main()
