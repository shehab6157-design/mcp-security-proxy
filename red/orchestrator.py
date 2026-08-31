"""
orchestrator.py
-------------
Phase 4: on-demand red-team run. NOT a daemon - triggered by a CLI command
(or, later, Phase 6's cron/Telegram trigger), runs a fixed number of
technique/target picks against the mock executor, then exits.

Safety design: every target this orchestrator considers comes from
red/scope.py's load_scope() - the lab scope allowlist is the only source of
targets it will ever plan against. The executor it hands each pick to then
independently reloads and re-checks that same file itself (see
red/executor.py) before doing anything. That means there is no path from
"the planning logic here has a bug" to "a real action lands on an
out-of-scope host" - per PROJECT_SPEC.md Phase 4's requirement that this be
"architecturally incapable of acting outside that list."

Usage:
    python3 -m red.orchestrator [--runs 3] [--scope config/lab_scope.yaml]
"""

from __future__ import annotations

import argparse
import random

from red.executor import Executor, MockExecutor
from red.run_log import HashChainRunLog
from red.scope import SCOPE_PATH, OutOfScopeError, load_scope
from red.techniques import CATALOG

RUN_LOG_PATH = "logs/red_runs.jsonl"


def plan_runs(scope: frozenset[str], n: int):
    """Pick n (technique, target) pairs, varying technique and target
    independently each time. Targets are drawn ONLY from the scope set
    passed in - this function has no other way to name a target."""
    targets = sorted(scope)
    return [(random.choice(CATALOG), random.choice(targets)) for _ in range(n)]


def run(executor: Executor, scope: frozenset[str], n: int, run_log: HashChainRunLog):
    if not scope:
        raise OutOfScopeError(
            "lab scope is empty - add at least one self-owned VM to config/lab_scope.yaml before running"
        )

    results = []
    for technique, target in plan_runs(scope, n):
        result = executor.run_technique(technique.id, technique.name, target)
        run_log.append(
            technique_id=result.technique_id,
            technique_name=result.technique_name,
            target=result.target,
            executor=executor.name,
            status=result.status,
            detail=result.detail,
        )
        results.append(result)
    return results


def main():
    parser = argparse.ArgumentParser(description="Run an on-demand, lab-scoped red-team simulation")
    parser.add_argument("--runs", type=int, default=3, help="number of technique/target picks to run")
    parser.add_argument(
        "--scope", default=SCOPE_PATH, help=f"path to the lab scope allowlist (default: {SCOPE_PATH})"
    )
    parser.add_argument(
        "--log-path", default=RUN_LOG_PATH, help=f"path to the red-team run log (default: {RUN_LOG_PATH})"
    )
    args = parser.parse_args()

    scope = load_scope(args.scope)
    print(f"Loaded {len(scope)} in-scope target(s) from {args.scope}: {sorted(scope)}")
    if not scope:
        print("Scope is empty - refusing to run. Add at least one self-owned lab VM to the scope file.")
        return

    executor = MockExecutor(scope_path=args.scope)
    run_log = HashChainRunLog(args.log_path)

    results = run(executor, scope, args.runs, run_log)

    print(f"\n=== {len(results)} run(s) via '{executor.name}' executor ===\n")
    for r in results:
        print(f"[{r.status}] {r.technique_id} ({r.technique_name}) -> {r.target}: {r.detail}")

    print(f"\nLogged to {args.log_path}")


if __name__ == "__main__":
    main()
