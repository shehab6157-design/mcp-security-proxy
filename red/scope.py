"""
scope.py
-------------
Phase 4 hard safety boundary: loads config/lab_scope.yaml and is the single
source of truth every red-team action is checked against before it's
allowed to run against a target - mock or live.

Deliberately fail-closed and deliberately narrow:
  - A missing, empty, or unparseable scope file means NO targets are in
    scope - never "allow everything" as a fallback.
  - Matching is exact string equality only. No CIDR ranges, no wildcards,
    no substring/prefix matching - a typo in a range could silently put an
    unintended host in scope, so every host must be listed explicitly.

Known limit (be honest about it, per PROJECT_SPEC.md's non-goals ethos):
this is a process-level, convention-based check - it stops this codebase
from dispatching an out-of-scope action, it is not network-level
enforcement (no firewall/segmentation). Pair it with real network isolation
for the lab VM(s) if this is ever run somewhere that matters.
"""

from __future__ import annotations

import yaml

SCOPE_PATH = "config/lab_scope.yaml"

# Entries that would defeat the point of an allowlist if accepted.
_DISALLOWED_ENTRIES = {"0.0.0.0", "0.0.0.0/0", "::", "::/0", "*", ""}


class OutOfScopeError(Exception):
    """Raised when a red-team action would target something not in the lab scope file."""


def load_scope(path: str = SCOPE_PATH) -> frozenset[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return frozenset()

    targets = data.get("targets") or []
    cleaned = set()
    for raw in targets:
        entry = str(raw).strip()
        if not entry or entry in _DISALLOWED_ENTRIES:
            continue
        if "/" in entry or "*" in entry or "?" in entry or " " in entry:
            # Reject CIDR notation, wildcards, and anything with whitespace -
            # exact single hosts only, see module docstring.
            continue
        cleaned.add(entry)
    return frozenset(cleaned)


def assert_in_scope(target: str, scope: frozenset[str]) -> None:
    if not scope:
        raise OutOfScopeError(
            "lab scope is empty (missing/blank config/lab_scope.yaml) - refusing all targets"
        )
    if target not in scope:
        raise OutOfScopeError(
            f"target {target!r} is not in the lab scope allowlist {sorted(scope)}"
        )
