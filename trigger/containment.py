"""
containment.py
-------------
Phase 6: a minimal, explicitly simulated containment recommendation.
PROJECT_SPEC.md's non-goals are explicit that this project does not
implement real least-privilege/access-control enforcement - so this never
touches any real credential, session, or permission, and never acts on its
own. For an alert-tier detection it only produces a recommendation a human
reviewing the run would want to see; the human decides whether to act on
it. Nothing below is a live action.
"""

from __future__ import annotations

_ALERT_TEMPLATE = (
    "recommend suspending '{agent}' pending human review "
    "(trace {trace_id}, correlated signals: {signals})"
)


def recommend_containment(tier: str, agent: str, trace_id: str, signals: list) -> str | None:
    """Returns a human-readable containment recommendation for an
    alert-tier detection, or None if this tier doesn't warrant one
    (observation/suppressed/missed rounds get no recommendation - a single
    signal or a suppressed match isn't enough to recommend suspending an
    identity)."""
    if tier != "alert":
        return None
    return _ALERT_TEMPLATE.format(agent=agent, trace_id=trace_id, signals=", ".join(signals))
