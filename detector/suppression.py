"""
suppression.py
-------------
Phase 3: business-context false-positive suppression.

Loads config/known_jobs.yaml - a human-curated list of known-legitimate
recurring patterns (agent/tool pair, active-hours window, expected payload
range) - and uses it to strip specific signals off a call's detection
result when that call matches a documented pattern.

This deliberately does NOT solve general business-logic judgment: a job
only suppresses signals it explicitly lists, and only for calls landing
inside ALL of its match criteria (agent_id, tool_name, hour window, payload
range). Anything else - including a call that matches on agent/tool/hours
but drifts outside the expected payload range - is left untouched and
still flows through detector.py's normal tiering. Suppressed signals are
never silently dropped: apply_suppression() returns them alongside which
job matched, so they stay visible in output for audit purposes.
"""

from __future__ import annotations

import yaml

KNOWN_JOBS_PATH = "config/known_jobs.yaml"


def load_known_jobs(path=KNOWN_JOBS_PATH):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return []
    return data.get("jobs", [])


def _hour_in_window(hour, start, end):
    if start <= end:
        return start <= hour <= end
    return hour >= start or hour <= end  # window wraps past midnight


def _job_matches(job, row):
    if job["agent_id"] != row["agent_id"]:
        return False
    if job["tool_name"] != row["tool_name"]:
        return False

    hours = job.get("hours")
    if hours is not None and not _hour_in_window(row["timestamp"].hour, hours["start"], hours["end"]):
        return False

    payload_range = job.get("payload_size")
    if payload_range is not None:
        size = row["payload_size"]
        if not (payload_range["min"] <= size <= payload_range["max"]):
            return False

    return True


def apply_suppression(row, signals, jobs):
    """
    Given the full list of signals detector.py raised for one call, return
    (remaining_signals, suppressed) - remaining_signals is what's left to
    tier normally, and suppressed is a list of {"signal": ..., "job": ...}
    dicts recording what was pulled out and why, so nothing disappears
    without a trace.
    """
    remaining = list(signals)
    suppressed = []

    for job in jobs:
        if not remaining:
            break
        if not _job_matches(job, row):
            continue
        for sig in job.get("suppresses", []):
            if sig in remaining:
                remaining.remove(sig)
                suppressed.append({"signal": sig, "job": job["name"]})

    return remaining, suppressed
