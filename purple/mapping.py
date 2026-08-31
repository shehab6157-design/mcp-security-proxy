"""
mapping.py
-------------
Phase 5: translates a completed red-team ExecutionResult (red/executor.py)
into the shape of an MCP tool call, so it can be appended to the same
hash-chained call log (logs/calls.jsonl) the Phase 2 detector already
knows how to baseline against.

This is a modeling simplification, stated openly: the red-team engine
reasons in ATT&CK technique IDs against network targets, while the blue
detector reasons in per-agent tool-call patterns. Rather than build a
second, parallel detection surface for network techniques, Phase 5 assumes
the scenario this project's own differentiator is actually about (baselining
identity behavior, AI-agent or not): an attacker who has compromised an
EXISTING agent identity and is now using it to call tools it wouldn't
normally call, at a size/pattern it wouldn't normally produce - not an
attacker inventing a brand-new identity from nothing, which the detector
doesn't have a baseline for anyway (see detector/detector.py: an agent with
no baseline profile is skipped, not flagged).

So each technique maps to a plausible tool_name that identity would call to
carry it out, plus a representative payload_size band.
"""

from __future__ import annotations

import random

TECHNIQUE_TOOL_MAP = {
    "T1046": {"tool_name": "scan_network", "payload_range": (2000, 6000)},
    "T1021": {"tool_name": "ssh_connect", "payload_range": (100, 500)},
    "T1078": {"tool_name": "list_credentials", "payload_range": (50, 300)},
    "T1059": {"tool_name": "execute_shell_command", "payload_range": (200, 4000)},
    "T1071": {"tool_name": "http_request", "payload_range": (500, 8000)},
}


def to_call_fields(technique_id: str, target: str) -> dict:
    """Returns {tool_name, target_resource, payload_size} for injecting a
    red-team action into the MCP call log as though the impersonated agent
    made this call itself."""
    mapping = TECHNIQUE_TOOL_MAP.get(technique_id)
    if mapping is None:
        # Unmapped technique - fall back to a generic name rather than
        # silently dropping the round.
        return {
            "tool_name": f"unmapped_{technique_id.lower()}",
            "target_resource": target,
            "payload_size": 500,
        }

    low, high = mapping["payload_range"]
    return {
        "tool_name": mapping["tool_name"],
        "target_resource": target,
        "payload_size": random.randint(low, high),
    }
