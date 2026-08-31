"""
techniques.py
-------------
A small, self-contained catalog of MITRE ATT&CK-style techniques for the
orchestrator to vary between (PROJECT_SPEC.md Phase 4: "orchestrated by
this project to vary technique/timing"). Just enough to exercise the
scope-gated mock executor - swap in Caldera's own ability catalog once a
real executor is wired in.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    id: str
    name: str


CATALOG = [
    Technique("T1046", "Network Service Discovery"),
    Technique("T1021", "Remote Services"),
    Technique("T1078", "Valid Accounts"),
    Technique("T1059", "Command and Scripting Interpreter"),
    Technique("T1071", "Application Layer Protocol"),
]
