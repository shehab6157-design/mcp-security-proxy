"""
executor.py
-------------
Phase 4: pluggable technique executors behind one interface, so the
orchestrator (and later Phase 5's purple-team loop) doesn't care whether a
run is simulated or hitting a real Caldera server.

The scope check is NOT something each executor remembers to call - it's
baked into the base class's run_technique(), which is the only public entry
point. Executor.__init__() loads its own copy of the scope file directly
from disk rather than trusting a scope set handed to it by the caller, so
even a buggy orchestrator that computed the wrong target list can't get a
live action dispatched to an out-of-scope host: the executor independently
re-verifies against the authoritative file every time. Subclasses only
implement _execute() and inherit the gate for free - they have no way to
reach real execution without passing through it first.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from red.scope import SCOPE_PATH, assert_in_scope, load_scope


@dataclass
class ExecutionResult:
    technique_id: str
    technique_name: str
    target: str
    status: str  # "simulated" | "success" | "failed"
    detail: str


class Executor(ABC):
    name: str

    def __init__(self, scope_path: str = SCOPE_PATH):
        self.scope_path = scope_path
        self._scope = load_scope(scope_path)

    def run_technique(self, technique_id: str, technique_name: str, target: str) -> ExecutionResult:
        assert_in_scope(target, self._scope)
        return self._execute(technique_id, technique_name, target)

    @abstractmethod
    def _execute(self, technique_id: str, technique_name: str, target: str) -> ExecutionResult:
        """Subclasses implement the actual (or simulated) action here. Only
        ever called after run_technique() has confirmed the target is in
        scope - never call this directly."""


class MockExecutor(Executor):
    """Doesn't touch the network. Reports what it WOULD have run, so the
    scope-gating and orchestration logic can be built and exercised before a
    real Caldera server is wired in (see PROJECT_SPEC.md Phase 4)."""

    name = "mock"

    def _execute(self, technique_id: str, technique_name: str, target: str) -> ExecutionResult:
        return ExecutionResult(
            technique_id=technique_id,
            technique_name=technique_name,
            target=target,
            status="simulated",
            detail=f"[mock] would run {technique_id} ({technique_name}) against {target} - no real action taken",
        )
