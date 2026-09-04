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

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass

from red.caldera_client import CalderaClient, CalderaError
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


class CalderaExecutor(Executor):
    """Launches real MITRE Caldera operations - Discovery adversary, atomic
    planner - against agents in the lab scope.

    Every target this class ever sees has already passed
    Executor.run_technique()'s assert_in_scope() gate; this class never
    reads the scope file itself, it only forwards an already-verified
    target on to Caldera in the log line.

    Caldera doesn't target an individual host per operation - an operation
    runs against a whole agent GROUP. This lab's scope file
    (config/lab_scope.yaml) lists exactly one host, and exactly one Caldera
    agent (group "red") runs on it, so one fixed group is enough here. If
    the scope file ever grows a second host on a different agent, this
    needs a real target->group lookup, not the single `group` constructor
    argument below - be honest about that limit rather than pretending a
    single group generalizes.

    Each call runs the Discovery adversary's whole ability bundle via
    Caldera's own atomic planner, not the one technique_id/name the
    orchestrator picked from red/techniques.py's catalog - Caldera decides
    the next ability by OS/fact-availability, not by an ATT&CK id we hand
    it. The picked technique is carried through only for the run log.
    """

    name = "caldera"

    ATOMIC_PLANNER_ID = "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a"
    DISCOVERY_ADVERSARY_ID = "0f4c3c67-845e-49a0-927e-90ed33c044e0"
    BASIC_SOURCE_ID = "ed32b9c3-9593-4c33-b0db-e2007315096b"

    def __init__(self, scope_path: str = SCOPE_PATH, group: str = "red", client: CalderaClient | None = None):
        super().__init__(scope_path)
        self.group = group
        self.client = client or CalderaClient()

    def _execute(self, technique_id: str, technique_name: str, target: str) -> ExecutionResult:
        op_name = f"mcp-sec-proxy-{technique_id}-{uuid.uuid4().hex[:8]}"
        try:
            op = self.client.create_operation(
                name=op_name,
                adversary_id=self.DISCOVERY_ADVERSARY_ID,
                planner_id=self.ATOMIC_PLANNER_ID,
                source_id=self.BASIC_SOURCE_ID,
                group=self.group,
            )
        except CalderaError as e:
            return ExecutionResult(
                technique_id=technique_id,
                technique_name=technique_name,
                target=target,
                status="failed",
                detail=f"[caldera] failed to launch operation against {target} (group={self.group!r}): {e}",
            )

        op_id = op.get("id", "unknown")
        return ExecutionResult(
            technique_id=technique_id,
            technique_name=technique_name,
            target=target,
            status="success",
            detail=(
                f"[caldera] launched operation {op_id} ({op_name!r}): Discovery adversary via atomic "
                f"planner against group {self.group!r} ({target}); plan pick {technique_id} "
                f"({technique_name}) triggered this run, Caldera's own ability set now drives it"
            ),
        )
