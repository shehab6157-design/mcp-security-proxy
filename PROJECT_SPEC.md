# MCP Security Proxy — Project Spec

## Goal
A personal, on-demand cybersecurity agent for lab/portfolio use. NOT 24/7 autonomous —
triggered manually or on a schedule. Combines a red-team simulation engine, a blue-team
behavioral anomaly detector, and a purple-team scoring orchestrator. Alerts sent to Telegram.
Runs only against self-owned lab targets (VMs on this network), never external systems.

## Differentiator
Most anomaly detection assumes the actor is human. This project baselines behavior per
identity (device or AI agent) regardless of whether that identity is human or an AI agent —
so it generalizes to detecting anomalous AI agent tool-call behavior, not just network traffic.

## Prior work this builds on
A related project (lateral-movement-detector) already built and validated:
- Per-device baseline of peer relationships, active hours, transfer volume, fan-out
- Four signal types: NEW_PEER, OFF_HOURS, VOLUME_OUTLIER, FANOUT_SPIKE
- Detected a simulated SSH-flood attack 5/5 with 0 false positives on real captured traffic

## Phase 1 — MCP Proxy (current phase)
Build an MCP proxy that sits between an AI agent and its tools, logging every call:
- Fields per log entry: trace_id, timestamp (UTC), agent_id, tool_name, target_resource,
  payload_size, a short reasoning_summary
- Each entry includes a hash of the previous entry (hash-chained, tamper-evident, append-only)
- This log is the equivalent of lateral-movement-detector's real_traffic.csv — the data
  source the detector will baseline against

## Phase 2 — Port the detector
Repoint baseline.py/detector.py logic (from lateral-movement-detector) at the MCP proxy's
call log instead of network traffic. Signal mapping:
- NEW_PEER → NEW_TOOL (agent calls a tool it's never used)
- VOLUME_OUTLIER → PAYLOAD_OUTLIER (unusually large payload in one call)
- OFF_HOURS → OFF_PATTERN (call at an unusual time/rate for this agent)
- FANOUT_SPIKE → SEQUENCE_SPIKE (burst of distinct tool calls in a short window)

Add tiered confidence: single-signal = log only; multiple correlated signals = alert.

## Phase 3 — Business-context mitigation (false positive reduction)
A config file (known_jobs.yaml or similar) listing known-legitimate recurring patterns
(device/agent pair, time window, expected volume range). Before alerting on a volume/payload
anomaly, check against this file — matches get suppressed or downgraded, not alerted.
Unmatched anomalies still get flagged for human review — this is NOT meant to solve business-
logic judgment in general, only handle known recurring legitimate patterns.

## Phase 4 — Red engine (lab-only, hard-scoped)
Use an existing framework (e.g. MITRE Caldera) as the attack executor, orchestrated by this
project to vary technique/timing. Hard-gated to a scope file listing only this lab's VM IPs —
must be architecturally incapable of acting outside that list.

## Phase 5 — Purple orchestrator
Runs red + blue in the same loop, scores blue's detection rate against red's variations,
logs results using the Phase 1 audit schema (trace ID, reasoning, replayable).

## Phase 6 — On-demand + Telegram alerts
No daemon — triggered by CLI command or cron schedule, not always-on. Telegram bot posts:
run started, technique attempted, detected/missed, containment action taken, run summary.

## Phase 7 — Baseline drift detection (closes the "slow evasion" gap)
Addresses the honestly-documented limitation that per-call detection can't catch an
attacker who stays inside known tools/hours/payload ranges while slowly drifting an
agent's baseline over time (e.g. via gradual memory/config/prompt manipulation).

- detector/drift.py: periodically snapshots each agent's baseline (reuse
  detector/baseline.py's stats), and compares the current snapshot to a prior one
  (e.g. this week vs last week) using a distributional distance measure appropriate
  for the stats involved (e.g. comparing means/stdevs, or a simple KL-divergence-style
  comparison for the known_tools set changing composition over time).
- New signal: BASELINE_DRIFT — fires when an agent's baseline itself has shifted
  beyond a configurable threshold between two snapshots, independent of whether any
  single call was flagged. This is a meta-signal about the baseline, not about one call.
- Snapshots are stored in a new hash-chained log (logs/baseline_snapshots.jsonl,
  same tamper-evident pattern as everything else) so drift can be verified/replayed,
  not just computed once and discarded.
- Explicit non-goal: this does NOT detect file-level tampering of any actual
  agent config/memory files (that would require visibility into agent internals this
  proxy doesn't have) — it only detects drift as reflected in observable tool-call
  behavior over time. State this limitation openly, same as the others.
- Verification approach: synthetic test where an agent's calls slowly shift over many
  days (e.g. active hours creeping later, payload sizes creeping up) while staying
  within each individual call's normal-looking range — confirm BASELINE_DRIFT fires
  even though the Phase 2 per-call detector alone would stay silent throughout.

## Explicit non-goals / known limits (be honest about these, don't overclaim)
- Does NOT solve general business-logic vulnerability judgment — novel cross-system logic
  flaws remain a human-review problem, this project only handles known documented patterns
- Does NOT implement least-privilege/scope-enforcement access control (deferred — this is
  for personal use only, not a multi-agent production system)
- Not a replacement for commercial autonomous pentesting tools (XBOW, Pentera, etc.) —
  a smaller specialized portfolio project, not a competitor

## Environment
- Ubuntu 24.04 LTS VM (VMware Workstation), hostname mcp-proxy
- Python 3.12 venv at ~/mcp-security-proxy/venv
- Project structure: proxy/, detector/, config/, logs/
