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
