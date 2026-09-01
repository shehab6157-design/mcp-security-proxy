# MCP Security Proxy

A personal, on-demand red/blue/purple-team lab project. It logs every tool call an
AI agent makes through an MCP proxy, baselines each agent's normal behavior, flags
anomalies, runs a lab-scoped red-team simulation against that baseline, scores
blue's detection rate, and narrates the whole run to Telegram.

Not a daemon. Nothing here runs 24/7 — it's triggered by a CLI command or a cron
job, does one run, and exits. Targets are restricted to self-owned lab VMs only,
never external systems.

## Why

Most anomaly detection assumes the actor being profiled is a human on a network —
peers, off-hours logins, transfer volume. This project applies the same behavioral
baselining technique to a different actor: an AI agent's MCP tool calls. An agent
that suddenly calls a tool it's never touched, at an hour it's never active, with a
payload far outside its normal size, or with a burst of distinct tools in one
window looks a lot like lateral movement looks on a network — so the same detection
approach generalizes to it.

It's built on top of a prior project, `lateral-movement-detector`, which validated
this baselining approach on real captured network traffic (per-device peer/hours/
volume/fan-out baselines, 4 signal types, 5/5 detection on a simulated SSH-flood
attack with 0 false positives). This project ports that same detector logic
(`baseline.py` / `detector.py`) onto a new data source — an MCP call log instead of
a traffic capture — rather than starting the detection approach from scratch.

## Architecture

```
AI agent (MCP client)
       │
       ▼
┌─────────────────┐     forwards every call     ┌────────────────────┐
│   proxy/server   │ ──────────────────────────▶ │ real downstream MCP │
│  (stdio MCP      │ ◀────────────────────────── │      server         │
│   proxy)         │        returns result        └────────────────────┘
└─────────────────┘
       │ writes one hash-chained entry per call
       ▼
logs/calls.jsonl  (proxy/audit_log.py — append-only, tamper-evident)
       │
       ▼
┌───────────────────┐   per-agent stats    ┌──────────────────┐
│ detector/baseline  │ ───────────────────▶ │ detector/baseline │
│  (learns normal)   │                      │     .json         │
└───────────────────┘                      └──────────────────┘
       │                                            │
       ▼                                            ▼
┌───────────────────────────────────────────────────────────┐
│ detector/detector — compares new calls to the baseline,    │
│ raises NEW_TOOL / OFF_PATTERN / PAYLOAD_OUTLIER /           │
│ SEQUENCE_SPIKE / UNKNOWN_AGENT, tiers by signal count        │
└───────────────────────────────────────────────────────────┘
       │
       ▼
┌───────────────────────────────────────────────────────────┐
│ detector/suppression — checks config/known_jobs.yaml;       │
│ strips signals a documented recurring job explains           │
│ (never silently — suppressed signals stay visible in output) │
└───────────────────────────────────────────────────────────┘
       │
       ▼  tier: alert / observation / suppressed

┌───────────────────┐        ┌───────────────────┐
│ red/orchestrator   │  scope │ config/lab_scope   │
│ picks technique +  │◀──────▶│  .yaml (hard        │
│ target, runs it via│        │  allowlist, fail-   │
│ red/executor        │        │  closed, exact-     │
│ (MockExecutor —     │        │  match only)         │
│ no live Caldera yet)│        └───────────────────┘
└───────────────────┘
       │ injects the result as an MCP call under an
       │ EXISTING baselined agent identity
       ▼
purple/orchestrator — runs red, injects into logs/calls.jsonl,
runs detector.detect() once over the updated log, reads back
each round's outcome by trace_id, scores alert/observation/
suppressed/missed, logs to logs/purple_runs.jsonl
       │
       ▼
trigger/run.py — the on-demand entrypoint (CLI or cron). Drives
the same red+blue round-trip and narrates each stage via
trigger/telegram.py: run started → technique attempted →
detected/observation/suppressed/missed → containment
recommendation (alert tier only, trigger/containment.py) →
run summary
       │
       ▼
   Telegram chat
```

Every log (`logs/calls.jsonl`, `logs/red_runs.jsonl`, `logs/purple_runs.jsonl`) is
append-only and hash-chained: each entry embeds the SHA-256 hash of the previous
entry, so editing or deleting a prior line breaks the chain for everything after
it. `proxy/audit_log.py` and `red/run_log.py` / `purple/scoreboard.py` are
independent implementations of the same pattern rather than shared code, on
purpose — different domain fields, low duplication cost, avoids coupling logs that
evolve separately.

## Components

| Package    | Role |
|------------|------|
| `proxy/`   | Stdio MCP proxy. Sits between the agent and a real downstream MCP server, forwards every call, writes a hash-chained audit entry (`trace_id`, UTC timestamp, `agent_id`, `tool_name`, `target_resource`, `payload_size`, `reasoning_summary`) for each one. |
| `detector/`| Learns a per-agent baseline (known tools, active hours, avg/std payload size, avg/std fan-out per time window) from the call log, then flags calls that deviate. Single signal → `observation` (logged only); 2+ correlated signals → `alert`. |
| `detector/suppression.py` | Checks anomalies against `config/known_jobs.yaml` — documented recurring legitimate patterns (agent + tool + hour window + payload range). Matched signals become `suppressed`, not silently dropped — the output still shows what was suppressed and by which job. |
| `red/`     | Lab-scoped red-team simulation. `scope.py` is a fail-closed allowlist loader (missing/empty/wildcard scope = no targets, ever); `executor.py`'s base class re-checks scope itself before any technique runs, so even a bug in the orchestrator can't get a live action dispatched out-of-scope; `MockExecutor` just reports what it would have done. |
| `purple/`  | Runs a red-team round, injects the result into the *same* `logs/calls.jsonl` under an already-baselined agent identity (modeling "attacker compromised a trusted identity," not "attacker is a new identity"), runs the detector over the updated log, and scores the round as alert/observation/suppressed/missed. |
| `trigger/` | The on-demand entrypoint (`trigger/run.py`) meant for a manual command or a cron job. Drives one purple round-trip and narrates each stage to Telegram (`trigger/telegram.py`, falls back to stdout if no bot token/chat ID is configured). `trigger/containment.py` produces a plain-text *recommendation* for alert-tier detections only — never a real action. |

## Running it

Requires Python 3.12 and the packages in `requirements.txt` (a venv is expected —
see `PROJECT_SPEC.md`'s environment notes).

```bash
pip install -r requirements.txt
```

**1. Generate some call traffic** through the proxy (dev smoke test against the
bundled mock downstream server):

```bash
python3 -m proxy.test_client
```

This drives `proxy/server.py` (configured via `config/proxy_config.yaml`), which
appends entries to `logs/calls.jsonl`. Run it a number of times (or point a real
MCP agent at the proxy) to build up enough history for a baseline.

**2. Build the baseline:**

```bash
python3 -m detector.baseline logs/calls.jsonl
```

Writes `detector/baseline.json`.

**3. Run the detector standalone:**

```bash
python3 -m detector.detector logs/calls.jsonl
```

Prints alerts / observations / suppressed calls against `config/known_jobs.yaml`.

**4. Run a red-team simulation on its own** (mock executor, targets restricted to
`config/lab_scope.yaml`):

```bash
python3 -m red.orchestrator --runs 3
```

**5. Run red + blue together and score detection:**

```bash
python3 -m purple.orchestrator --rounds 5 --impersonate-agent dev-test-agent
```

Requires a baseline that already contains `--impersonate-agent`'s identity (step 2
must have run against call history for that agent first).

**6. Run the full on-demand pipeline with Telegram notifications:**

```bash
cp .env.example .env   # fill in TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID, or leave blank
python3 -m trigger.run --rounds 5 --impersonate-agent dev-test-agent
```

Without Telegram credentials set, notifications print to stdout instead — the
pipeline runs the same either way. For scheduled runs, add a cron entry, e.g.:

```
0 3 * * * cd /path/to/mcp-security-proxy && venv/bin/python3 -m trigger.run
```

## Known limitations

Being upfront about where this project currently overstates or hasn't yet proven
itself:

- **Mock executor only — no live Caldera integration yet.** `red/executor.py`
  defines a scope-gated `Executor` interface specifically so a real MITRE Caldera
  (or similar) executor can be dropped in behind it later, but the only executor
  that exists today is `MockExecutor`, which never touches the network — it just
  reports what it *would* have run. The scope-enforcement design (fail-closed
  allowlist, exact-match only, re-checked independently by the executor) is built
  and tested, but it has only ever gated a simulated action, not a real one.

- **`target_resource` and `reasoning_summary` are best-effort heuristics, not
  ground truth.** MCP tool-call arguments are arbitrary JSON with no first-class
  "what resource is this touching" or "why" field. `proxy/extract.py` scans a
  fixed list of common argument key names (`path`, `url`, `host`, `command`, etc.)
  for `target_resource`, falling back to the first argument key/value if none
  match. `reasoning_summary` only reflects real agent intent if the calling agent
  populates the non-standard `_meta.reasoning` field this proxy defines; otherwise
  it's a generated stub listing the argument keys. Both are documented in the code
  as best-effort — the detector doesn't (and shouldn't) trust either one blindly.

- **Business-logic judgment isn't solved.** `config/known_jobs.yaml` suppression
  only handles patterns a human has explicitly documented in advance (specific
  agent + tool + hour window + payload range). It does not, and isn't intended to,
  make any general judgment about whether a novel action is legitimate — an
  unmatched anomaly is always left for human review, never auto-cleared.

- **Detection has only been exercised against deliberately obvious anomalies.**
  Verification so far (per project history) has been things like a brand-new tool
  name, an off-hours call, or a payload far outside normal range — synthetic and
  clearly outside the baseline. It has not been tested against a subtler or
  evasive adversary deliberately trying to blend into an agent's normal
  tool-call pattern (e.g. staying inside known tools/hours/payload ranges while
  still doing something malicious, or slowly drifting a baseline over many
  legitimate-looking calls before acting). The z-score/count-based signals here
  are not adversarially hardened.

- **Phase 7's `tools_jsd` drift threshold (0.15) is an unvalidated placeholder.**
  `detector/drift.py`'s other three BASELINE_DRIFT thresholds have some basis: the
  payload/fanout z-score thresholds (2.0) are consistent with `detector.py`'s
  existing calibration, and `hours_jsd` (0.4) was empirically derived by measuring
  the real noise floor two stable training weeks produce (~0.286) and setting the
  threshold with margin above it. `tools_jsd` got none of that — the synthetic
  verification test (`detector/test_drift_synthetic.py`) only varies one agent's
  active hours and payload size over time, calling a single tool throughout, so
  it never exercises a shifting tool-usage mix at all. 0.15 is a guess at "a real
  composition shift should clear this, ordinary noise shouldn't," not a measured
  value. It needs its own calibration test — one that actually varies an agent's
  tool-usage mix over time — before it should be trusted.

- Other explicit non-goals carried over from `PROJECT_SPEC.md`: no
  least-privilege/access-control enforcement (`trigger/containment.py` only ever
  produces a human-facing recommendation, never a real action), and this isn't
  positioned as a competitor to commercial autonomous pentesting tools (XBOW,
  Pentera, etc.) — it's a smaller, specialized portfolio project.

## Safety

`red/scope.py` is the single source of truth for what the red-team engine is
allowed to target (`config/lab_scope.yaml`). It fails closed — a missing, empty,
or wildcard/CIDR scope file yields *no* in-scope targets, never "allow everything"
— and matching is exact-string only. `red/executor.py`'s base class reloads and
re-checks this file itself before any technique runs, independent of whatever the
orchestrator computed, so a planning bug upstream can't get a live action
dispatched to something not on the list. This is process-level, convention-based
scoping, not network-level enforcement — it stops this codebase from acting
out-of-scope, but it is not a substitute for real firewall/segmentation around the
lab VM(s) it targets.
