"""Best-effort extraction of log fields from an MCP tool call.

MCP tool-call arguments are arbitrary, tool-defined JSON, and the protocol carries
no first-class "what resource is this touching" or "why did the agent call this"
field. We extract both on a best-effort basis:

- target_resource: scan common argument keys used by real-world tools.
- reasoning_summary: read it from the call's `_meta.reasoning` field if the
  calling agent supplies one (a convention this proxy defines, not part of the
  MCP spec), otherwise fall back to a generated summary of the arguments.

Neither is a source of truth the detector should trust blindly - both are
labeled best-effort in the schema on purpose.
"""

from __future__ import annotations

import json
from typing import Any

_RESOURCE_KEYS = (
    "path",
    "file",
    "filepath",
    "file_path",
    "filename",
    "url",
    "uri",
    "target",
    "resource",
    "host",
    "hostname",
    "endpoint",
    "query",
    "command",
    "cmd",
)

_MAX_FIELD_LEN = 200


def _truncate(s: str, limit: int = _MAX_FIELD_LEN) -> str:
    s = s.strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def extract_target_resource(tool_name: str, arguments: dict[str, Any] | None) -> str:
    if not arguments:
        return tool_name

    for key in _RESOURCE_KEYS:
        if key in arguments and arguments[key] is not None:
            return _truncate(str(arguments[key]))

    first_key = next(iter(arguments))
    return _truncate(f"{first_key}={arguments[first_key]!r}")


def extract_reasoning_summary(
    tool_name: str, arguments: dict[str, Any] | None, meta: dict[str, Any] | None
) -> str:
    if meta:
        reasoning = meta.get("reasoning")
        if isinstance(reasoning, str) and reasoning.strip():
            return _truncate(reasoning)

    if not arguments:
        return f"{tool_name} called with no arguments (no reasoning supplied)"

    arg_keys = ", ".join(list(arguments.keys())[:5])
    return _truncate(
        f"{tool_name} called with args [{arg_keys}] (no reasoning supplied)"
    )


def payload_size(arguments: dict[str, Any] | None) -> int:
    if not arguments:
        return 0
    return len(json.dumps(arguments, separators=(",", ":")).encode("utf-8"))
