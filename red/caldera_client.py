"""
caldera_client.py
-------------
Phase 4 (live executor): minimal MITRE Caldera REST API client - just enough
to launch an operation and check its state. No plugin management, no agent
deployment, no ability CRUD - those are done through Caldera's own UI/CLI;
this only needs to start and observe operations that CalderaExecutor
(red/executor.py) hands it.

Credentials/endpoint come from environment variables - CALDERA_API_KEY
(required) and CALDERA_URL (optional, defaults to the local server) -
loaded from a local .env file via python-dotenv if one exists, matching
trigger/telegram.py's convention. .env is gitignored; the key must never
land in a committed config file.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from dotenv import load_dotenv

load_dotenv()

DEFAULT_BASE_URL = "http://localhost:8888"
_TIMEOUT_SECONDS = 15


class CalderaError(Exception):
    """Raised when the Caldera API can't be reached or returns an error."""


class CalderaClient:
    def __init__(self, base_url: str | None = None, api_key: str | None = None):
        self.base_url = (base_url or os.environ.get("CALDERA_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.api_key = api_key or os.environ.get("CALDERA_API_KEY")
        if not self.api_key:
            raise CalderaError(
                "CALDERA_API_KEY is not set - add it to .env before using the live Caldera executor"
            )

    def _request(self, method: str, path: str, body: dict | None = None):
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("KEY", self.api_key)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            raise CalderaError(f"{method} {path} -> HTTP {e.code}: {detail}") from e
        except urllib.error.URLError as e:
            raise CalderaError(f"{method} {path} -> unreachable ({e.reason})") from e

    def create_operation(
        self,
        *,
        name: str,
        adversary_id: str,
        planner_id: str,
        source_id: str,
        group: str,
        autonomous: int = 1,
        obfuscator: str = "plain-text",
        auto_close: bool = True,
        visibility: int = 51,
    ) -> dict:
        body = {
            "name": name,
            "adversary": {"adversary_id": adversary_id},
            "planner": {"id": planner_id},
            "source": {"id": source_id},
            "group": group,
            "state": "running",
            "autonomous": autonomous,
            "obfuscator": obfuscator,
            "auto_close": auto_close,
            "visibility": visibility,
        }
        return self._request("POST", "/api/v2/operations", body)

    def get_operation(self, operation_id: str) -> dict:
        return self._request("GET", f"/api/v2/operations/{operation_id}")
