"""
telegram.py
-------------
Phase 6: minimal Telegram Bot API client for run notifications - no daemon,
no polling, just fire-and-forget sendMessage calls the on-demand trigger
makes at a few points during a run (PROJECT_SPEC.md Phase 6: "Telegram bot
posts: run started, technique attempted, detected/missed, containment
action taken, run summary").

Credentials come from environment variables only - TELEGRAM_BOT_TOKEN and
TELEGRAM_CHAT_ID, loaded from a local .env file via python-dotenv if one
exists. .env is gitignored; the token must never land in a committed
config file. If either is unset, TelegramNotifier.notify() prints to
stdout instead of raising or silently doing nothing - so a run is fully
inspectable even before Telegram is configured.
"""

from __future__ import annotations

import os
import urllib.parse
import urllib.request

from dotenv import load_dotenv

load_dotenv()

API_BASE = "https://api.telegram.org"
_TIMEOUT_SECONDS = 10


class TelegramNotifier:
    def __init__(self, bot_token: str | None = None, chat_id: str | None = None):
        self.bot_token = bot_token or os.environ.get("TELEGRAM_BOT_TOKEN")
        self.chat_id = chat_id or os.environ.get("TELEGRAM_CHAT_ID")
        self.enabled = bool(self.bot_token and self.chat_id)

    def notify(self, text: str) -> None:
        if not self.enabled:
            print(f"[telegram disabled - would send] {text}")
            return

        url = f"{API_BASE}/bot{self.bot_token}/sendMessage"
        data = urllib.parse.urlencode({"chat_id": self.chat_id, "text": text}).encode("utf-8")
        try:
            with urllib.request.urlopen(url, data=data, timeout=_TIMEOUT_SECONDS) as resp:
                if resp.status != 200:
                    print(f"[telegram] non-200 response ({resp.status}) sending: {text}")
        except OSError as e:
            # A network hiccup or bad token shouldn't crash an on-demand
            # security run - print locally so the message isn't lost, and
            # keep going.
            print(f"[telegram] failed to send ({e}): {text}")
