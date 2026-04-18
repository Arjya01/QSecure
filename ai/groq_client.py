"""
Q-Secure | ai/groq_client.py
Phase 5 — Groq API Integration.

Primary model:  llama-3.3-70b-versatile  (deep analysis)
Fast model:     llama-3.1-8b-instant     (quick single-field generation)
Graceful degradation: if unavailable → returns None, rule-based activates.
"""

from __future__ import annotations
import os
import json
import time
import logging

log = logging.getLogger(__name__)

_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "backend", "ai_config.json")

def _load_key_from_config() -> str:
    """Load Groq key from ai_config.json (takes precedence over env var)."""
    try:
        with open(_CONFIG_PATH, "r") as f:
            data = json.load(f)
            return data.get("groq_api_key", "").strip()
    except Exception:
        return ""

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy import — groq is optional; degradation if not installed
# ---------------------------------------------------------------------------
try:
    from groq import Groq
    _GROQ_AVAILABLE = True
except ImportError:
    _GROQ_AVAILABLE = False
    log.warning("groq package not installed — AI layer will use rule-based fallback. Install: pip install groq")


class GroqClient:
    """
    Thin wrapper around the Groq API client.
    All methods return None on failure — callers must handle graceful degradation.
    """

    PRIMARY_MODEL = "llama-3.3-70b-versatile"
    FAST_MODEL    = "llama-3.1-8b-instant"

    def __init__(self):
        self._client = None
        if _GROQ_AVAILABLE:
            # Priority: ai_config.json > GROQ_API_KEY env var
            api_key = _load_key_from_config() or os.environ.get("GROQ_API_KEY", "")
            if api_key:
                try:
                    self._client = Groq(api_key=api_key)
                    log.info("Groq client initialized successfully.")
                except Exception as e:
                    log.warning(f"Groq client init failed: {e}")

    def reload(self, api_key: str) -> bool:
        """Hot-reload the Groq client with a new API key. Returns True on success."""
        if not _GROQ_AVAILABLE:
            return False
        if not api_key:
            self._client = None
            return True
        try:
            self._client = Groq(api_key=api_key)
            log.info("Groq client reloaded with new API key.")
            return True
        except Exception as e:
            log.warning(f"Groq client reload failed: {e}")
            self._client = None
            return False

    def is_available(self) -> bool:
        """True if GROQ_API_KEY is set and groq package is installed."""
        return self._client is not None

    def complete(
        self,
        system: str,
        user: str,
        max_tokens: int = 1000,
        fast_mode: bool = False,
    ) -> str | None:
        """
        Send a chat completion request.
        fast_mode=True → llama-3.1-8b-instant
        fast_mode=False → llama-3.3-70b-versatile
        Returns text on success, None on failure.
        Retries up to 3 times with exponential backoff on rate-limit errors.
        """
        if not self.is_available():
            return None

        model = self.FAST_MODEL if fast_mode else self.PRIMARY_MODEL
        max_retries = 3

        for attempt in range(max_retries):
            try:
                response = self._client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user",   "content": user},
                    ],
                    max_tokens=max_tokens,
                    temperature=0.3,    # Low temperature for consistent security analysis
                )
                return response.choices[0].message.content
            except Exception as e:
                err_str = str(e).lower()
                if "rate_limit" in err_str or "429" in err_str:
                    wait = 2 ** attempt
                    log.warning(f"Groq rate limit on attempt {attempt+1}/{max_retries}, waiting {wait}s")
                    time.sleep(wait)
                    continue
                log.warning(f"Groq completion failed (attempt {attempt+1}): {e}")
                return None

        log.warning("Groq completion failed after max retries")
        return None
