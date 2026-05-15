"""
Secure server-side client for xAI / Grok-compatible Chat Completions API.
API key is read from environment only — never exposed to the browser.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Generator, List, Optional

import requests

logger = logging.getLogger(__name__)

DEFAULT_BASE = "https://api.x.ai/v1"
DEFAULT_MODEL = "grok-2-latest"
DEFAULT_TIMEOUT = 55


class GrokAPIError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None, body: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


def _api_key() -> Optional[str]:
    return (os.environ.get("GROK_API_KEY") or os.environ.get("XAI_API_KEY") or "").strip() or None


def _base_url() -> str:
    return (os.environ.get("GROK_API_BASE") or DEFAULT_BASE).rstrip("/")


def _model() -> str:
    return (os.environ.get("GROK_MODEL") or DEFAULT_MODEL).strip()


def is_configured() -> bool:
    return bool(_api_key())


def chat_completion(
    messages: List[Dict[str, str]],
    *,
    temperature: float = 0.45,
    max_tokens: int = 1200,
    stream: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """
    Non-streaming chat completion. Returns assistant plain-text content.
    """
    key = _api_key()
    if not key:
        raise GrokAPIError("Grok API key not configured")

    url = f"{_base_url()}/chat/completions"
    payload: Dict[str, Any] = {
        "model": _model(),
        "messages": messages,
        "temperature": float(temperature),
        "max_tokens": int(max_tokens),
        "stream": bool(stream),
    }
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=timeout)
    except requests.Timeout as e:
        raise GrokAPIError("Grok request timed out") from e
    except requests.RequestException as e:
        raise GrokAPIError(f"Grok network error: {e}") from e

    if r.status_code == 429:
        raise GrokAPIError("Grok rate limit exceeded", status_code=429, body=r.text)
    if r.status_code >= 400:
        logger.warning("Grok HTTP %s: %s", r.status_code, r.text[:500])
        raise GrokAPIError("Grok API error", status_code=r.status_code, body=r.text)

    try:
        data = r.json()
    except json.JSONDecodeError as e:
        raise GrokAPIError("Invalid JSON from Grok API") from e

    try:
        return (data["choices"][0]["message"]["content"] or "").strip()
    except (KeyError, IndexError, TypeError) as e:
        logger.error("Unexpected Grok payload: %s", str(data)[:800])
        raise GrokAPIError("Unexpected Grok response shape") from e


def chat_completion_stream(
    messages: List[Dict[str, str]],
    *,
    temperature: float = 0.45,
    max_tokens: int = 1200,
    timeout: int = DEFAULT_TIMEOUT,
) -> Generator[str, None, None]:
    """
    Streaming tokens (SSE). Yields decoded text deltas as they arrive.
    Caller should aggregate. If streaming is unsupported, raises.
    """
    key = _api_key()
    if not key:
        raise GrokAPIError("Grok API key not configured")

    url = f"{_base_url()}/chat/completions"
    payload: Dict[str, Any] = {
        "model": _model(),
        "messages": messages,
        "temperature": float(temperature),
        "max_tokens": int(max_tokens),
        "stream": True,
    }
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }

    try:
        with requests.post(url, headers=headers, json=payload, stream=True, timeout=timeout) as r:
            if r.status_code >= 400:
                raise GrokAPIError("Grok API error", status_code=r.status_code, body=r.text[:500])
            for line in r.iter_lines(decode_unicode=True):
                if not line:
                    continue
                if line.startswith("data: "):
                    chunk = line[6:].strip()
                    if chunk == "[DONE]":
                        break
                    try:
                        obj = json.loads(chunk)
                    except json.JSONDecodeError:
                        continue
                    try:
                        delta = obj["choices"][0]["delta"].get("content") or ""
                    except (KeyError, IndexError, TypeError):
                        delta = ""
                    if delta:
                        yield delta
    except requests.Timeout as e:
        raise GrokAPIError("Grok stream timed out") from e
    except requests.RequestException as e:
        raise GrokAPIError(f"Grok stream network error: {e}") from e
