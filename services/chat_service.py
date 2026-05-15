"""
TrustLens chat orchestration: Grok (xAI) when configured, else rules-based KB.
Includes lightweight URL / scam heuristics for trust hints (not a replacement for scanners).
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import ai_engine
from services import grok_client

logger = logging.getLogger(__name__)

_URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.I)

_SYSTEM_PROMPT = """You are TrustLens AI — a cybersecurity and fraud-awareness assistant for Indian users.
Tone: clear, calm, professional, slightly futuristic. Use Markdown when helpful (headings, bullets, bold).
Rules:
- Never ask for OTPs, passwords, CVV, or private keys. Never tell users to disable security.
- If the user pastes a URL or suspicious message, explain risks generically and recommend using TrustLens scanners (Website Scanner, Scam Message, Fake Job, QR Scanner, RBI/SEBI Verifier) instead of declaring legal guilt.
- Prefer actionable steps: verify domain, check RBI/SEBI registers, call official bank numbers, use cybercrime.gov.in / 1930 for fraud.
- Keep answers concise unless the user asks for depth. If uncertain, say what is unknown and what to verify next.
"""


def sanitize_user_message(raw: str, max_len: int = 4000) -> str:
    """Strip control chars and bound length; escape is for DB display elsewhere."""
    s = (raw or "").replace("\x00", "").strip()
    if len(s) > max_len:
        s = s[:max_len]
    return s


def extract_urls(text: str) -> List[str]:
    return list(dict.fromkeys(m.group(0) for m in _URL_RE.finditer(text or "")))


def heuristic_trust_assessment(message: str) -> Tuple[int, List[str]]:
    """
    Returns (trust_score 0-100, flags). Higher = safer *message to discuss with assistant*,
    not a guarantee the linked site is safe.
    """
    flags: List[str] = []
    m = (message or "").lower()
    score = 78

    if extract_urls(message):
        flags.append("contains_url")
        score -= 12
    if any(x in m for x in ("otp", "cvv", "password", "upi pin", "remote desktop", "anydesk", "teamviewer")):
        flags.append("credential_or_remote_access")
        score -= 18
    if any(x in m for x in ("click here", "limited time", "act now", "verify your account", "suspended", "kyc update")):
        flags.append("urgency_or_account_pressure")
        score -= 10
    if any(x in m for x in ("investment", "double your money", "guaranteed returns", "crypto mining")):
        flags.append("high_risk_financial_pitch")
        score -= 8

    score = max(5, min(95, score))
    return score, flags


def _history_to_messages(history: Optional[List[Dict[str, Any]]], limit_pairs: int = 8) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if not history:
        return out
    for h in history[-limit_pairs:]:
        if not isinstance(h, dict):
            continue
        u = (h.get("user") or "").strip()
        b = (h.get("bot") or "").strip()
        if u:
            out.append({"role": "user", "content": u[:4000]})
        if b:
            out.append({"role": "assistant", "content": b[:8000]})
    return out


def build_messages(user_message: str, history: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, str]]:
    trust, flags = heuristic_trust_assessment(user_message)
    urls = extract_urls(user_message)
    hint_lines = [
        f"Heuristic session risk score (assistant-side, not legal verdict): **{trust}/100**.",
    ]
    if flags:
        hint_lines.append("Flags: " + ", ".join(flags) + ".")
    if urls:
        hint_lines.append("Detected URLs — advise verification with Website Scanner before visiting or entering credentials.")
    hint = "\n".join(hint_lines)

    messages: List[Dict[str, str]] = [{"role": "system", "content": _SYSTEM_PROMPT + "\n\n" + hint}]
    messages.extend(_history_to_messages(history))
    messages.append({"role": "user", "content": user_message})
    return messages


def generate_reply(
    user_message: str,
    history: Optional[List[Dict[str, Any]]] = None,
    *,
    use_grok: bool = True,
) -> Tuple[str, Dict[str, Any]]:
    """
    Returns (assistant_text, meta dict with trust_score, flags, source).
    """
    trust, flags = heuristic_trust_assessment(user_message)
    meta: Dict[str, Any] = {"trust_score": trust, "flags": flags, "source": "fallback"}

    if use_grok and grok_client.is_configured():
        try:
            msgs = build_messages(user_message, history)
            text = grok_client.chat_completion(msgs, temperature=0.4, max_tokens=1400)
            if text:
                meta["source"] = "grok"
                return text, meta
        except grok_client.GrokAPIError as e:
            logger.warning("Grok chat failed (%s): %s", e.status_code, e)
        except Exception as e:
            logger.exception("Unexpected Grok error: %s", e)

    # Rules-based fallback (existing engine)
    fb = ai_engine.get_chatbot_response(user_message, history=history)
    meta["source"] = "rules"
    return fb, meta
