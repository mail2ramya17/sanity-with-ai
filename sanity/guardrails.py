"""Guardrails that keep the AI itself secure. AI is a new attack surface; secure it like one.

1. Human approves every action        -> enforced in actions.py (AI identity cannot execute)
2. Least privilege for AI agents      -> AI identity is read-only; each action has its own narrow scope
3. Defend against prompt injection    -> logs, tickets and code are UNTRUSTED input (detect + spotlight)
4. No secrets or PII in prompts       -> redact before anything reaches a model; approved models only
5. Log everything the AI does         -> every suggestion and decision goes to the audit log (store.py)
"""
from __future__ import annotations

import re

INJECTION_PATTERNS = {
    "override": re.compile(r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|all|earlier)\b.{0,20}\b(instructions?|rules?|prompts?)", re.I | re.S),
    "role_hijack": re.compile(r"\b(you are now|from now on you|act as|pretend to be)\b", re.I),
    "mode_switch": re.compile(r"\b(maintenance|developer|debug|god|admin)\s+mode\b", re.I),
    "verdict_steering": re.compile(r"\b(mark|classify|treat)\b.{0,30}\b(benign|false positive|safe|resolved)\b", re.I),
    "action_steering": re.compile(r"\b(close|resolve|suppress|delete|dismiss)\b.{0,20}\b(this|the|all)\b.{0,15}\b(incident|alert|ticket)s?\b", re.I),
    "exfiltration": re.compile(r"\b(send|post|upload|forward)\b.{0,40}(https?://|webhook)", re.I),
}

REDACTIONS = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("ACCESS_KEY", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("TOKEN", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")),
    ("PASSWORD", re.compile(r"(?i)\b(password|passwd|pwd|secret)\b(\s*(is|=|:)\s*)\S+")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("CARD", re.compile(r"\b(?:\d[ -]?){15,16}\b")),
]


def detect_injection(text: str) -> list[str]:
    return [name for name, rx in INJECTION_PATTERNS.items() if rx.search(text or "")]


def redact(text: str) -> tuple[str, list[str]]:
    found = []
    for label, rx in REDACTIONS:
        def sub(m: re.Match, label=label) -> str:
            found.append(label)
            if label == "PASSWORD":
                return f"{m.group(1)}{m.group(2)}[REDACTED_{label}]"
            return f"[REDACTED_{label}]"
        text = rx.sub(sub, text)
    return text, found


def spotlight(text: str) -> str:
    """Mark untrusted data so the model treats it as data, never as instructions."""
    cleaned = (text or "").replace("<<", "« ").replace(">>", " »")
    return f"<<UNTRUSTED_DATA>>{cleaned}<<END_UNTRUSTED_DATA>>"


def check_model(model: str, approved: list[str]) -> None:
    if not any(model == m or model.startswith(m + "-") for m in approved):
        raise PermissionError(f"model '{model}' is not on the approved model list")
