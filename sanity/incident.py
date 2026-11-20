"""Incident summaries. Before: write the timeline at 4 a.m. After: AI builds it from logs and chat; you review it."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from .guardrails import detect_injection, redact
from .models import Incident
from .store import Store


def _hhmm(ts: str) -> str:
    return ts[11:16]


def timeline(inc: Incident, chat: list[dict], store: Store) -> list[tuple[str, str, str]]:
    events: list[tuple[str, str, str]] = []
    by_rule: dict[str, list] = defaultdict(list)
    for a in inc.alerts:
        by_rule[(a.source, a.rule, a.title)].append(a.time)
    for (source, rule, title), times in by_rule.items():
        n = len(times)
        span = f" ({n}× until {_hhmm(max(times))})" if n > 1 else ""
        events.append((min(times), source.upper(), f"{title}{span}"))
    lo, hi = inc.first_seen, max(a.time for a in inc.alerts)
    for msg in chat:
        if lo[:13] <= msg["time"][:13] <= hi[:11] + "23":
            text, _ = redact(msg["text"])
            events.append((msg["time"], f"chat:{msg['user']}", text))
    return sorted(events)


def response_log(inc: Incident, store: Store) -> list[tuple[str, str, str]]:
    """Human and AI response steps from the audit log (real time, kept apart from the alert clock)."""
    out = []
    for rec in store.audit_records():
        d = rec["details"]
        if d.get("incident") != inc.id or rec["event"] not in ("decision", "action", "suggestion"):
            continue
        label = {"suggestion": f"AI suggested {', '.join(d.get('actions', []))}",
                 "decision": f"{d.get('verdict', '').upper()}: {d.get('reason', '')}",
                 "action": f"Executed {d.get('action')} ({d.get('scope')}), approved by {d.get('approved_by')}"}[rec["event"]]
        out.append((rec["ts"], rec["actor"], label))
    return out


def report(inc: Incident, chat: list[dict], store: Store) -> str:
    s, c = inc.summary, inc.context
    lines = [f"# {inc.id}: {s.get('what_happened', inc.category)}", "",
             f"**Severity** {inc.severity} · **Score** {inc.score} · **Owner** {c.get('owner')} · "
             f"**Sources** {', '.join(c.get('sources', []))} · **Alerts** {c.get('alert_count')}", "",
             f"**Why it matters:** {s.get('why_it_matters', '')}", ""]
    if c.get("blast_radius", {}).get("reachable"):
        lines.append(f"**Blast radius:** {', '.join(c['blast_radius']['reachable'])}")
        lines.append("")
    if inc.flags:
        lines += ["> ⚠️ " + "; ".join(inc.flags), ""]
    lines += ["## Timeline (UTC)", "", "| Time | Source | Event |", "|---|---|---|"]
    for ts, src, text in timeline(inc, chat, store):
        lines.append(f"| {_hhmm(ts)} | {src} | {text.replace('|', '/')} |")
    resp = response_log(inc, store)
    if resp:
        lines += ["", "## Response log (from the audit trail)", "", "| Time (UTC) | Actor | Step |", "|---|---|---|"]
        lines += [f"| {ts[:16].replace('T', ' ')} | {actor} | {text.replace('|', '/')} |" for ts, actor, text in resp]
    lines += ["", "## Recommended actions (need human approval)", ""]
    lines += [f"- [ ] `{a}`" for a in inc.proposed_actions]
    if any(detect_injection(m["text"]) for m in chat):
        lines += ["", "> Chat contained instruction-like text; it was treated as data."]
    lines += ["", "_Drafted by AI from logs, alerts and chat. Secrets and PII redacted. Review before sharing._"]
    return "\n".join(lines) + "\n"


def load_chat(path: Path) -> list[dict]:
    p = Path(path)
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()] if p.exists() else []
