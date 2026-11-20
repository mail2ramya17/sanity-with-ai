"""Signals -> AI triage -> AI enrich -> Human decision -> Act -> Learn."""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from .assistant import Assistant, TemplateAssistant, allowed_actions, analyse
from .decisions import load_learned
from .enrich import enrich
from .store import Store
from .triage import load_alerts, load_yaml, triage

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "config"


def key_of(inc) -> str:
    return f"{inc.category}:{inc.entities[0]}"


def run(alerts_path: Path, state: Store, assistant: Assistant | None = None, config: Path = CONFIG,
        today: dt.date | None = None) -> dict:
    inventory = load_yaml(config / "inventory.yaml")
    tuning = load_yaml(config / "tuning.yaml")
    catalog = load_yaml(config / "actions.yaml")
    alerts = load_alerts(alerts_path)
    result = triage(alerts, inventory, tuning, load_learned(state), today)
    assistant = assistant or TemplateAssistant()
    queue = []
    for inc in result["review"]:
        enrich(inc, inventory)
        analyse(inc, assistant, catalog, state)
        queue.append({
            "id": inc.id, "key": key_of(inc), "category": inc.category, "entity": inc.entities[0],
            "severity": inc.severity, "score": inc.score, "summary": inc.summary, "context": inc.context,
            "flags": inc.flags, "proposed_actions": inc.proposed_actions,
            "allowed_actions": allowed_actions(inc.category, catalog),
            "fingerprints": [g.fingerprint for g in inc.groups], "alert_count": len(inc.alerts),
        })
    state.save("queue.json", queue)
    metrics = {"alerts": result["alerts"], "groups": result["groups"], "suppressed_alerts": result["suppressed_alerts"],
               "incidents": len(result["incidents"]), "for_review": len(queue),
               "alerts_behind_review": sum(q["alert_count"] for q in queue)}
    history = state.load("metrics.json", [])
    history.append({"run": len(history) + 1, **metrics})
    state.save("metrics.json", history)
    state.audit("system", "triage_run", **metrics)
    return {"metrics": metrics, "queue": queue, "incidents": result["incidents"]}
