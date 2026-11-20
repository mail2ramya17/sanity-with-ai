"""AI triage: dedupe, filter noise, correlate, score. You review the top N, not every alert."""
from __future__ import annotations

import datetime as dt
import json
from collections import defaultdict
from pathlib import Path

import yaml

from .models import SEVERITY, Alert, AlertGroup, Incident


def load_alerts(path: Path) -> list[Alert]:
    return [Alert(**json.loads(line)) for line in Path(path).read_text().splitlines() if line.strip()]


def _matches(alert: Alert, match: dict) -> bool:
    for key in ("rule", "entity", "source", "category"):
        if key in match and getattr(alert, key) != match[key]:
            return False
    return all(alert.attributes.get(k) == v for k, v in (match.get("attribute") or {}).items())


def active_suppressions(rules: list[dict], today: dt.date) -> list[dict]:
    return [r for r in rules if dt.date.fromisoformat(str(r["expires"])) >= today]


def group(alerts: list[Alert]) -> list[AlertGroup]:
    buckets: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        buckets[a.fingerprint].append(a)
    groups = []
    for fp, items in buckets.items():
        top = max(items, key=lambda a: SEVERITY[a.severity])
        groups.append(AlertGroup(fp, top.rule, top.entity, top.category, top.severity,
                                 sorted(items, key=lambda a: a.time), {a.source for a in items}))
    return groups


def apply_suppressions(groups: list[AlertGroup], rules: list[dict]) -> None:
    for g in groups:
        for r in rules:
            if all(_matches(a, r["match"]) for a in g.alerts):
                g.suppressed_by = r["id"]
                break


def correlate(groups: list[AlertGroup]) -> list[Incident]:
    """Merge alert groups on the same entity into one incident (SIEM + EDR + ticket = one story)."""
    by_entity: dict[str, list[AlertGroup]] = defaultdict(list)
    for g in groups:
        if not g.suppressed_by:
            by_entity[g.entity].append(g)
    incidents = []
    for entity, gs in by_entity.items():
        main = max(gs, key=lambda g: SEVERITY[g.severity])
        incidents.append(Incident(id="", entities=[entity], category=main.category, groups=gs))
    return incidents


def weight_for(entity: str, inventory: dict) -> float:
    weights = inventory["criticality_weight"]
    if entity in inventory["assets"]:
        return weights[inventory["assets"][entity]["criticality"]]
    ident = inventory["identities"].get(entity)
    if ident:
        if "Global Administrator" in ident.get("roles", []):
            return weights["crown_jewel"]
        return weights["high"] if ident.get("privileged") else weights["medium"]
    return weights["medium"]


def score(inc: Incident, inventory: dict, correlation_bonus: float) -> float:
    w = weight_for(inc.entities[0], inventory)
    best = max(SEVERITY[g.severity] * max(a.confidence for a in g.alerts) for g in inc.groups)
    return round(best * w * (1 + correlation_bonus * (len(inc.sources) - 1)), 2)


def triage(alerts: list[Alert], inventory: dict, tuning: dict, learned: list[dict] | None = None,
           today: dt.date | None = None) -> dict:
    today = today or dt.date.today()
    rules = active_suppressions(tuning["suppressions"] + (learned or []), today)
    groups = group(alerts)
    apply_suppressions(groups, rules)
    incidents = correlate(groups)
    for inc in incidents:
        inc.score = score(inc, inventory, tuning["triage"]["correlation_bonus"])
    incidents.sort(key=lambda i: (-i.score, i.first_seen))
    for n, inc in enumerate(incidents, 1):
        inc.id = f"INC-{n:03d}"
    suppressed = [g for g in groups if g.suppressed_by]
    return {
        "alerts": len(alerts),
        "groups": len(groups),
        "suppressed_groups": len(suppressed),
        "suppressed_alerts": sum(len(g.alerts) for g in suppressed),
        "incidents": incidents,
        "review": incidents[: tuning["triage"]["review_top_n"]],
    }


def load_yaml(path: Path) -> dict:
    return yaml.safe_load(Path(path).read_text())
