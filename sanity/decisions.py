"""Human decision -> Act -> Learn.

* Only a named human can approve, reject or escalate. AI identities are refused.
* Only approved actions run, each with its own narrowly scoped credential. Executors are dry-run by default.
* A "false positive" rejection becomes a learned suppression with an owner and a 30-day expiry,
  so the next run is quieter, and the tuning still expires and gets re-reviewed.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

import yaml

from .store import Store

VERDICTS = {"approve", "reject", "escalate"}


class ApprovalRequired(PermissionError):
    pass


def _is_human(actor: str | None) -> bool:
    return bool(actor) and not actor.lower().startswith(("ai:", "bot:", "svc-", "system"))


def decide(store: Store, incident_key: str, verdict: str, by: str, actions: list[str] | None = None,
           reason: str = "", today: dt.date | None = None) -> dict:
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {sorted(VERDICTS)}")
    if not _is_human(by):
        store.audit(by or "unknown", "decision_refused", incident=incident_key, why="decisions require a named human")
        raise ApprovalRequired("only a named human can decide; AI suggests, it never decides")
    queue = {q["key"]: q for q in store.load("queue.json", [])}
    item = queue.get(incident_key)
    if not item:
        raise KeyError(f"{incident_key} is not in the review queue")
    chosen = actions if actions is not None else item["proposed_actions"]
    if verdict == "approve":
        unknown = [a for a in chosen if a not in item["allowed_actions"]]
        if unknown:
            raise ValueError(f"actions {unknown} are not allowed for a {item['category']} incident")
    decision = {"key": incident_key, "incident": item["id"], "verdict": verdict, "by": by, "reason": reason,
                "actions": chosen if verdict == "approve" else [], "executed": False,
                "at": (today or dt.date.today()).isoformat()}
    decisions = store.load("decisions.json", [])
    decisions.append(decision)
    store.save("decisions.json", decisions)
    store.audit(f"human:{by}", "decision", **decision)
    if verdict == "reject" and reason.lower().startswith("false positive"):
        learn_from_false_positive(store, item, by, reason, today)
    return decision


# ---------------- Act (least privilege) ----------------

@dataclass(frozen=True)
class ScopedCredential:
    principal: str
    scopes: frozenset[str]


class DryRunExecutor:
    """Prints the exact API call an action would make. Swap for real executors per platform."""

    def run(self, action: str, target: str, cred: ScopedCredential, scope: str) -> str:
        if scope not in cred.scopes:
            raise PermissionError(f"{cred.principal} lacks scope {scope}")
        return f"[dry-run] {cred.principal} -> {scope} on {target}"


def act(store: Store, catalog: dict, executor=None, actor: str = "sanity-executor") -> list[dict]:
    executor = executor or DryRunExecutor()
    decisions = store.load("decisions.json", [])
    results = []
    for d in decisions:
        if d["verdict"] != "approve" or d["executed"]:
            continue
        if not _is_human(d.get("by")):
            raise ApprovalRequired(f"{d['key']}: approval was not given by a named human")
        target = d["key"].split(":", 1)[1]
        for action in d["actions"]:
            scope = catalog["actions"][action]["scope"]
            cred = ScopedCredential(f"{actor}/{action}", frozenset({scope}))  # one narrow credential per action
            out = executor.run(action, target, cred, scope)
            results.append({"incident": d["incident"], "action": action, "result": out, "approved_by": d["by"]})
            store.audit(f"executor:{actor}", "action", incident=d["incident"], action=action, scope=scope,
                        approved_by=d["by"], result=out)
        d["executed"] = True
    store.save("decisions.json", decisions)
    return results


def ai_execute(store: Store, action: str, target: str, catalog: dict) -> None:
    """What happens if the AI tries to act on its own: refused, and logged."""
    ai_scopes = set(catalog["ai_identity_scopes"])
    scope = catalog["actions"][action]["scope"]
    store.audit("ai:assistant", "action_refused", action=action, target=target, scope=scope,
                why="AI identity is read-only; actions need human approval")
    if scope not in ai_scopes:
        raise ApprovalRequired(f"AI identity has scopes {sorted(ai_scopes)}; {scope} requires a human-approved executor")


# ---------------- Learn ----------------

def learn_from_false_positive(store: Store, item: dict, by: str, reason: str, today: dt.date | None) -> list[dict]:
    today = today or dt.date.today()
    path = store.root / "learned-suppressions.yaml"
    learned = yaml.safe_load(path.read_text()) if path.exists() else []
    new = []
    for fp in item["fingerprints"]:
        rule, entity = fp.split("|", 1)
        new.append({"id": f"LRN-{len(learned) + len(new) + 1:03d}", "match": {"rule": rule, "entity": entity},
                    "reason": f"Human verdict: {reason}", "owner": by,
                    "expires": (today + dt.timedelta(days=30)).isoformat(), "learned_from": item["id"]})
    path.write_text(yaml.safe_dump(learned + new, sort_keys=False))
    store.audit(f"human:{by}", "tuning_learned", incident=item["id"], suppressions=[n["id"] for n in new])
    return new


def load_learned(store: Store) -> list[dict]:
    path = store.root / "learned-suppressions.yaml"
    return yaml.safe_load(path.read_text()) or [] if path.exists() else []
