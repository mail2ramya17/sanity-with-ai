"""AI enrich: context, owner and blast radius, so the human decides with the facts in front of them."""
from __future__ import annotations

from collections import deque

from .models import Incident


def _node(name: str, inventory: dict) -> dict | None:
    return inventory["assets"].get(name) or inventory["identities"].get(name)


def blast_radius(entity: str, inventory: dict, depth: int = 2) -> dict:
    """Breadth-first walk over what this entity can reach. Crown jewels in reach raise the stakes."""
    seen, queue, reach = {entity}, deque([(entity, 0)]), []
    while queue:
        name, d = queue.popleft()
        node = _node(name, inventory)
        if not node or d >= depth:
            continue
        for nxt in node.get("connects_to", []):
            if nxt not in seen:
                seen.add(nxt)
                reach.append(nxt)
                queue.append((nxt, d + 1))
    crown = [r for r in reach if inventory["assets"].get(r, {}).get("criticality") == "crown_jewel"]
    return {"reachable": reach, "crown_jewels": crown}


def enrich(inc: Incident, inventory: dict) -> None:
    entity = inc.entities[0]
    asset = inventory["assets"].get(entity)
    ident = inventory["identities"].get(entity)
    ctx: dict = {"entity_type": "asset" if asset else "identity" if ident else "unknown"}
    if asset:
        ctx.update(owner=asset["owner"], criticality=asset["criticality"], env=asset["env"],
                   internet_facing=asset["internet_facing"], data=asset.get("data", []))
    elif ident:
        ctx.update(owner=ident["owner"], manager=ident.get("manager"), privileged=ident.get("privileged", False),
                   roles=ident.get("roles", []), dormant_days=ident.get("dormant_days"))
    else:
        ctx.update(owner="unknown", criticality="unknown")
    ctx["blast_radius"] = blast_radius(entity, inventory)
    ctx["alert_count"] = len(inc.alerts)
    ctx["sources"] = sorted(inc.sources)
    ctx["first_seen"] = inc.first_seen
    inc.context = ctx
