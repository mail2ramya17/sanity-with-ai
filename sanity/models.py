from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY = {"informational": 1, "low": 2, "medium": 4, "high": 7, "critical": 10}


@dataclass
class Alert:
    id: str
    source: str          # siem | edr | cspm | ticket
    rule: str
    severity: str
    entity: str          # user, host or cloud resource the alert is about
    time: str            # ISO 8601
    title: str
    description: str = ""
    category: str = "other"
    confidence: float = 0.8
    attributes: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        return f"{self.rule}|{self.entity}"


@dataclass
class AlertGroup:
    fingerprint: str
    rule: str
    entity: str
    category: str
    severity: str
    alerts: list[Alert]
    sources: set[str]
    suppressed_by: str | None = None


@dataclass
class Incident:
    id: str
    entities: list[str]
    category: str
    groups: list[AlertGroup]
    score: float = 0.0
    context: dict = field(default_factory=dict)
    summary: dict = field(default_factory=dict)
    proposed_actions: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)

    @property
    def alerts(self) -> list[Alert]:
        return [a for g in self.groups for a in g.alerts]

    @property
    def sources(self) -> set[str]:
        return {s for g in self.groups for s in g.sources}

    @property
    def severity(self) -> str:
        return max((g.severity for g in self.groups), key=lambda s: SEVERITY[s])

    @property
    def first_seen(self) -> str:
        return min(a.time for a in self.alerts)
