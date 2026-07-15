"""Incident correlation (FR-12).

Collapses the alert stream into a short, ranked list of incidents. Alerts are
grouped by detection campaign (rule), which is what turns 17,000-plus row-level
alerts into a handful of things an analyst can actually read. Each incident names
its primary entity (highest risk), the full affected-entity set (capped for
display, count retained), the MITRE techniques, and a plain-English narrative.

Grouping by rule fits this dataset, where each campaign targets a distinct entity
set. The per-entity risk table (risk.py) is the cross-cutting view that would
surface an entity spanning several techniques.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .model import Alert, level_to_severity

MAX_AFFECTED_SHOWN = 50
MAX_BREADTH_BONUS = 25

# rule_id -> (readable category, the basis on which it flags). Single source of
# truth for the human-facing "what and why", used by incidents and the category
# rollup in the report.
RULE_CATALOG: dict[int, tuple[str, str]] = {
    100100: ("Brute force / password spray",
             "Many distinct sources failing authentication on one host (SSH + RDP)"),
    100200: ("Port scan",
             "Many distinct sources refused by one host across many ports"),
    100300: ("DNS tunneling",
             "High-entropy, long, and numerous subdomains under one parent domain"),
    100400: ("Suspicious domain",
             "Domain on the threat-intel indicator list or a flagged TLD"),
    100500: ("Malicious PowerShell",
             "Encoded / download-cradle / hidden-window / policy-bypass command"),
    100600: ("C2 indicator",
             "Traffic to a known command-and-control handler port"),
    100700: ("Bitsadmin download",
             "SigmaHQ-derived Bitsadmin transfer or create/addfile download command"),
    100710: ("Certutil download",
             "SigmaHQ-derived Certutil URL download command"),
    100110: ("Classic brute force",
             "Repeated failed logins from one source against one target and username"),
    100120: ("Password spray",
             "Authentication failures spread across users or source addresses"),
    100130: ("Lateral movement",
             "One source reaching several internal hosts over remote-service ports"),
    100210: ("Classic port scan",
             "One source probing many refused destination ports on one target"),
}


def _breadth_bonus(affected_count: int) -> int:
    """A campaign hitting many entities is more urgent than one hitting a single
    host. Bonus grows with the order of magnitude of affected entities."""
    if affected_count <= 1:
        return 0
    return min(MAX_BREADTH_BONUS, round(8 * math.log10(affected_count)))


def _event_count(alert: Alert) -> int:
    for key in (
        "events",
        "event_count",
        "failed_events",
        "refused_events",
        "queries",
        "distinct_sources",
    ):
        v = alert.evidence.get(key)
        if isinstance(v, int):
            return v
    return 1


def _narrative(rule_id: int, alerts: list[Alert], primary: str) -> str:
    n_entities = len({a.entity for a in alerts})
    ev = alerts[0].evidence
    if rule_id == 100200:
        return (
            f"Distributed port scan against {primary}: refused connections from "
            f"{ev.get('distinct_sources', '?')} distinct sources across "
            f"{ev.get('distinct_ports', '?')} ports."
        )
    if rule_id == 100100:
        users = ", ".join(ev.get("top_usernames", [])[:3])
        return (
            f"Distributed brute force against {primary}: failed auth from "
            f"{ev.get('distinct_sources', '?')} distinct sources targeting {users}."
        )
    if rule_id == 100300:
        return (
            f"DNS tunneling via {primary}: {ev.get('unique_subdomains', '?')} unique "
            f"high-entropy subdomains."
        )
    if rule_id == 100400:
        return f"Suspicious domain activity: {n_entities} known-bad domains contacted."
    if rule_id == 100500:
        patterns = sorted({p for a in alerts for p in a.evidence.get("matched_patterns", [])})
        return (
            f"Malicious PowerShell across {n_entities} hosts using "
            f"{', '.join(patterns)}."
        )
    if rule_id == 100600:
        return (
            f"C2 indicator: {sum(_event_count(a) for a in alerts)} connections to "
            f"{primary.replace('c2-port-', 'port ')} from "
            f"{ev.get('distinct_srcips', '?')} internal hosts."
        )
    if rule_id in (100700, 100710):
        return f"{RULE_CATALOG[rule_id][0]} command observed on {primary}."
    return f"{len(alerts)} related alerts on {primary}."


@dataclass(slots=True)
class Incident:
    incident_id: str
    rule_id: int
    title: str
    category: str
    basis: str
    primary_entity: str
    severity: str
    risk_score: int
    techniques: list[str]
    first_seen: datetime
    last_seen: datetime
    alert_count: int
    event_count: int
    affected_count: int
    affected_entities: list[str]
    narrative: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.incident_id,
            # The SPA uses this explicit relationship for related-alert
            # navigation. Inferring it from category/title text is fragile.
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "basis": self.basis,
            "primary_entity": self.primary_entity,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "techniques": self.techniques,
            "first_seen": self.first_seen.isoformat(sep=" "),
            "last_seen": self.last_seen.isoformat(sep=" "),
            "alert_count": self.alert_count,
            "event_count": self.event_count,
            "affected_count": self.affected_count,
            "affected_entities": self.affected_entities,
            "narrative": self.narrative,
        }


def build_incidents(alerts: list[Alert], entity_risk: dict[str, int]) -> list[Incident]:
    groups: dict[int, list[Alert]] = {}
    for a in alerts:
        groups.setdefault(a.rule_id, []).append(a)

    incidents: list[Incident] = []
    for rule_id, group in groups.items():
        entities = sorted({a.entity for a in group})
        primary = max(entities, key=lambda e: (entity_risk.get(e, 0), e))
        top_entity_risk = max((entity_risk.get(e, 0) for e in entities), default=0)
        risk = min(100, top_entity_risk + _breadth_bonus(len(entities)))
        max_level = max(a.level for a in group)
        techniques = sorted({t for a in group for t in a.mitre_ids})
        category, basis = RULE_CATALOG.get(rule_id, (group[0].description, ""))
        incidents.append(
            Incident(
                incident_id="",  # assigned after ranking
                rule_id=rule_id,
                title=group[0].description,
                category=category,
                basis=basis,
                primary_entity=primary,
                severity=level_to_severity(max_level),
                risk_score=risk,
                techniques=techniques,
                first_seen=min(a.first_seen for a in group),
                last_seen=max(a.last_seen for a in group),
                alert_count=len(group),
                event_count=sum(_event_count(a) for a in group),
                affected_count=len(entities),
                affected_entities=entities[:MAX_AFFECTED_SHOWN],
                narrative=_narrative(rule_id, group, primary),
            )
        )

    incidents.sort(key=lambda i: (-i.risk_score, -i.event_count, i.rule_id))
    for n, inc in enumerate(incidents, start=1):
        inc.incident_id = f"INC-{n:04d}"
    return incidents
