"""Per-entity risk scoring (FR-11), in the spirit of risk-based alerting.

Each alert is assigned a risk contribution from its severity and the magnitude of
what it saw (a scan from 15,000 sources outweighs one from 60). Contributions are
summed per entity, so an entity hit by several detections rises to the top. An
entity implicated by more than one distinct rule gets a convergence bonus, which
is the whole point of risk-based alerting: separate weak signals that share a
target are collectively strong.

The scheme is deliberately simple and explainable: every number an analyst sees
can be traced back to a severity band and an order-of-magnitude scale.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from .model import Alert

# Base points per severity band. Documented, not magic: CRITICAL is worth ~5x LOW.
SEVERITY_POINTS = {"CRITICAL": 50, "HIGH": 35, "MEDIUM": 20, "LOW": 10, "INFO": 5}

# Evidence keys that express "how big is this", used for the magnitude multiplier.
_SCALE_KEYS = (
    "distinct_sources",
    "distinct_srcips",
    "unique_subdomains",
    "failed_events",
    "refused_events",
    "events",
    "event_count",
    "queries",
)

CONVERGENCE_BONUS = 15


def _scale_metric(evidence: dict[str, Any]) -> int:
    values = [1]
    for key in _SCALE_KEYS:
        v = evidence.get(key)
        if isinstance(v, int):
            values.append(v)
    return max(values)


def alert_risk(alert: Alert) -> int:
    """Risk points (0-100) for a single alert: severity base x magnitude."""
    base = SEVERITY_POINTS.get(alert.severity, 5)
    scale = _scale_metric(alert.evidence)
    # 1.0 at scale 1, rising to 2.0 by scale 10,000 (four orders of magnitude).
    multiplier = 1.0 + min(1.0, math.log10(scale) / 4) if scale > 1 else 1.0
    return min(100, round(base * multiplier))


def _band(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


@dataclass(slots=True)
class EntityRisk:
    entity: str
    risk_score: int
    severity: str
    contributing_rules: list[int]
    techniques: list[str]
    alert_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "contributing_rules": self.contributing_rules,
            "techniques": self.techniques,
            "alert_count": self.alert_count,
        }


def score_entities(alerts: list[Alert]) -> list[EntityRisk]:
    """Assign each alert a risk_score and aggregate risk per entity, ranked."""
    agg: dict[str, dict[str, Any]] = {}
    for a in alerts:
        a.risk_score = alert_risk(a)
        e = agg.setdefault(
            a.entity, {"score": 0, "rules": set(), "tech": set(), "count": 0}
        )
        e["score"] += a.risk_score
        e["rules"].add(a.rule_id)
        e["tech"].update(a.mitre_ids)
        e["count"] += 1

    result: list[EntityRisk] = []
    for entity, d in agg.items():
        score = d["score"]
        if len(d["rules"]) >= 2:
            score += CONVERGENCE_BONUS
        score = min(100, score)
        result.append(
            EntityRisk(
                entity=entity,
                risk_score=score,
                severity=_band(score),
                contributing_rules=sorted(d["rules"]),
                techniques=sorted(d["tech"]),
                alert_count=d["count"],
            )
        )
    result.sort(key=lambda er: (-er.risk_score, er.entity))
    return result
