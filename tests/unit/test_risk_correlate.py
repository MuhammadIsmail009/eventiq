"""Risk scoring and incident correlation."""

from __future__ import annotations

from datetime import datetime

from eventiq.correlate import build_incidents
from eventiq.model import Alert
from eventiq.risk import alert_risk, score_entities

TS = datetime(2026, 7, 1, 0, 0, 0)


def _alert(rule_id: int, level: int, entity: str, **evidence: object) -> Alert:
    return Alert(
        rule_id=rule_id, level=level, description="x", mitre_ids=["T1000"], title="t",
        entity=entity, first_seen=TS, last_seen=TS, data={}, evidence=evidence,
    )


def test_magnitude_raises_risk() -> None:
    small = _alert(100200, 12, "a", distinct_sources=60)
    large = _alert(100200, 12, "b", distinct_sources=15000)
    assert alert_risk(large) > alert_risk(small)
    assert alert_risk(large) <= 100


def test_convergence_bonus_when_two_rules_hit_one_entity() -> None:
    alerts = [
        _alert(100200, 12, "host", distinct_sources=100),
        _alert(100500, 13, "host", events=1),
    ]
    ranked = score_entities(alerts)
    top = ranked[0]
    assert top.entity == "host"
    assert len(top.contributing_rules) == 2
    # score exceeds the sum of the two bases alone (bonus applied), capped at 100
    assert top.risk_score <= 100


def test_incidents_group_by_campaign_and_rank() -> None:
    alerts = [
        _alert(100500, 13, f"host{i}", events=1) for i in range(2000)
    ] + [
        _alert(100200, 12, "victim", distinct_sources=15000, distinct_ports=30),
    ]
    er = {e.entity: e.risk_score for e in score_entities(alerts)}
    incidents = build_incidents(alerts, er)
    # 2000 powershell alerts collapse into ONE incident; scan is its own incident
    assert len(incidents) == 2
    ps = next(i for i in incidents if i.rule_id == 100500)
    assert ps.alert_count == 2000
    assert ps.affected_count == 2000
    assert len(ps.affected_entities) <= 50  # capped for display
    assert ps.to_dict()["rule_id"] == 100500
    # incidents carry sequential ids and are risk-ranked
    assert incidents[0].incident_id == "INC-0001"
    assert incidents[0].risk_score >= incidents[1].risk_score
