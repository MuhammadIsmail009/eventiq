"""Report assembly and writers (FR-13, FR-14).

The JSON report is the single source of truth every downstream (JSONL, HTML,
Wazuh XML, Sigma YAML) is a pure function of. Output is deterministic: same
input plus same config yields byte-identical JSON except for ``generated_at``
(NFR-3). Alerts are sorted by (level desc, rule_id, entity, first_seen).
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .config import Config
from .correlate import RULE_CATALOG, Incident
from .detectors import enabled_rule_ids
from .engine import InputStats
from .model import Alert, level_to_severity
from .risk import EntityRisk

DEFAULT_GENERATED_AT = "1970-01-01 00:00:00"


def category_summary(alerts: list[Alert]) -> list[dict[str, Any]]:
    """Roll flagged events up per detection category: how many, how bad, why."""
    groups: dict[int, dict[str, Any]] = defaultdict(
        lambda: {"ids": set(), "level": 0, "mitre": set(), "alerts": 0}
    )
    for a in alerts:
        g = groups[a.rule_id]
        g["ids"] |= a.match_ids
        g["level"] = max(g["level"], a.level)
        g["mitre"].update(a.mitre_ids)
        g["alerts"] += 1
    out: list[dict[str, Any]] = []
    for rid, g in groups.items():
        name, basis = RULE_CATALOG.get(rid, (str(rid), ""))
        out.append(
            {
                "rule_id": rid,
                "category": name,
                "basis": basis,
                "severity": level_to_severity(g["level"]),
                "events": len(g["ids"]),
                "alerts": g["alerts"],
                "mitre": sorted(g["mitre"]),
            }
        )
    out.sort(key=lambda c: -int(c["events"]))
    return out


def _flagged_event_count(alerts: list[Alert]) -> int:
    flagged: set[str] = set()
    for a in alerts:
        flagged |= a.match_ids
    return len(flagged)


def _sort_key(alert: Alert) -> tuple[int, int, str, str]:
    return (-alert.level, alert.rule_id, alert.entity, alert.first_seen.isoformat())


def sort_alerts(alerts: list[Alert]) -> list[Alert]:
    return sorted(alerts, key=_sort_key)


def build_report(
    alerts: list[Alert],
    stats: InputStats,
    config: Config,
    *,
    incidents: list[Incident] | None = None,
    entity_risk: list[EntityRisk] | None = None,
    overview: dict[str, Any] | None = None,
    validation: dict[str, Any] | None = None,
    generated_at: str = DEFAULT_GENERATED_AT,
    include_dataset_notes: bool = True,
) -> dict[str, Any]:
    ordered = sort_alerts(alerts)
    incidents = incidents or []
    entity_risk = entity_risk or []
    overview = dict(overview or {})

    by_severity: Counter[str] = Counter(a.severity for a in ordered)
    distinct_rules = sorted({a.rule_id for a in ordered})
    flagged = _flagged_event_count(ordered)
    total = overview.get("total_events", stats.rows)
    overview["flagged_events"] = flagged
    overview["benign_events"] = max(0, total - flagged)
    overview["flagged_pct"] = round(100 * flagged / total, 2) if total else 0.0

    return {
        "generated_at": generated_at,
        "input": {
            "file": stats.file,
            "rows": stats.rows,
            "malformed": stats.malformed,
            "span_start": stats.span_start.isoformat(sep=" ") if stats.span_start else None,
            "span_end": stats.span_end.isoformat(sep=" ") if stats.span_end else None,
            "schema": "complete" if not stats.missing_optional else "partial",
            "missing_optional": list(stats.missing_optional),
        },
        "summary": {
            "by_severity": dict(by_severity),
            "distinct_rules": distinct_rules,
            "alert_count": len(ordered),
            "incident_count": len(incidents),
            "entities_at_risk": len(entity_risk),
            "flagged_events": flagged,
            "benign_events": overview["benign_events"],
        },
        "overview": overview,
        "categories": category_summary(ordered),
        "incidents": [i.to_dict() for i in incidents],
        "entity_risk": [e.to_dict() for e in entity_risk],
        "alerts": [a.to_envelope() for a in ordered],
        "coverage": {
            "rules_enabled": len(enabled_rule_ids(config)),
            "scope": "network, DNS, authentication, and selected Windows command behaviours",
        },
        "not_detected": [
            {"name": nd.name, "reason": nd.reason, "numbers": nd.numbers}
            for nd in config.not_detected
        ] if include_dataset_notes else [],
        "validation": validation,
    }


def write_json(report: dict[str, Any], path: str | Path) -> None:
    Path(path).write_text(
        json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )


def write_jsonl(alerts: list[Alert], path: str | Path) -> None:
    """Emit one alert per line, ingestible by Wazuh's JSON decoder (FR-14)."""
    lines = [json.dumps(a.to_envelope(), sort_keys=True) for a in sort_alerts(alerts)]
    Path(path).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
