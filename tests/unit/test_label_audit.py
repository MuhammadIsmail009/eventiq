"""Accuracy is shown only where the file contains a supported answer key."""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from eventiq.cli import _print_validation
from eventiq.model import Alert
from eventiq.validate import score_alerts


def _alert(rule_id: int, *ids: str) -> Alert:
    return Alert(
        rule_id=rule_id,
        level=10,
        description="test",
        mitre_ids=[],
        title="test",
        entity="entity",
        first_seen=datetime(2026, 7, 1),
        last_seen=datetime(2026, 7, 1),
        data={},
        evidence={},
        match_ids=set(ids),
    )


def _write(path: Path, rows: list[dict[str, str]]) -> Path:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["log_id", "event_type", "event_status"]
        )
        writer.writeheader()
        writer.writerows(rows)
    return path


def test_unknown_only_labels_do_not_create_zero_accuracy_headline(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "unknown.csv",
        [{"log_id": "L1", "event_type": "system_event", "event_status": "SUCCESS"}],
    )
    result = score_alerts([_alert(100710, "L1")], path)
    assert result["label_audit"]["quality"] == "unsupported"
    assert result["overall"] is None
    assert result["per_rule"] == {}
    assert any(item["rule_id"] == 100710 for item in result["unscored"])


def test_partial_answer_key_scores_only_present_campaign(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "partial.csv",
        [
            {"log_id": "L1", "event_type": "DNS_TUNNELING", "event_status": "ALLOWED"},
            {"log_id": "L2", "event_type": "DNS_QUERY", "event_status": "ALLOWED"},
        ],
    )
    result = score_alerts([_alert(100300, "L1")], path)
    assert result["label_audit"]["quality"] == "partial"
    assert list(result["per_rule"]) == ["dns_tunnel"]
    assert result["overall"]["f1"] == 1.0
    assert any(item["rule_id"] == 100600 for item in result["unscored"])


def test_unscorable_validation_prints_without_crashing(
    tmp_path: Path, capsys: object
) -> None:
    path = _write(
        tmp_path / "unknown.csv",
        [{"log_id": "L1", "event_type": "system_event", "event_status": "SUCCESS"}],
    )
    result = score_alerts([], path)
    _print_validation(result)
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "overall metrics are N/A" in out
