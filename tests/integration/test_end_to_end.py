"""End-to-end: analyze -> validate on the combined fixture, asserting the floor."""

from __future__ import annotations

from pathlib import Path

from eventiq.cli import main
from eventiq.config import load_config
from eventiq.detectors import build_detectors
from eventiq.engine import run_analysis
from eventiq.sources import get_source
from eventiq.validate import score_alerts

REPO = Path(__file__).resolve().parents[2]


def _validate(csv_path: Path) -> dict:
    cfg = load_config(REPO / "config" / "default.yml")
    result = run_analysis(get_source("stdlib", str(csv_path)), build_detectors(cfg))
    return score_alerts(result.alerts, str(csv_path))


def test_precision_recall_floor(dataset_csv: Path) -> None:
    v = _validate(dataset_csv)
    for name, r in v["per_rule"].items():
        assert r["recall"] >= 0.95, f"{name} recall {r['recall']}"
        assert r["precision"] >= 0.90, f"{name} precision {r['precision']}"
    assert v["overall"]["f1"] >= 0.95


def test_beats_naive_failed_login_baseline(dataset_csv: Path) -> None:
    v = _validate(dataset_csv)
    brute = v["per_rule"]["brute_force"]
    naive = v["naive_failed_login_baseline"]["precision"]
    assert brute["precision"] > naive
    assert naive < 0.6  # the background noise sinks the naive rule


def test_c2_reported_but_not_scored(dataset_csv: Path) -> None:
    v = _validate(dataset_csv)
    assert "c2_port" not in v["per_rule"]
    assert any(u["rule_id"] == 100600 and u["alerts"] == 1 for u in v["unscored"])


def test_cli_analyze_exit_code_and_report(dataset_csv: Path, tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    jsonl = tmp_path / "alerts.jsonl"
    code = main([
        "analyze", str(dataset_csv), "-c", str(REPO / "config" / "default.yml"),
        "-o", str(out), "--jsonl", str(jsonl), "--validate",
        "--generated-at", "2026-07-14 00:00:00",
    ])
    assert code == 1  # alerts at/above min severity -> exit 1
    assert out.exists() and jsonl.exists()
    import json

    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["validation"]["overall"]["f1"] >= 0.95
    assert len(report["not_detected"]) == 2
    assert jsonl.read_text(encoding="utf-8").strip().count("\n") + 1 >= 12
    # correlation collapses alerts into a readable incident list
    incidents = report["incidents"]
    assert 1 <= len(incidents) <= 8
    assert incidents[0]["risk_score"] >= incidents[-1]["risk_score"]  # risk-ranked
    assert report["entity_risk"], "entity risk table present"
    assert report["summary"]["incident_count"] == len(incidents)


def test_cli_config_error_exit_2(dataset_csv: Path, tmp_path: Path) -> None:
    bad = tmp_path / "bad.yml"
    bad.write_text("bogus_key: 1\n", encoding="utf-8")
    code = main(["analyze", str(dataset_csv), "-c", str(bad), "-o", str(tmp_path / "r.json")])
    assert code == 2
