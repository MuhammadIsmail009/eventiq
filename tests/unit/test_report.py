"""Report determinism and malformed-row handling."""

from __future__ import annotations

from pathlib import Path

from eventiq.config import load_config
from eventiq.correlate import RULE_CATALOG
from eventiq.detectors import build_detectors, enabled_rule_ids
from eventiq.engine import run_analysis
from eventiq.report import build_report
from eventiq.sources import get_source
from eventiq.sources.csv_source import CsvSource, MalformedRowError

REPO = Path(__file__).resolve().parents[2]


def _report(csv_path: Path) -> dict:
    cfg = load_config(REPO / "config" / "default.yml")
    result = run_analysis(get_source("stdlib", str(csv_path)), build_detectors(cfg))
    return build_report(result.alerts, result.stats, cfg, generated_at="fixed")


def test_deterministic_except_generated_at(dataset_csv: Path) -> None:
    import json

    a = json.dumps(_report(dataset_csv), sort_keys=True)
    b = json.dumps(_report(dataset_csv), sort_keys=True)
    assert a == b


def test_catalog_and_coverage_match_every_enabled_rule(dataset_csv: Path) -> None:
    cfg = load_config(REPO / "config" / "default.yml")
    enabled = enabled_rule_ids(cfg)

    assert enabled == set(RULE_CATALOG)
    assert len(enabled) == 12
    assert _report(dataset_csv)["coverage"]["rules_enabled"] == len(enabled)


def test_malformed_counted_not_crashed(tmp_path: Path) -> None:
    p = tmp_path / "m.csv"
    from tests.conftest import HEADER

    good = ",".join(HEADER)
    # A row with a non-numeric port -> unparseable, must be counted not fatal.
    bad = (
        "L1,2026-07-01 00:00:01,1.1.1.1,2.2.2.2,notaport,443,TCP,HTTP,,"
        "NETWORK_CONNECTION,SUCCESS,,,1,2,LOW"
    )
    p.write_text(good + "\n" + bad + "\n", encoding="utf-8")
    src = CsvSource(str(p))
    list(src)
    assert src.rows == 1
    assert src.malformed == 1


def test_strict_mode_raises(tmp_path: Path) -> None:
    p = tmp_path / "m.csv"
    from tests.conftest import HEADER

    bad = (
        "L1,2026-07-01 00:00:01,1.1.1.1,2.2.2.2,notaport,443,TCP,HTTP,,"
        "NETWORK_CONNECTION,SUCCESS,,,1,2,LOW"
    )
    p.write_text(",".join(HEADER) + "\n" + bad + "\n", encoding="utf-8")
    src = CsvSource(str(p), strict=True)
    try:
        list(src)
        raised = False
    except MalformedRowError:
        raised = True
    assert raised
