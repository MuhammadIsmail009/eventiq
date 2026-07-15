"""Each detector fires on its campaign and stays quiet on benign decoys."""

from __future__ import annotations

from pathlib import Path

from eventiq.config import load_config
from eventiq.detectors import build_detectors
from eventiq.engine import run_analysis
from eventiq.model import Alert
from eventiq.sources import get_source

REPO = Path(__file__).resolve().parents[2]


def _alerts(csv_path: Path) -> dict[int, list[Alert]]:
    cfg = load_config(REPO / "config" / "default.yml")
    detectors = build_detectors(cfg)
    result = run_analysis(get_source("stdlib", str(csv_path)), detectors)
    by_rule: dict[int, list[Alert]] = {}
    for a in result.alerts:
        by_rule.setdefault(a.rule_id, []).append(a)
    return by_rule


def test_port_scan_fires_on_destination(dataset_csv: Path) -> None:
    alerts = _alerts(dataset_csv).get(100200, [])
    assert len(alerts) == 1
    a = alerts[0]
    assert a.entity == "172.16.10.25"
    assert a.evidence["distinct_sources"] >= 50
    assert a.evidence["distinct_ports"] >= 15
    assert a.evidence["refused_events"] == 60


def test_brute_force_fires_and_ignores_background(dataset_csv: Path) -> None:
    alerts = _alerts(dataset_csv).get(100100, [])
    entities = {a.entity for a in alerts}
    assert entities == {"10.10.20.15"}  # not the background hosts, not the 28-source host
    a = alerts[0]
    assert a.evidence["distinct_sources"] >= 50
    assert set(a.data["ports"]) == {22, 3389}


def test_dns_tunnel_fires_once(dataset_csv: Path) -> None:
    alerts = _alerts(dataset_csv).get(100300, [])
    assert len(alerts) == 1
    a = alerts[0]
    assert a.entity == "data-transfer.example"
    assert a.evidence["unique_subdomains"] >= 5
    assert a.evidence["max_label_len"] >= 20


def test_suspicious_domain_fires_per_ioc(dataset_csv: Path) -> None:
    alerts = _alerts(dataset_csv).get(100400, [])
    assert len(alerts) == 6
    assert "data-transfer.example" not in {a.entity for a in alerts}  # tunneling not double-counted


def test_powershell_fires_per_host(dataset_csv: Path) -> None:
    alerts = _alerts(dataset_csv).get(100500, [])
    assert len(alerts) == 4
    all_patterns = {p for a in alerts for p in a.evidence["matched_patterns"]}
    assert all_patterns == {
        "encodedcommand", "downloadstring", "windowstyle_hidden", "executionpolicy_bypass"
    }


def test_c2_port_aggregates_to_one_finding(dataset_csv: Path) -> None:
    alerts = _alerts(dataset_csv).get(100600, [])
    assert len(alerts) == 1  # one finding per IOC port, not one per destination
    a = alerts[0]
    assert a.entity == "c2-port-4444"
    assert a.evidence["ioc_port"] == 4444
    assert a.evidence["event_count"] == 5
    assert a.evidence["distinct_dstips"] == 1
