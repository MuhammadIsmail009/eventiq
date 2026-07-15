"""Classic single-source detectors (Phase 7): each fires on its shape and stays
quiet on the benign near-miss, including events spread outside the time window."""

from __future__ import annotations

import csv
from pathlib import Path

from eventiq.config import load_config
from eventiq.detectors import build_detectors
from eventiq.engine import run_analysis
from eventiq.model import Alert
from eventiq.sources import get_source

REPO = Path(__file__).resolve().parents[2]

HEADER = [
    "log_id", "timestamp", "source_ip", "destination_ip", "source_port",
    "destination_port", "protocol", "service", "username", "event_type",
    "event_status", "domain", "command", "bytes_sent", "bytes_received", "severity",
]


def _row(lid: int, ts_sec: int, **kw: object) -> dict[str, object]:
    hh, mm, ss = ts_sec // 3600 % 24, ts_sec // 60 % 60, ts_sec % 60
    base: dict[str, object] = {
        "log_id": f"L{lid:07d}",
        "timestamp": f"2026-07-01 {hh:02d}:{mm:02d}:{ss:02d}",
        "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
        "source_port": 40000 + lid, "destination_port": 443, "protocol": "TCP",
        "service": "HTTP", "username": "", "event_type": "NETWORK_CONNECTION",
        "event_status": "SUCCESS", "domain": "", "command": "",
        "bytes_sent": 100, "bytes_received": 200, "severity": "LOW",
    }
    base.update(kw)
    return base


def _alerts(tmp_path: Path, rows: list[dict[str, object]]) -> dict[int, list[Alert]]:
    path = tmp_path / "c.csv"
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=HEADER)
        w.writeheader()
        w.writerows(rows)
    cfg = load_config(REPO / "config" / "default.yml")
    result = run_analysis(get_source("stdlib", str(path)), build_detectors(cfg))
    by_rule: dict[int, list[Alert]] = {}
    for a in result.alerts:
        by_rule.setdefault(a.rule_id, []).append(a)
    return by_rule


# --- classic_port_scan 100210 --------------------------------------------

def test_classic_port_scan_fires(tmp_path: Path) -> None:
    rows = [
        _row(i, i * 3, source_ip="198.51.100.9", destination_ip="192.168.1.5",
             destination_port=20 + i, event_status="SUCCESS")
        for i in range(12)
    ]
    a = _alerts(tmp_path, rows).get(100210, [])
    assert len(a) == 1
    assert a[0].entity == "198.51.100.9"
    assert a[0].evidence["distinct_ports"] == 12


def test_classic_port_scan_quiet_below_threshold(tmp_path: Path) -> None:
    rows = [
        _row(i, i * 3, source_ip="198.51.100.9", destination_ip="192.168.1.5",
             destination_port=20 + i)
        for i in range(5)
    ]
    assert _alerts(tmp_path, rows).get(100210, []) == []


def test_classic_port_scan_quiet_when_spread_beyond_window(tmp_path: Path) -> None:
    # 12 ports but one per hour: never 10 inside the 300s window.
    rows = [
        _row(i, i * 3600, source_ip="198.51.100.9", destination_ip="192.168.1.5",
             destination_port=20 + i)
        for i in range(12)
    ]
    assert _alerts(tmp_path, rows).get(100210, []) == []


# --- classic_brute_force 100110 ------------------------------------------

def test_classic_brute_force_fires(tmp_path: Path) -> None:
    rows = [
        _row(i, i * 5, source_ip="203.0.113.7", destination_ip="192.168.1.9",
             destination_port=22, service="SSH", username="root",
             event_status="FAILED")
        for i in range(8)
    ]
    a = _alerts(tmp_path, rows).get(100110, [])
    assert len(a) == 1
    assert a[0].entity == "203.0.113.7"
    assert a[0].evidence["failed_attempts"] == 8


def test_classic_brute_force_quiet_below_threshold(tmp_path: Path) -> None:
    rows = [
        _row(i, i * 5, source_ip="203.0.113.7", destination_ip="192.168.1.9",
             destination_port=22, service="SSH", username="root",
             event_status="FAILED")
        for i in range(7)
    ]
    assert _alerts(tmp_path, rows).get(100110, []) == []


# --- password_spray 100120 -----------------------------------------------

def test_password_spray_shape_a_one_source_many_users(tmp_path: Path) -> None:
    rows = [
        _row(i, i * 5, source_ip="198.51.100.77", destination_ip="192.168.1.20",
             destination_port=22, service="SSH", username=f"user{i}",
             event_status="FAILED")
        for i in range(6)
    ]
    a = [x for x in _alerts(tmp_path, rows).get(100120, [])
         if x.data.get("shape") == "source_to_many_users"]
    assert len(a) == 1
    assert a[0].evidence["distinct_usernames"] == 6


def test_password_spray_shape_b_many_sources_one_account(tmp_path: Path) -> None:
    rows = [
        _row(i, i * 5, source_ip=f"203.0.113.{i}", destination_ip="192.168.1.20",
             destination_port=22, service="SSH", username="administrator",
             event_status="FAILED")
        for i in range(8)
    ]
    a = [x for x in _alerts(tmp_path, rows).get(100120, [])
         if x.data.get("shape") == "many_sources_one_user"]
    assert len(a) == 1
    assert a[0].evidence["distinct_sources"] == 8


def test_password_spray_shape_b_defers_to_distributed_above_cap(tmp_path: Path) -> None:
    # 60 sources on one account is the distributed campaign (rule 100100 owns it),
    # so password_spray shape B must stay silent above max_sources.
    rows = [
        _row(i, i * 5, source_ip=f"185.199.{i // 256}.{i % 256}",
             destination_ip="192.168.1.20", destination_port=22, service="SSH",
             username="administrator", event_status="FAILED")
        for i in range(60)
    ]
    b = [x for x in _alerts(tmp_path, rows).get(100120, [])
         if x.data.get("shape") == "many_sources_one_user"]
    assert b == []


# --- lateral_movement 100130 ---------------------------------------------

def test_lateral_movement_fires(tmp_path: Path) -> None:
    rows = [
        _row(i, i * 5, source_ip="198.51.100.150", destination_ip=f"192.168.1.{i}",
             destination_port=445, protocol="TCP", service="SMB",
             username="administrator", event_status="FAILED")
        for i in range(6)
    ]
    a = _alerts(tmp_path, rows).get(100130, [])
    assert len(a) == 1
    assert a[0].entity == "198.51.100.150"
    assert a[0].evidence["distinct_hosts"] == 6


def test_lateral_movement_quiet_on_non_remote_ports(tmp_path: Path) -> None:
    # Same fan-out but on 443 (web), not a remote-service port: no lateral alert.
    rows = [
        _row(i, i * 5, source_ip="198.51.100.150", destination_ip=f"192.168.1.{i}",
             destination_port=443, service="HTTPS", username="administrator",
             event_status="FAILED")
        for i in range(6)
    ]
    assert _alerts(tmp_path, rows).get(100130, []) == []
