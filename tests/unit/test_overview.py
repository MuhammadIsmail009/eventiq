"""Whole-file profiler and category rollup."""

from __future__ import annotations

from datetime import datetime

from eventiq.model import Alert
from eventiq.overview import StreamProfiler
from eventiq.report import category_summary

TS = datetime(2026, 7, 1, 3, 0, 0)


def _ev(**kw: object):
    from eventiq.model import Event
    base = {
        "log_id": "L1", "timestamp": TS, "srcip": "1.1.1.1", "dstip": "2.2.2.2",
        "srcport": 1, "dstport": 443, "protocol": "TCP", "service": "HTTP",
        "srcuser": "", "status": "SUCCESS", "domain": "", "command": "",
        "bytes_sent": 10, "bytes_received": 20,
    }
    base.update(kw)
    return Event(**base)  # type: ignore[arg-type]


def test_profiler_counts_raw_fields() -> None:
    p = StreamProfiler()
    p.observe(_ev(srcip="a", dstip="x", protocol="TCP", status="SUCCESS"))
    p.observe(_ev(srcip="b", dstip="x", protocol="UDP", status="FAILED", service="DNS"))
    p.observe(_ev(srcip="a", dstip="y", protocol="TCP", status="SUCCESS"))
    r = p.result()
    assert r["total_events"] == 3
    assert r["distinct"]["source_ips"] == 2
    assert r["distinct"]["destination_ips"] == 2
    assert r["protocol"] == {"TCP": 2, "UDP": 1}
    assert r["status"]["FAILED"] == 1
    assert r["daily_volume"] == [["2026-07-01", 3]]


def _alert(rule_id: int, level: int, ids: set[str], mitre: list[str]) -> Alert:
    return Alert(
        rule_id=rule_id, level=level, description="d", mitre_ids=mitre, title="t",
        entity="e", first_seen=TS, last_seen=TS, data={}, evidence={}, match_ids=ids,
    )


def test_category_summary_rolls_up_and_sorts() -> None:
    alerts = [
        _alert(100500, 13, {"a", "b"}, ["T1059.001"]),
        _alert(100500, 13, {"b", "c"}, ["T1059.001"]),   # overlaps b -> 3 distinct
        _alert(100600, 12, {"x", "y", "z", "w"}, ["T1571"]),
    ]
    cats = category_summary(alerts)
    assert cats[0]["rule_id"] == 100600  # more events sorts first
    ps = next(c for c in cats if c["rule_id"] == 100500)
    assert ps["events"] == 3  # deduped across alerts
    assert ps["category"] == "Malicious PowerShell"
    assert ps["basis"]
