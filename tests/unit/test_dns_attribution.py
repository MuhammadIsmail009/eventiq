"""DNS campaign evidence must contain candidate rows only."""

from __future__ import annotations

from datetime import datetime, timedelta

from eventiq.config import DnsTunnelConfig
from eventiq.detectors.dns_tunnel import DnsTunnelDetector
from eventiq.model import Event


def _event(log_id: str, domain: str, offset: int = 0) -> Event:
    return Event(
        log_id=log_id,
        timestamp=datetime(2026, 7, 1) + timedelta(seconds=offset),
        srcip="10.0.0.1",
        dstip="8.8.8.8",
        srcport=None,
        dstport=53,
        protocol="UDP",
        service="DNS",
        srcuser="",
        status="ALLOWED",
        domain=domain,
        command="",
        bytes_sent=0,
        bytes_received=0,
    )


def test_alert_matches_only_rows_that_pass_both_candidate_checks() -> None:
    det = DnsTunnelDetector(
        DnsTunnelConfig(min_entropy=3.0, min_label_len=20, min_query_count=2)
    )
    det.feed(_event("candidate-1", "a1b2c3d4e5f6g7h8i9j0.example.com"))
    det.feed(_event("benign-sibling", "www.example.com", 1))
    det.feed(_event("candidate-2", "z9y8x7w6v5u4t3s2r1q0.example.com", 2))
    alerts = det.finalize()
    assert len(alerts) == 1
    assert alerts[0].match_ids == {"candidate-1", "candidate-2"}
    assert alerts[0].evidence["queries"] == 2


def test_long_low_entropy_and_short_high_entropy_do_not_combine() -> None:
    det = DnsTunnelDetector(
        DnsTunnelConfig(min_entropy=3.0, min_label_len=20, min_query_count=1)
    )
    det.feed(_event("long", f"{'a' * 30}.example.com"))
    det.feed(_event("random-short", "a1b2c3d4.example.com", 1))
    assert det.finalize() == []


def test_repeated_candidate_domain_does_not_meet_unique_threshold() -> None:
    det = DnsTunnelDetector(
        DnsTunnelConfig(min_entropy=3.0, min_label_len=20, min_query_count=2)
    )
    domain = "a1b2c3d4e5f6g7h8i9j0.example.com"
    for i in range(5):
        det.feed(_event(f"row-{i}", domain, i))
    assert det.finalize() == []

