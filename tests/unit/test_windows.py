"""Boundary tests for the convergence primitive."""

from __future__ import annotations

from datetime import datetime

from eventiq.model import Event
from eventiq.windows import ConvergenceGroup, subnet_24


def _event(srcip: str, dstport: int | None, status: str, sec: int, br: int = 5) -> Event:
    return Event(
        log_id=f"L{sec}", timestamp=datetime(2026, 7, 1, 0, 0, sec), srcip=srcip,
        dstip="10.0.0.9", srcport=1234, dstport=dstport, protocol="TCP",
        service="SSH", srcuser="root", status=status, domain="", command="",
        bytes_sent=10, bytes_received=br,
    )


def test_subnet_24() -> None:
    assert subnet_24("203.0.5.7") == "203.0.5.0/24"
    assert subnet_24("not-an-ip") == "not-an-ip"


def test_distinct_dedup_and_counts() -> None:
    g = ConvergenceGroup()
    g.observe(_event("203.0.0.1", 22, "BLOCKED", 1, br=0))
    g.observe(_event("203.0.0.1", 22, "BLOCKED", 2, br=0))  # duplicate source
    g.observe(_event("203.0.0.2", 23, "ALLOWED", 3, br=5))
    assert g.count == 3
    assert len(g.sources) == 2  # deduped
    assert len(g.subnets24) == 1
    assert len(g.dstports) == 2
    assert g.blocked == 2
    assert g.zero_bytes_back == 2


def test_blocked_frac_and_span() -> None:
    g = ConvergenceGroup()
    g.observe(_event("1.1.1.1", 22, "BLOCKED", 10))
    g.observe(_event("1.1.1.2", 22, "SUCCESS", 5))
    g.observe(_event("1.1.1.3", 22, "BLOCKED", 20))
    assert g.blocked_frac == 2 / 3
    assert g.first_seen == datetime(2026, 7, 1, 0, 0, 5)
    assert g.last_seen == datetime(2026, 7, 1, 0, 0, 20)


def test_top_usernames_ordering() -> None:
    g = ConvergenceGroup()
    for _ in range(3):
        g.observe(_event("2.2.2.2", 22, "FAILED", 1))  # srcuser root x3
    g.usernames["admin"] = 5
    assert g.top_usernames(1) == ["admin"]
