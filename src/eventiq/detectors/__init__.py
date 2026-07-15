"""Detector protocol and registry.

Each detector reads raw Event fields only, never the held-out label columns
(enforced by tests/test_no_label_leak.py). A detector accumulates state across
the single streaming pass and emits Alerts on ``finalize()``.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from ..config import Config
from ..model import Alert, Event


class Detector(Protocol):
    name: str

    def feed(self, event: Event) -> None: ...

    def finalize(self) -> list[Alert]: ...


def enabled_rule_ids(config: Config) -> set[int]:
    """Return every rule ID the effective detector configuration can emit.

    Keep this registry beside ``build_detectors`` so report coverage cannot
    drift from the detector set when a detector or configurable Sigma rule is
    added.
    """
    from .brute_force import RULE_ID as BRUTE_FORCE
    from .c2_port import RULE_ID as C2_PORT
    from .classic_brute_force import RULE_ID as CLASSIC_BRUTE_FORCE
    from .classic_port_scan import RULE_ID as CLASSIC_PORT_SCAN
    from .dns_tunnel import RULE_ID as DNS_TUNNEL
    from .lateral_movement import RULE_ID as LATERAL_MOVEMENT
    from .password_spray import RULE_ID as PASSWORD_SPRAY
    from .port_scan import RULE_ID as PORT_SCAN
    from .powershell import RULE_ID as POWERSHELL
    from .sigma_commands import RULES as SIGMA_RULES
    from .suspicious_domain import RULE_ID as SUSPICIOUS_DOMAIN

    core = {
        PORT_SCAN,
        BRUTE_FORCE,
        CLASSIC_PORT_SCAN,
        CLASSIC_BRUTE_FORCE,
        PASSWORD_SPRAY,
        LATERAL_MOVEMENT,
        DNS_TUNNEL,
        SUSPICIOUS_DOMAIN,
        POWERSHELL,
        C2_PORT,
    }
    sigma = {SIGMA_RULES[name][0] for name in config.sigma_commands.enabled_rules}
    return core | sigma


def build_detectors(config: Config) -> list[Detector]:
    """Construct every enabled detector from config, in report order."""
    from .brute_force import BruteForceDetector
    from .c2_port import C2PortDetector
    from .classic_brute_force import ClassicBruteForceDetector
    from .classic_port_scan import ClassicPortScanDetector
    from .dns_tunnel import DnsTunnelDetector
    from .lateral_movement import LateralMovementDetector
    from .password_spray import PasswordSprayDetector
    from .port_scan import PortScanDetector
    from .powershell import PowerShellDetector
    from .sigma_commands import SigmaCommandDetector
    from .suspicious_domain import SuspiciousDomainDetector

    detectors: list[Detector] = [
        PortScanDetector(config.port_scan),
        BruteForceDetector(config.brute_force),
        ClassicPortScanDetector(config.classic_port_scan),
        ClassicBruteForceDetector(config.classic_brute_force),
        PasswordSprayDetector(config.password_spray),
        LateralMovementDetector(config.lateral_movement),
        DnsTunnelDetector(config.dns_tunnel),
        SuspiciousDomainDetector(config.suspicious_domain),
        PowerShellDetector(config.powershell),
        SigmaCommandDetector(config.sigma_commands),
        C2PortDetector(config.c2_port),
    ]
    return detectors


def run_detectors(events: Iterable[Event], detectors: list[Detector]) -> list[Alert]:
    for event in events:
        for det in detectors:
            det.feed(event)
    alerts: list[Alert] = []
    for det in detectors:
        alerts.extend(det.finalize())
    return alerts
