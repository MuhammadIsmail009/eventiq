"""Malicious PowerShell detection (FR-8).

Matches encoded-command, download-cradle, hidden-window and execution-policy-
bypass patterns in the command field. Grouped per source host (the host running
the malicious command). Reads the command field only.
"""

from __future__ import annotations

import re
from datetime import datetime

from ..config import PowerShellConfig
from ..model import Alert, Event

RULE_ID = 100500

# Configurable pattern keys -> the regex that recognises them. Case-insensitive.
# "-enc" matches both "-enc" and "-EncodedCommand" (the latter starts with -enc).
_PATTERN_REGEX = {
    "encodedcommand": re.compile(r"-enc", re.IGNORECASE),
    "downloadstring": re.compile(r"downloadstring", re.IGNORECASE),
    "windowstyle_hidden": re.compile(r"-w(?:indowstyle)?\s+hidden", re.IGNORECASE),
    "executionpolicy_bypass": re.compile(r"-e(?:xecutionpolicy)?\s+bypass", re.IGNORECASE),
}


class UnknownPatternError(ValueError):
    """Raised when a configured PowerShell pattern key is not recognised."""


class _HostStats:
    __slots__ = ("count", "patterns", "commands", "first_seen", "last_seen", "ids")

    def __init__(self) -> None:
        self.count = 0
        self.patterns: set[str] = set()
        self.commands: list[str] = []
        self.first_seen: datetime | None = None
        self.last_seen: datetime | None = None
        self.ids: list[str] = []


class PowerShellDetector:
    name = "powershell"

    def __init__(self, cfg: PowerShellConfig) -> None:
        self.cfg = cfg
        unknown = [p for p in cfg.patterns if p not in _PATTERN_REGEX]
        if unknown:
            raise UnknownPatternError(f"unknown powershell pattern(s): {', '.join(unknown)}")
        self.patterns = [(p, _PATTERN_REGEX[p]) for p in cfg.patterns]
        self.hosts: dict[str, _HostStats] = {}

    def feed(self, event: Event) -> None:
        command = event.command
        if not command:
            return
        matched = [name for name, rx in self.patterns if rx.search(command)]
        if not matched:
            return
        stats = self.hosts.get(event.srcip)
        if stats is None:
            stats = _HostStats()
            self.hosts[event.srcip] = stats
        stats.count += 1
        stats.patterns.update(matched)
        if len(stats.commands) < 5:
            stats.commands.append(command[:120])
        if stats.first_seen is None or event.timestamp < stats.first_seen:
            stats.first_seen = event.timestamp
        if stats.last_seen is None or event.timestamp > stats.last_seen:
            stats.last_seen = event.timestamp
        stats.ids.append(event.log_id)

    def finalize(self) -> list[Alert]:
        alerts: list[Alert] = []
        for srcip, s in self.hosts.items():
            assert s.first_seen is not None and s.last_seen is not None
            alerts.append(
                Alert(
                    rule_id=RULE_ID,
                    level=self.cfg.level,
                    description="Malicious PowerShell command pattern",
                    mitre_ids=list(self.cfg.mitre),
                    title=f"Malicious PowerShell on {srcip}",
                    entity=srcip,
                    first_seen=s.first_seen,
                    last_seen=s.last_seen,
                    data={"srcip": srcip, "sample_commands": s.commands},
                    evidence={
                        "matched_patterns": sorted(s.patterns),
                        "events": s.count,
                    },
                    sample_rows=s.ids[:5],
                    match_ids=set(s.ids),
                )
            )
        return alerts
