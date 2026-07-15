"""Conservative command detections derived from current SigmaHQ rules.

This is intentionally not advertised as a general Sigma runtime. EventIQ's
normalised CSV model exposes a command line but not Sigma's Image or
OriginalFileName fields, so each rule requires the utility name in the command
itself as a safe substitute for the process-image selection.
"""

from __future__ import annotations

import re
from datetime import datetime

from ..config import SigmaCommandConfig
from ..model import Alert, Event

RULES: dict[str, tuple[int, str, re.Pattern[str]]] = {
    "bitsadmin_download": (
        100700,
        "Sigma-derived Bitsadmin file download",
        re.compile(r"(?:^|[\\/\s])bitsadmin(?:\.exe)?(?=\s|$)", re.IGNORECASE),
    ),
    "certutil_download": (
        100710,
        "Sigma-derived Certutil file download",
        re.compile(r"(?:^|[\\/\s])certutil(?:\.exe)?(?=\s|$)", re.IGNORECASE),
    ),
}


class UnknownSigmaCommandRule(ValueError):
    """Raised when config enables a rule this build does not implement."""


def _matches(name: str, command: str, image: re.Pattern[str]) -> bool:
    if not image.search(command):
        return False
    value = f" {command.lower()} "
    if name == "bitsadmin_download":
        return " /transfer " in value or (
            (" /create " in value or " /addfile " in value) and "http" in value
        )
    if name == "certutil_download":
        return "http" in value and any(
            flag in value for flag in ("urlcache ", "verifyctl ", " url ")
        )
    return False


class _RuleStats:
    __slots__ = ("commands", "first_seen", "last_seen", "ids")

    def __init__(self) -> None:
        self.commands: list[str] = []
        self.first_seen: datetime | None = None
        self.last_seen: datetime | None = None
        self.ids: list[str] = []


class SigmaCommandDetector:
    name = "sigma_commands"

    def __init__(self, cfg: SigmaCommandConfig) -> None:
        self.cfg = cfg
        unknown = sorted(set(cfg.enabled_rules) - set(RULES))
        if unknown:
            raise UnknownSigmaCommandRule(
                f"unknown Sigma-derived command rule(s): {', '.join(unknown)}"
            )
        self.enabled = [(name, *RULES[name]) for name in cfg.enabled_rules]
        self.matches: dict[tuple[str, str], _RuleStats] = {}

    def feed(self, event: Event) -> None:
        if not event.command:
            return
        for name, _rule_id, _title, image in self.enabled:
            if not _matches(name, event.command, image):
                continue
            key = (name, event.srcip or "unknown-source")
            stats = self.matches.setdefault(key, _RuleStats())
            if len(stats.commands) < 5:
                stats.commands.append(event.command[:160])
            stats.ids.append(event.log_id)
            if stats.first_seen is None or event.timestamp < stats.first_seen:
                stats.first_seen = event.timestamp
            if stats.last_seen is None or event.timestamp > stats.last_seen:
                stats.last_seen = event.timestamp

    def finalize(self) -> list[Alert]:
        alerts: list[Alert] = []
        for (name, entity), stats in self.matches.items():
            rule_id, description, _image = RULES[name]
            assert stats.first_seen is not None and stats.last_seen is not None
            alerts.append(
                Alert(
                    rule_id=rule_id,
                    level=self.cfg.level,
                    description=description,
                    mitre_ids=list(self.cfg.mitre),
                    title=f"{description} on {entity}",
                    entity=entity,
                    first_seen=stats.first_seen,
                    last_seen=stats.last_seen,
                    data={"srcip": entity, "sample_commands": stats.commands},
                    evidence={
                        "events": len(stats.ids),
                        "source": "SigmaHQ",
                        "rule_key": name,
                    },
                    sample_rows=stats.ids[:5],
                    match_ids=set(stats.ids),
                )
            )
        return alerts
