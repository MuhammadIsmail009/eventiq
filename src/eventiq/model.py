"""Core data contracts: the raw-only Event and the Wazuh-shaped Alert.

Freeze these before writing detectors (PLAN section 3). The single hard
guarantee of the project is enforced here structurally: ``Event`` has no
``event_type`` and no ``severity`` field, so a detector cannot read the answer
key even by accident.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class Event:
    """One log row, mapped onto Wazuh-native field names (FR-2).

    Deliberately absent: ``event_type`` and ``severity``. They are dropped at
    parse time so no detector can see them.
    """

    log_id: str
    timestamp: datetime
    srcip: str
    dstip: str
    srcport: int | None
    dstport: int | None
    protocol: str
    service: str
    srcuser: str
    status: str  # was "event_status": SUCCESS | FAILED | ALLOWED | BLOCKED
    domain: str
    command: str
    bytes_sent: int
    bytes_received: int


def parse_timestamp(raw: str) -> datetime:
    """Parse ``YYYY-MM-DD HH:MM:SS`` fast (fixed format, avoids strptime cost)."""
    # "2026-07-01 00:00:01"
    return datetime(
        int(raw[0:4]),
        int(raw[5:7]),
        int(raw[8:10]),
        int(raw[11:13]),
        int(raw[14:16]),
        int(raw[17:19]),
    )


# Wazuh rule level -> dashboard severity band (DESIGN section 6).
def level_to_severity(level: int) -> str:
    if level >= 14:
        return "CRITICAL"
    if level >= 12:
        return "HIGH"
    if level >= 10:
        return "MEDIUM"
    if level >= 5:
        return "LOW"
    return "INFO"


@dataclass(slots=True)
class Alert:
    """A finding, mirroring the Wazuh alert envelope (FR-13)."""

    rule_id: int
    level: int
    description: str
    mitre_ids: list[str]
    title: str
    entity: str
    first_seen: datetime
    last_seen: datetime
    data: dict[str, Any]
    evidence: dict[str, Any]
    sample_rows: list[str] = field(default_factory=list)
    status: str = "open"
    # Risk points assigned by risk.py (0-100). Populated after detection.
    risk_score: int = 0
    # Exact source-row ids this alert fired on. Used by the validator for
    # event-level scoring; intentionally NOT emitted in the report envelope.
    match_ids: set[str] = field(default_factory=set)

    @property
    def severity(self) -> str:
        return level_to_severity(self.level)

    def to_envelope(self) -> dict[str, Any]:
        """Render the Wazuh-style alert object used in the JSON report."""
        return {
            "rule": {
                "id": self.rule_id,
                "level": self.level,
                "description": self.description,
                "mitre": {"id": list(self.mitre_ids)},
            },
            "title": self.title,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "entity": self.entity,
            "first_seen": self.first_seen.isoformat(sep=" "),
            "last_seen": self.last_seen.isoformat(sep=" "),
            "data": self.data,
            "evidence": self.evidence,
            "sample_rows": self.sample_rows,
            "status": self.status,
        }
