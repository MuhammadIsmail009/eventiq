"""Streaming CSV reader (stdlib default). O(1) memory over the file.

Maps raw columns onto Wazuh-native field names (FR-2) and drops ``event_type``
and ``severity`` at parse time (PLAN section 2). Malformed rows are counted, not
crashed on (FR-3); ``strict=True`` turns the first malformed row into an error.
"""

from __future__ import annotations

import csv
from collections.abc import Iterator

from ..model import Event, parse_timestamp

# Raw CSV header -> Event attribute. The two held-out columns (event_type,
# severity) are intentionally not mapped, so they never reach an Event.
_COLUMN_MAP = {
    "log_id": "log_id",
    "timestamp": "timestamp",
    "source_ip": "srcip",
    "destination_ip": "dstip",
    "source_port": "srcport",
    "destination_port": "dstport",
    "protocol": "protocol",
    "service": "service",
    "username": "srcuser",
    "event_status": "status",
    "domain": "domain",
    "command": "command",
    "bytes_sent": "bytes_sent",
    "bytes_received": "bytes_received",
}

# Small, exact compatibility layer for common names in generated/reviewer CSVs.
# We deliberately do not guess broad schemas: an alias is accepted only when
# the canonical column is absent, and ambiguous files are rejected.
_ALIASES = {
    "destination_ip": "dest_ip",
    "username": "target_user",
    "event_status": "status",
}
_REQUIRED = {"timestamp", "source_ip", "destination_ip"}


class MalformedRowError(Exception):
    """Raised in strict mode when a row cannot be parsed."""


def _to_int_or_none(value: str) -> int | None:
    value = value.strip()
    if value == "":
        return None
    return int(value)


def _to_int(value: str) -> int:
    value = value.strip()
    if value == "":
        return 0
    return int(value)


class CsvSource:
    """Iterable event source over a single CSV file."""

    def __init__(self, path: str, *, strict: bool = False) -> None:
        self.path = path
        self.strict = strict
        self.rows = 0
        self.malformed = 0
        self.missing_optional: list[str] = []

    def __iter__(self) -> Iterator[Event]:
        with open(self.path, encoding="utf-8-sig", newline="") as fh:
            reader = csv.reader(fh)
            try:
                header = next(reader)
            except StopIteration:
                return
            raw_idx = {name.strip(): i for i, name in enumerate(header)}
            idx: dict[str, int] = {}
            for canonical in _COLUMN_MAP:
                alias = _ALIASES.get(canonical)
                if canonical in raw_idx and alias and alias in raw_idx:
                    raise MalformedRowError(
                        f"CSV has both {canonical!r} and alias {alias!r}; remove one"
                    )
                if canonical in raw_idx:
                    idx[canonical] = raw_idx[canonical]
                elif alias and alias in raw_idx:
                    idx[canonical] = raw_idx[alias]
            missing = _REQUIRED - set(idx)
            if missing:
                raise MalformedRowError(
                    f"CSV missing required column(s): {', '.join(sorted(missing))}"
                )
            self.missing_optional = sorted(set(_COLUMN_MAP) - set(idx))
            for raw in reader:
                self.rows += 1
                try:
                    yield self._to_event(raw, idx, self.rows)
                except (ValueError, IndexError) as exc:
                    self.malformed += 1
                    if self.strict:
                        raise MalformedRowError(
                            f"malformed row {self.rows}: {exc}"
                        ) from exc

    @staticmethod
    def _to_event(raw: list[str], idx: dict[str, int], row_number: int) -> Event:
        def value(name: str) -> str:
            return raw[idx[name]] if name in idx else ""

        log_id = raw[idx["log_id"]].strip() if "log_id" in idx else ""
        return Event(
            log_id=log_id or f"row-{row_number:09d}",
            timestamp=parse_timestamp(raw[idx["timestamp"]]),
            srcip=raw[idx["source_ip"]],
            dstip=raw[idx["destination_ip"]],
            srcport=(
                _to_int_or_none(raw[idx["source_port"]])
                if "source_port" in idx
                else None
            ),
            dstport=_to_int_or_none(value("destination_port")),
            protocol=value("protocol"),
            service=value("service"),
            srcuser=value("username"),
            status=value("event_status").upper(),
            domain=value("domain"),
            command=value("command"),
            bytes_sent=_to_int(value("bytes_sent")),
            bytes_received=_to_int(value("bytes_received")),
        )
