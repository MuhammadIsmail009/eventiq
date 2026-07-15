"""Optional Polars-backed reader (could-have). Behind ``--engine polars``.

Kept behind the same EventSource interface so detection logic never forks. Only
imported when selected, so the base install does not need polars.
"""

from __future__ import annotations

from collections.abc import Iterator

from ..model import Event, parse_timestamp
from .csv_source import _to_int, _to_int_or_none


class PolarsSource:
    def __init__(self, path: str, *, strict: bool = False) -> None:
        self.path = path
        self.strict = strict
        self.rows = 0
        self.malformed = 0

    def __iter__(self) -> Iterator[Event]:
        import polars as pl

        frame = pl.read_csv(self.path, infer_schema_length=0)
        for record in frame.iter_rows(named=True):
            self.rows += 1
            try:
                yield Event(
                    log_id=record["log_id"],
                    timestamp=parse_timestamp(record["timestamp"]),
                    srcip=record["source_ip"],
                    dstip=record["destination_ip"],
                    srcport=_to_int_or_none(record["source_port"]),
                    dstport=_to_int_or_none(record["destination_port"]),
                    protocol=record["protocol"],
                    service=record["service"],
                    srcuser=record["username"],
                    status=record["event_status"],
                    domain=record["domain"],
                    command=record["command"],
                    bytes_sent=_to_int(record["bytes_sent"]),
                    bytes_received=_to_int(record["bytes_received"]),
                )
            except (ValueError, KeyError) as exc:
                self.malformed += 1
                if self.strict:
                    raise ValueError(f"malformed row {self.rows}: {exc}") from exc
