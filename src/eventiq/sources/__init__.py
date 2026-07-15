"""Event sources. The reader is pluggable behind a small protocol so a Polars
reader can drop in later without touching detection logic (Council verdict)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol

from ..model import Event


class EventSource(Protocol):
    """An iterable of raw-only Events that also reports parse statistics."""

    path: str
    rows: int
    malformed: int

    def __iter__(self) -> Iterator[Event]: ...


def get_source(engine: str, path: str, *, strict: bool = False) -> EventSource:
    """Return the reader for ``engine`` ('stdlib' default, 'polars' optional)."""
    if engine == "stdlib":
        from .csv_source import CsvSource

        return CsvSource(path, strict=strict)
    if engine == "polars":
        from .polars_source import PolarsSource

        return PolarsSource(path, strict=strict)
    raise ValueError(f"unknown engine: {engine!r}")
