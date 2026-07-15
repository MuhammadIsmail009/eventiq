"""Single-pass analysis orchestration.

Streams events from a source through every detector, tracking input statistics
(row count, malformed count, time span) as it goes. Memory is a function of
detector window state and active entities, not input size (NFR-1).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .detectors import Detector
from .model import Alert
from .overview import StreamProfiler
from .sources import EventSource


@dataclass(slots=True)
class InputStats:
    file: str
    rows: int
    malformed: int
    span_start: datetime | None
    span_end: datetime | None
    missing_optional: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AnalysisResult:
    alerts: list[Alert]
    stats: InputStats
    overview: dict[str, Any] = field(default_factory=dict)


def run_analysis(source: EventSource, detectors: list[Detector]) -> AnalysisResult:
    span_start: datetime | None = None
    span_end: datetime | None = None
    profiler = StreamProfiler()
    for event in source:
        ts = event.timestamp
        if span_start is None or ts < span_start:
            span_start = ts
        if span_end is None or ts > span_end:
            span_end = ts
        profiler.observe(event)
        for det in detectors:
            det.feed(event)
    alerts: list[Alert] = []
    for det in detectors:
        alerts.extend(det.finalize())
    stats = InputStats(
        file=source.path,
        rows=source.rows,
        malformed=source.malformed,
        span_start=span_start,
        span_end=span_end,
        missing_optional=list(getattr(source, "missing_optional", [])),
    )
    return AnalysisResult(alerts=alerts, stats=stats, overview=profiler.result())
