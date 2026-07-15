"""Convergence tracking primitive for the distributed detectors.

Design note (data-driven, PLAN section 4 corrected against the file): the port
scan and brute force in this dataset are distributed across sources AND spread
uniformly across 35 days (the off-hours trap). A short sliding window therefore
accumulates only ~2 events and never crosses a distinct-source threshold. The
correct primitive for batch analysis is per-destination convergence over the
whole pass: how many distinct sources, subnets and ports converge on one host,
and with what refusal rate.

For a streaming deployment this is the seam where a large fixed time bucket (or
a HyperLogLog distinct-counter at 100x scale) would slot in. See the SCALING
note in the README.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Hashable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .model import Event

MAX_SAMPLES = 5


def subnet_24(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


@dataclass(slots=True)
class ConvergenceGroup:
    """Distinct-source convergence stats for one destination host.

    Holds no Event objects (memory): only the scalar fields the detectors need,
    plus the ids of the rows that contributed, so the validator can score at the
    event level.
    """

    count: int = 0
    blocked: int = 0
    zero_bytes_back: int = 0
    protocol: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sources: set[str] = field(default_factory=set)
    subnets24: set[str] = field(default_factory=set)
    dstports: set[int] = field(default_factory=set)
    usernames: dict[str, int] = field(default_factory=dict)
    services: set[str] = field(default_factory=set)
    ids: list[str] = field(default_factory=list)

    def observe(self, event: Event) -> None:
        self.count += 1
        if event.status == "BLOCKED":
            self.blocked += 1
        if event.bytes_received == 0:
            self.zero_bytes_back += 1
        if not self.protocol:
            self.protocol = event.protocol
        if self.first_seen is None or event.timestamp < self.first_seen:
            self.first_seen = event.timestamp
        if self.last_seen is None or event.timestamp > self.last_seen:
            self.last_seen = event.timestamp
        self.sources.add(event.srcip)
        self.subnets24.add(subnet_24(event.srcip))
        if event.dstport is not None:
            self.dstports.add(event.dstport)
        if event.service:
            self.services.add(event.service)
        if event.srcuser:
            self.usernames[event.srcuser] = self.usernames.get(event.srcuser, 0) + 1
        self.ids.append(event.log_id)

    @property
    def blocked_frac(self) -> float:
        return self.blocked / self.count if self.count else 0.0

    @property
    def sample_rows(self) -> list[str]:
        return self.ids[:MAX_SAMPLES]

    def top_usernames(self, n: int = 5) -> list[str]:
        return [u for u, _ in sorted(self.usernames.items(), key=lambda kv: (-kv[1], kv[0]))[:n]]


class ConvergenceTracker:
    """Maps destination host -> ConvergenceGroup, populated during the stream."""

    def __init__(self) -> None:
        self.groups: dict[str, ConvergenceGroup] = {}

    def observe(self, dstip: str, event: Event) -> None:
        group = self.groups.get(dstip)
        if group is None:
            group = ConvergenceGroup()
            self.groups[dstip] = group
        group.observe(event)

    def items(self) -> list[tuple[str, ConvergenceGroup]]:
        return list(self.groups.items())


# --- Classic single-source detection primitive (Phase 7) -------------------
#
# The distributed detectors above pivot on a destination that thousands of
# sources converge on. The classic attack shapes (one source, one short burst)
# are the opposite: they are invisible over a 35-day batch but obvious inside a
# few minutes. The right primitive for them is a sliding time window that counts
# distinct values per key (distinct ports scanned, distinct usernames sprayed,
# distinct hosts reached) and fires when the count crosses a threshold.
#
# Memory: a global time-ordered eviction deque holds only the events inside the
# current window, so peak memory is bounded to one window's worth of traffic, not
# the whole file. This assumes events arrive in time order, which real security
# logs do (the 1M reference file is 100% time-sorted).


@dataclass(slots=True)
class WindowHit:
    """One key that crossed the distinct-count threshold, with its evidence."""

    key: Any
    distinct: int
    values: list[Any]
    member_ids: list[str]
    first_seen: datetime
    last_seen: datetime


@dataclass(slots=True)
class _KeyState:
    counts: dict[Any, int] = field(default_factory=dict)
    ids: deque[str] = field(default_factory=deque)
    tss: deque[datetime] = field(default_factory=deque)

    def add(self, value: Any, rowid: str, ts: datetime) -> None:
        self.counts[value] = self.counts.get(value, 0) + 1
        self.ids.append(rowid)
        self.tss.append(ts)

    def evict_oldest(self, value: Any) -> None:
        n = self.counts.get(value, 0)
        if n <= 1:
            self.counts.pop(value, None)
        else:
            self.counts[value] = n - 1
        if self.ids:
            self.ids.popleft()
        if self.tss:
            self.tss.popleft()

    def empty(self) -> bool:
        return not self.counts


class SlidingDistinctWindow:
    """Counts distinct values per key inside a sliding time window.

    Feed ``(ts, key, value, rowid)`` in time order. When a key holds at least
    ``threshold`` distinct values within ``window_seconds``, the peak window is
    recorded and returned by :meth:`results`. Each key fires at most once (the
    peak window is kept). Memory is bounded to events inside the live window.
    """

    def __init__(self, window_seconds: int, threshold: int) -> None:
        self.window = window_seconds
        self.threshold = threshold
        self._global: deque[tuple[int, Hashable, Any]] = deque()
        self._keys: dict[Hashable, _KeyState] = {}
        self._results: dict[Hashable, WindowHit] = {}

    def add(self, ts: datetime, key: Hashable, value: Any, rowid: str) -> None:
        epoch = int(ts.timestamp())
        g = self._global
        horizon = epoch - self.window
        while g and g[0][0] <= horizon:
            _, ok, ov = g.popleft()
            ks = self._keys.get(ok)
            if ks is not None:
                ks.evict_oldest(ov)
                if ks.empty():
                    del self._keys[ok]
        ks = self._keys.get(key)
        if ks is None:
            ks = _KeyState()
            self._keys[key] = ks
        ks.add(value, rowid, ts)
        g.append((epoch, key, value))
        distinct = len(ks.counts)
        if distinct >= self.threshold:
            prev = self._results.get(key)
            if prev is None or distinct > prev.distinct:
                self._results[key] = WindowHit(
                    key=key,
                    distinct=distinct,
                    values=sorted(ks.counts, key=str),
                    member_ids=list(ks.ids),
                    first_seen=ks.tss[0],
                    last_seen=ks.tss[-1],
                )

    def results(self) -> list[WindowHit]:
        return list(self._results.values())
