"""C2 indicator by destination port (FR-9).

Connections to a known command-and-control port (default 4444, the Metasploit
handler default). Aggregated into ONE finding per IOC port, because emitting one
alert per external destination produced tens of thousands of rows and buried the
signal. The finding rolls up the internal hosts talking out and the external
destinations they reached, with top talkers ranked. Reads raw fields only.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime

from ..config import C2PortConfig
from ..model import Alert, Event

RULE_ID = 100600


class _PortStats:
    __slots__ = ("count", "srcips", "dstips", "services", "first_seen", "last_seen", "ids")

    def __init__(self) -> None:
        self.count = 0
        self.srcips: Counter[str] = Counter()
        self.dstips: Counter[str] = Counter()
        self.services: set[str] = set()
        self.first_seen: datetime | None = None
        self.last_seen: datetime | None = None
        self.ids: list[str] = []

    def observe(self, event: Event) -> None:
        self.count += 1
        self.srcips[event.srcip] += 1
        self.dstips[event.dstip] += 1
        if event.service:
            self.services.add(event.service)
        if self.first_seen is None or event.timestamp < self.first_seen:
            self.first_seen = event.timestamp
        if self.last_seen is None or event.timestamp > self.last_seen:
            self.last_seen = event.timestamp
        self.ids.append(event.log_id)


def _top(counter: Counter[str], n: int = 10) -> list[str]:
    return [f"{ip} ({c})" for ip, c in counter.most_common(n)]


class C2PortDetector:
    name = "c2_port"

    def __init__(self, cfg: C2PortConfig) -> None:
        self.cfg = cfg
        self.ports = set(cfg.ioc_ports)
        self.by_port: dict[int, _PortStats] = {}

    def feed(self, event: Event) -> None:
        if event.dstport is None or event.dstport not in self.ports:
            return
        stats = self.by_port.get(event.dstport)
        if stats is None:
            stats = _PortStats()
            self.by_port[event.dstport] = stats
        stats.observe(event)

    def finalize(self) -> list[Alert]:
        alerts: list[Alert] = []
        for port, s in self.by_port.items():
            assert s.first_seen is not None and s.last_seen is not None
            alerts.append(
                Alert(
                    rule_id=RULE_ID,
                    level=self.cfg.level,
                    description="Traffic to known command-and-control port",
                    mitre_ids=list(self.cfg.mitre),
                    title=f"C2 indicator: traffic to port {port}",
                    entity=f"c2-port-{port}",
                    first_seen=s.first_seen,
                    last_seen=s.last_seen,
                    data={
                        "ioc_port": port,
                        "services": sorted(s.services),
                        "top_internal_hosts": _top(s.srcips),
                        "top_external_dsts": _top(s.dstips),
                    },
                    evidence={
                        "event_count": s.count,
                        "distinct_srcips": len(s.srcips),
                        "distinct_dstips": len(s.dstips),
                        "ioc_port": port,
                    },
                    sample_rows=s.ids[:5],
                    match_ids=set(s.ids),
                )
            )
        return alerts
