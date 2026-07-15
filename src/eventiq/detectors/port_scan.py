"""Distributed port scan detection (FR-4).

Pivots on the destination: a host that many distinct sources converge on, across
many ports, with a high refusal rate. This catches a scan spread across thousands
of throwaway source IPs (a botnet or proxy-rotating scanner), which the textbook
"one source hits N ports" rule misses entirely on this data.
"""

from __future__ import annotations

from ..config import PortScanConfig
from ..model import Alert, Event
from ..windows import ConvergenceTracker

RULE_ID = 100200


class PortScanDetector:
    name = "port_scan"

    def __init__(self, cfg: PortScanConfig) -> None:
        self.cfg = cfg
        self.refused = set(cfg.refused_statuses)
        self.tracker = ConvergenceTracker()

    def feed(self, event: Event) -> None:
        # Track only refused connection attempts. That is the scan signature and
        # it bounds memory to the handful of hosts that receive refused traffic,
        # instead of every destination in the file.
        if event.status not in self.refused:
            return
        self.tracker.observe(event.dstip, event)

    def finalize(self) -> list[Alert]:
        alerts: list[Alert] = []
        for dstip, g in self.tracker.items():
            if len(g.sources) < self.cfg.min_distinct_sources:
                continue
            if len(g.dstports) < self.cfg.min_distinct_ports:
                continue
            assert g.first_seen is not None and g.last_seen is not None
            alerts.append(
                Alert(
                    rule_id=RULE_ID,
                    level=self.cfg.level,
                    description="Distributed port scan converging on a single host",
                    mitre_ids=list(self.cfg.mitre),
                    title=f"Distributed port scan against {dstip}",
                    entity=dstip,
                    first_seen=g.first_seen,
                    last_seen=g.last_seen,
                    data={"dstip": dstip, "protocol": g.protocol},
                    evidence={
                        "distinct_sources": len(g.sources),
                        "distinct_subnets_24": len(g.subnets24),
                        "distinct_ports": len(g.dstports),
                        "refused_events": g.count,
                        "zero_bytes_back": g.zero_bytes_back,
                        "threshold_distinct_sources": self.cfg.min_distinct_sources,
                    },
                    sample_rows=g.sample_rows,
                    match_ids=set(g.ids),
                )
            )
        return alerts
