"""Distributed brute force / password spray detection (FR-5).

Pivots on the destination host and username set: a host receiving failed
authentication from an anomalous number of distinct sources. This separates the
real distributed campaign (15,926 sources onto one host) from the tens of
thousands of scattered background failed logins (benign max: 28 sources on any
one host), which a naive "any failed login" rule cannot do.
"""

from __future__ import annotations

from ..config import BruteForceConfig
from ..model import Alert, Event
from ..windows import ConvergenceTracker

RULE_ID = 100100


class BruteForceDetector:
    name = "brute_force"

    def __init__(self, cfg: BruteForceConfig) -> None:
        self.cfg = cfg
        self.services = {s.lower() for s in cfg.services}
        self.ports = set(cfg.ports)
        self.tracker = ConvergenceTracker()

    def _is_auth(self, event: Event) -> bool:
        if event.service and event.service.lower() in self.services:
            return True
        return event.dstport is not None and event.dstport in self.ports

    def feed(self, event: Event) -> None:
        if event.status != "FAILED":
            return
        if not self._is_auth(event):
            return
        self.tracker.observe(event.dstip, event)

    def finalize(self) -> list[Alert]:
        alerts: list[Alert] = []
        for dstip, g in self.tracker.items():
            if len(g.sources) < self.cfg.min_distinct_sources:
                continue
            assert g.first_seen is not None and g.last_seen is not None
            alerts.append(
                Alert(
                    rule_id=RULE_ID,
                    level=self.cfg.level,
                    description="Distributed brute force / password spray on auth service",
                    mitre_ids=list(self.cfg.mitre),
                    title=f"Distributed brute force against {dstip}",
                    entity=dstip,
                    first_seen=g.first_seen,
                    last_seen=g.last_seen,
                    data={
                        "dstip": dstip,
                        "services": sorted(g.services),
                        "ports": sorted(g.dstports),
                    },
                    evidence={
                        "distinct_sources": len(g.sources),
                        "distinct_subnets_24": len(g.subnets24),
                        "failed_events": g.count,
                        "top_usernames": g.top_usernames(),
                        "threshold_distinct_sources": self.cfg.min_distinct_sources,
                    },
                    sample_rows=g.sample_rows,
                    match_ids=set(g.ids),
                )
            )
        return alerts
