"""Lateral movement fan-out (Phase 7, rule 100130).

One source failing authentication against many distinct hosts on remote-service
ports (SMB 445, RDP 3389, WinRM 5985/5986) inside a window. This is the
credential-reuse sweep across a subnet that no destination-pivot rule can see,
because each destination is hit only a few times.

Keys on the source and counts distinct destination hosts in a sliding window.
Reads raw fields only.
"""

from __future__ import annotations

from ..config import LateralMovementConfig
from ..model import Alert, Event
from ..windows import SlidingDistinctWindow

RULE_ID = 100130


class LateralMovementDetector:
    name = "lateral_movement"

    def __init__(self, cfg: LateralMovementConfig) -> None:
        self.cfg = cfg
        self.ports = set(cfg.ports)
        self.window = SlidingDistinctWindow(cfg.window_seconds, cfg.min_hosts)

    def feed(self, event: Event) -> None:
        if event.status != "FAILED":
            return
        if event.dstport is None or event.dstport not in self.ports:
            return
        self.window.add(event.timestamp, event.srcip, event.dstip, event.log_id)

    def finalize(self) -> list[Alert]:
        alerts: list[Alert] = []
        for hit in self.window.results():
            srcip = hit.key
            alerts.append(
                Alert(
                    rule_id=RULE_ID,
                    level=self.cfg.level,
                    description="One source failing auth across many hosts on remote-service ports",
                    mitre_ids=list(self.cfg.mitre),
                    title=f"Lateral movement fan-out from {srcip}",
                    entity=str(srcip),
                    first_seen=hit.first_seen,
                    last_seen=hit.last_seen,
                    data={"srcip": srcip},
                    evidence={
                        "distinct_hosts": hit.distinct,
                        "hosts": [str(h) for h in hit.values[:20]],
                        "ports": sorted(self.ports),
                        "window_seconds": self.cfg.window_seconds,
                        "threshold_distinct_hosts": self.cfg.min_hosts,
                    },
                    sample_rows=hit.member_ids[:5],
                    match_ids=set(hit.member_ids),
                )
            )
        return alerts
