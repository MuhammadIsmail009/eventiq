"""Classic single-source port scan (Phase 7, rule 100210).

One source touching many distinct ports of one host inside a short window, any
connection status. This is the textbook horizontal/vertical scan that the
distributed port_scan (100200) misses, because that rule needs 50+ refused
sources converging on a host and a lone scanner never reaches it.

Keys on the (source, destination) pair and counts distinct destination ports in
a sliding window. Reads raw fields only.
"""

from __future__ import annotations

from ..config import ClassicPortScanConfig
from ..model import Alert, Event
from ..windows import SlidingDistinctWindow

RULE_ID = 100210


class ClassicPortScanDetector:
    name = "classic_port_scan"

    def __init__(self, cfg: ClassicPortScanConfig) -> None:
        self.cfg = cfg
        self.window = SlidingDistinctWindow(cfg.window_seconds, cfg.min_ports)

    def feed(self, event: Event) -> None:
        if event.dstport is None:
            return
        self.window.add(event.timestamp, (event.srcip, event.dstip), event.dstport, event.log_id)

    def finalize(self) -> list[Alert]:
        alerts: list[Alert] = []
        for hit in self.window.results():
            srcip, dstip = hit.key
            alerts.append(
                Alert(
                    rule_id=RULE_ID,
                    level=self.cfg.level,
                    description="Single source scanning many ports of one host",
                    mitre_ids=list(self.cfg.mitre),
                    title=f"Port scan from {srcip} against {dstip}",
                    entity=srcip,
                    first_seen=hit.first_seen,
                    last_seen=hit.last_seen,
                    data={"srcip": srcip, "dstip": dstip},
                    evidence={
                        "distinct_ports": hit.distinct,
                        "ports": hit.values[:20],
                        "window_seconds": self.cfg.window_seconds,
                        "threshold_distinct_ports": self.cfg.min_ports,
                    },
                    sample_rows=hit.member_ids[:5],
                    match_ids=set(hit.member_ids),
                )
            )
        return alerts
