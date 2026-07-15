"""Classic single-source brute force (Phase 7, rule 100110).

One source failing authentication against one host many times inside a short
window. Complements the distributed brute_force (100100), which needs 50+
distinct sources and so ignores a single noisy attacker.

Keys on the (source, destination) pair and counts failed attempts in a sliding
window. Each failed row is its own distinct value, so the distinct count is the
attempt count. Reads raw fields only; never the held-out label.
"""

from __future__ import annotations

from ..config import ClassicBruteForceConfig
from ..model import Alert, Event
from ..windows import SlidingDistinctWindow

RULE_ID = 100110


class ClassicBruteForceDetector:
    name = "classic_brute_force"

    def __init__(self, cfg: ClassicBruteForceConfig) -> None:
        self.cfg = cfg
        self.window = SlidingDistinctWindow(cfg.window_seconds, cfg.min_failures)

    def feed(self, event: Event) -> None:
        if event.status != "FAILED":
            return
        if not event.srcuser:
            return
        # value = log_id so every failed attempt is distinct; distinct == count.
        self.window.add(event.timestamp, (event.srcip, event.dstip), event.log_id, event.log_id)

    def finalize(self) -> list[Alert]:
        alerts: list[Alert] = []
        for hit in self.window.results():
            srcip, dstip = hit.key
            alerts.append(
                Alert(
                    rule_id=RULE_ID,
                    level=self.cfg.level,
                    description="Repeated failed authentication from one source",
                    mitre_ids=list(self.cfg.mitre),
                    title=f"Brute force from {srcip} against {dstip}",
                    entity=srcip,
                    first_seen=hit.first_seen,
                    last_seen=hit.last_seen,
                    data={"srcip": srcip, "dstip": dstip},
                    evidence={
                        "failed_attempts": hit.distinct,
                        "window_seconds": self.cfg.window_seconds,
                        "threshold_failed_attempts": self.cfg.min_failures,
                    },
                    sample_rows=hit.member_ids[:5],
                    match_ids=set(hit.member_ids),
                )
            )
        return alerts
