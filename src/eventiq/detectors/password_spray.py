"""Password spray (Phase 7, rule 100120).

Two spray shapes the distributed rules miss:

  A) One source failing across many distinct usernames inside a window (spraying
     a user list from a single host).
  B) Many sources failing one account across the whole file, in the band below
     the distributed threshold (min_sources..max_sources-1). Above max_sources it
     is the distributed campaign and rule 100100 owns it, so we do not
     double-report it.

Reads raw fields only.
"""

from __future__ import annotations

from datetime import datetime

from ..config import PasswordSprayConfig
from ..model import Alert, Event
from ..windows import SlidingDistinctWindow

RULE_ID = 100120


class _AccountState:
    __slots__ = ("sources", "ids", "first_seen", "last_seen")

    def __init__(self) -> None:
        self.sources: set[str] = set()
        self.ids: list[str] = []
        self.first_seen: datetime | None = None
        self.last_seen: datetime | None = None


class PasswordSprayDetector:
    name = "password_spray"

    def __init__(self, cfg: PasswordSprayConfig) -> None:
        self.cfg = cfg
        # Shape A: distinct usernames per source in a window.
        self.by_source = SlidingDistinctWindow(cfg.window_seconds, cfg.min_usernames)
        # Shape B: distinct sources per (dst, user) over the whole file.
        self.by_account: dict[tuple[str, str], _AccountState] = {}

    def feed(self, event: Event) -> None:
        if event.status != "FAILED" or not event.srcuser:
            return
        self.by_source.add(
            event.timestamp, (event.srcip, event.dstip), event.srcuser, event.log_id
        )
        acct = self.by_account.get((event.dstip, event.srcuser))
        if acct is None:
            acct = _AccountState()
            self.by_account[(event.dstip, event.srcuser)] = acct
        acct.sources.add(event.srcip)
        acct.ids.append(event.log_id)
        if acct.first_seen is None or event.timestamp < acct.first_seen:
            acct.first_seen = event.timestamp
        if acct.last_seen is None or event.timestamp > acct.last_seen:
            acct.last_seen = event.timestamp

    def finalize(self) -> list[Alert]:
        alerts: list[Alert] = []
        # Shape A
        for hit in self.by_source.results():
            srcip, dstip = hit.key
            alerts.append(
                Alert(
                    rule_id=RULE_ID,
                    level=self.cfg.level,
                    description="One source spraying many usernames at one host",
                    mitre_ids=list(self.cfg.mitre),
                    title=f"Password spray from {srcip} against {dstip}",
                    entity=srcip,
                    first_seen=hit.first_seen,
                    last_seen=hit.last_seen,
                    data={"srcip": srcip, "dstip": dstip, "shape": "source_to_many_users"},
                    evidence={
                        "distinct_usernames": hit.distinct,
                        "usernames": [str(u) for u in hit.values[:20]],
                        "window_seconds": self.cfg.window_seconds,
                        "threshold_distinct_usernames": self.cfg.min_usernames,
                    },
                    sample_rows=hit.member_ids[:5],
                    match_ids=set(hit.member_ids),
                )
            )
        # Shape B
        for (dstip, user), acct in self.by_account.items():
            n = len(acct.sources)
            if not (self.cfg.min_sources <= n < self.cfg.max_sources):
                continue
            assert acct.first_seen is not None and acct.last_seen is not None
            alerts.append(
                Alert(
                    rule_id=RULE_ID,
                    level=self.cfg.level,
                    description="Many sources failing one account (below distributed threshold)",
                    mitre_ids=list(self.cfg.mitre),
                    title=f"Password spray against account {user} on {dstip}",
                    entity=dstip,
                    first_seen=acct.first_seen,
                    last_seen=acct.last_seen,
                    data={"dstip": dstip, "username": user, "shape": "many_sources_one_user"},
                    evidence={
                        "distinct_sources": n,
                        "username": user,
                        "min_sources": self.cfg.min_sources,
                        "max_sources": self.cfg.max_sources,
                    },
                    sample_rows=acct.ids[:5],
                    match_ids=set(acct.ids),
                )
            )
        return alerts
