"""DNS tunneling detection (FR-6).

Not entropy alone (R-3). A parent domain fires only when it carries subdomains
that are simultaneously high-entropy, long-labelled, AND numerous-and-unique.
The tunneling channel here shows 54-character random labels under one parent with
thousands of unique subdomains; the benign domains and the static suspicious
domains fail at least one of the three tests.
"""

from __future__ import annotations

import math
from collections import Counter
from datetime import datetime

from ..config import DnsTunnelConfig
from ..model import Alert, Event

RULE_ID = 100300


def shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of a string. Empty string is 0.0."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _parent_domain(domain: str) -> str:
    labels = domain.split(".")
    if len(labels) <= 2:
        return domain
    return ".".join(labels[-2:])


class _ParentStats:
    __slots__ = (
        "subdomains",
        "max_entropy",
        "max_label_len",
        "count",
        "first_seen",
        "last_seen",
        "ids",
        "srcips",
    )

    def __init__(self) -> None:
        self.subdomains: set[str] = set()
        self.max_entropy = 0.0
        self.max_label_len = 0
        self.count = 0
        self.first_seen: datetime | None = None
        self.last_seen: datetime | None = None
        self.ids: list[str] = []
        self.srcips: set[str] = set()


class DnsTunnelDetector:
    name = "dns_tunnel"

    def __init__(self, cfg: DnsTunnelConfig) -> None:
        self.cfg = cfg
        self.allow = {d.lower() for d in cfg.allowlist}
        self.parents: dict[str, _ParentStats] = {}

    def feed(self, event: Event) -> None:
        domain = event.domain
        if not domain:
            return
        parent = _parent_domain(domain.lower())
        if parent in self.allow:
            return
        labels = domain.split(".")
        longest_label = max(labels, key=len) if labels else ""
        longest = len(longest_label)
        entropy = shannon_entropy(longest_label)

        # A row becomes evidence only when the same label satisfies both
        # conditions. This prevents one long, low-entropy row and a different
        # short, high-entropy row from combining into a false campaign. It also
        # keeps benign sibling queries out of match_ids when a parent fires.
        if longest < self.cfg.min_label_len or entropy < self.cfg.min_entropy:
            return

        stats = self.parents.get(parent)
        if stats is None:
            stats = _ParentStats()
            self.parents[parent] = stats
        stats.subdomains.add(domain.lower())
        stats.count += 1
        stats.srcips.add(event.srcip)
        stats.max_entropy = max(stats.max_entropy, entropy)
        stats.max_label_len = max(stats.max_label_len, longest)
        if stats.first_seen is None or event.timestamp < stats.first_seen:
            stats.first_seen = event.timestamp
        if stats.last_seen is None or event.timestamp > stats.last_seen:
            stats.last_seen = event.timestamp
        stats.ids.append(event.log_id)

    def finalize(self) -> list[Alert]:
        alerts: list[Alert] = []
        for parent, s in self.parents.items():
            if len(s.subdomains) < self.cfg.min_query_count:
                continue
            assert s.first_seen is not None and s.last_seen is not None
            alerts.append(
                Alert(
                    rule_id=RULE_ID,
                    level=self.cfg.level,
                    description="DNS tunneling: high-entropy long-label subdomains at volume",
                    mitre_ids=list(self.cfg.mitre),
                    title=f"DNS tunneling via {parent}",
                    entity=parent,
                    first_seen=s.first_seen,
                    last_seen=s.last_seen,
                    data={"parent_domain": parent},
                    evidence={
                        "unique_subdomains": len(s.subdomains),
                        "max_entropy": round(s.max_entropy, 3),
                        "max_label_len": s.max_label_len,
                        "queries": s.count,
                        "distinct_srcips": len(s.srcips),
                        "thresholds": {
                            "min_entropy": self.cfg.min_entropy,
                            "min_label_len": self.cfg.min_label_len,
                            "min_unique_subdomains": self.cfg.min_query_count,
                        },
                    },
                    sample_rows=s.ids[:5],
                    match_ids=set(s.ids),
                )
            )
        return alerts
