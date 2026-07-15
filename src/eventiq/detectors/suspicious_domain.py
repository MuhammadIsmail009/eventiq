"""Suspicious domain detection (FR-7).

A configurable indicator list (threat intel), plus a conservative bad-TLD
heuristic as a secondary net. Indicator lists in config are not "hardcoded
attack constants" in detection logic (NFR-5): they are exactly how a SOC feeds
threat intel to a rule.
"""

from __future__ import annotations

from datetime import datetime

from ..config import SuspiciousDomainConfig
from ..model import Alert, Event

RULE_ID = 100400


class _DomainStats:
    __slots__ = ("count", "srcips", "first_seen", "last_seen", "ids", "reason")

    def __init__(self, reason: str) -> None:
        self.count = 0
        self.srcips: set[str] = set()
        self.first_seen: datetime | None = None
        self.last_seen: datetime | None = None
        self.ids: list[str] = []
        self.reason = reason


class SuspiciousDomainDetector:
    name = "suspicious_domain"

    def __init__(self, cfg: SuspiciousDomainConfig) -> None:
        self.cfg = cfg
        self.iocs = {d.lower() for d in cfg.iocs}
        self.bad_tlds = {t.lower().lstrip(".") for t in cfg.bad_tlds}
        self.domains: dict[str, _DomainStats] = {}

    def _match(self, domain: str) -> str | None:
        if domain in self.iocs:
            return "ioc_list"
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        if tld in self.bad_tlds:
            return f"bad_tld:{tld}"
        return None

    def feed(self, event: Event) -> None:
        if not event.domain:
            return
        domain = event.domain.lower()
        reason = self._match(domain)
        if reason is None:
            return
        stats = self.domains.get(domain)
        if stats is None:
            stats = _DomainStats(reason)
            self.domains[domain] = stats
        stats.count += 1
        stats.srcips.add(event.srcip)
        if stats.first_seen is None or event.timestamp < stats.first_seen:
            stats.first_seen = event.timestamp
        if stats.last_seen is None or event.timestamp > stats.last_seen:
            stats.last_seen = event.timestamp
        stats.ids.append(event.log_id)

    def finalize(self) -> list[Alert]:
        alerts: list[Alert] = []
        for domain, s in self.domains.items():
            assert s.first_seen is not None and s.last_seen is not None
            tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
            alerts.append(
                Alert(
                    rule_id=RULE_ID,
                    level=self.cfg.level,
                    description="Connection to known-suspicious domain",
                    mitre_ids=list(self.cfg.mitre),
                    title=f"Suspicious domain {domain}",
                    entity=domain,
                    first_seen=s.first_seen,
                    last_seen=s.last_seen,
                    data={"domain": domain, "tld": tld},
                    evidence={
                        "matched": s.reason,
                        "queries": s.count,
                        "distinct_srcips": len(s.srcips),
                    },
                    sample_rows=s.ids[:5],
                    match_ids=set(s.ids),
                )
            )
        return alerts
