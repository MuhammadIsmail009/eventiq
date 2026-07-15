"""Whole-file characterisation from raw fields only (no held-out labels).

Runs alongside detection in the single pass and answers "what is in this file":
how much traffic, of what protocols and statuses, to and from whom. This is the
descriptive layer the dashboard leads with, so a reader understands the logs
before the findings. It never reads event_type or severity.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .model import Event


@dataclass(slots=True)
class StreamProfiler:
    total: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    protocol: Counter[str] = field(default_factory=Counter)
    status: Counter[str] = field(default_factory=Counter)
    service: Counter[str] = field(default_factory=Counter)
    src: Counter[str] = field(default_factory=Counter)
    dst: Counter[str] = field(default_factory=Counter)
    user: Counter[str] = field(default_factory=Counter)
    domain: Counter[str] = field(default_factory=Counter)
    dstport: Counter[int] = field(default_factory=Counter)
    day: Counter[str] = field(default_factory=Counter)

    def observe(self, event: Event) -> None:
        self.total += 1
        self.bytes_sent += event.bytes_sent
        self.bytes_received += event.bytes_received
        self.protocol[event.protocol] += 1
        self.status[event.status] += 1
        if event.service:
            self.service[event.service] += 1
        self.src[event.srcip] += 1
        self.dst[event.dstip] += 1
        if event.srcuser:
            self.user[event.srcuser] += 1
        if event.domain:
            self.domain[event.domain] += 1
        if event.dstport is not None:
            self.dstport[event.dstport] += 1
        ts = event.timestamp
        self.day[f"{ts.year:04d}-{ts.month:02d}-{ts.day:02d}"] += 1

    def result(self) -> dict[str, Any]:
        return {
            "total_events": self.total,
            "distinct": {
                "source_ips": len(self.src),
                "destination_ips": len(self.dst),
                "usernames": len(self.user),
                "domains": len(self.domain),
                "services": len(self.service),
            },
            "protocol": dict(self.protocol.most_common()),
            "status": dict(self.status.most_common()),
            "top_services": self.service.most_common(8),
            "top_source_ips": self.src.most_common(8),
            "top_destination_ips": self.dst.most_common(8),
            "top_usernames": self.user.most_common(8),
            "top_domains": self.domain.most_common(6),
            "top_dstports": [[str(p), n] for p, n in self.dstport.most_common(8)],
            "daily_volume": [[d, n] for d, n in sorted(self.day.items())],
            "bytes": {"sent": self.bytes_sent, "received": self.bytes_received},
        }
