"""Score detections against the held-out event_type labels (FR-15).

This module is the ONLY place event_type is read, and it is the scorer, never a
detector. The match rule (R-4), stated precisely and at EVENT granularity:

    Each fired alert carries the exact set of source-row ids it fired on
    (Alert.match_ids). A row is "flagged by rule R" iff its log_id is in the union
    of match_ids across R's alerts. For rule R with campaign label L:
        flagged & label == L    -> true positive
        flagged & label != L    -> false positive
        not flagged & label == L -> false negative

Event-level scoring is used (not entity+time-window) because a host-entity rule
like PowerShell must be judged on the command events it flagged, not on all the
benign traffic those hosts also generate. We report per-rule precision/recall/F1,
alert-level validity, and the naive "alert on any failed login" baseline. The
C2-port rule is reported but not scored: this dataset labels port 4444 traffic as
NETWORK_CONNECTION, so no ground-truth campaign label exists.
"""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path
from typing import Any

from .model import Alert

# rule_id -> (short name, held-out campaign label)
SCORED: dict[int, tuple[str, str]] = {
    100100: ("brute_force", "FAILED_LOGIN_BURST"),
    100200: ("port_scan", "PORT_SCAN"),
    100300: ("dns_tunnel", "DNS_TUNNELING"),
    100400: ("suspicious_domain", "SUSPICIOUS_DNS"),
    100500: ("powershell", "SUSPICIOUS_POWERSHELL"),
}
UNSCORED: dict[int, str] = {
    100600: (
        "c2_port traffic (port 4444) is labelled NETWORK_CONNECTION in this "
        "dataset; there is no ground-truth C2 campaign label, so it is reported "
        "but cannot be scored against event_type."
    ),
    100700: "No held-out campaign label is defined for the Sigma-derived Bitsadmin rule.",
    100710: "No held-out campaign label is defined for the Sigma-derived Certutil rule.",
}


def _prf(tp: int, fp: int, fn: int) -> dict[str, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}


def score_alerts(alerts: list[Alert], csv_path: str | Path) -> dict[str, Any]:
    flagged: dict[int, set[str]] = {rid: set() for rid in SCORED}
    alert_counts: dict[int, int] = {}
    for a in alerts:
        alert_counts[a.rule_id] = alert_counts.get(a.rule_id, 0) + 1
        if a.rule_id in flagged:
            flagged[a.rule_id] |= a.match_ids

    counts: dict[int, dict[str, int]] = {rid: {"tp": 0, "fp": 0, "fn": 0} for rid in SCORED}
    campaign_ids: dict[str, set[str]] = {label: set() for _, label in SCORED.values()}
    failed_total = 0
    failed_burst = 0
    label_counts: Counter[str] = Counter()

    with open(csv_path, encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        for row_number, row in enumerate(reader, start=1):
            label = (row.get("event_type") or "").strip()
            log_id = (row.get("log_id") or "").strip() or f"row-{row_number:09d}"
            status = (row.get("event_status") or row.get("status") or "").upper()
            label_counts[label] += 1
            if status == "FAILED":
                failed_total += 1
                if label == "FAILED_LOGIN_BURST":
                    failed_burst += 1
            if label in campaign_ids:
                campaign_ids[label].add(log_id)
            for rid, (_, campaign) in SCORED.items():
                if log_id in flagged[rid]:
                    if label == campaign:
                        counts[rid]["tp"] += 1
                    else:
                        counts[rid]["fp"] += 1
                elif label == campaign:
                    counts[rid]["fn"] += 1

    known_labels = {campaign for _, campaign in SCORED.values()}
    present_campaigns = known_labels & set(label_counts)
    per_rule: dict[str, Any] = {}
    tot = {"tp": 0, "fp": 0, "fn": 0}
    for rid, (name, campaign) in SCORED.items():
        if campaign not in present_campaigns:
            continue
        c = counts[rid]
        for k in tot:
            tot[k] += c[k]
        valid = sum(
            1 for a in alerts if a.rule_id == rid and a.match_ids & campaign_ids[campaign]
        )
        per_rule[name] = {
            "rule_id": rid,
            "campaign": campaign,
            **c,
            **_prf(c["tp"], c["fp"], c["fn"]),
            "alerts": alert_counts.get(rid, 0),
            "alerts_valid": valid,
        }

    if not present_campaigns:
        label_quality = "unsupported"
    elif len(present_campaigns) == len(SCORED):
        label_quality = "fully_scorable"
    else:
        label_quality = "partial"

    unscored = [
        {
            "rule_id": rid,
            "note": f"No {campaign} examples are present in this file, so this rule is N/A.",
            "alerts": alert_counts.get(rid, 0),
        }
        for rid, (_name, campaign) in SCORED.items()
        if campaign not in present_campaigns
    ]
    unscored.extend(
        {"rule_id": rid, "note": note, "alerts": alert_counts.get(rid, 0)}
        for rid, note in UNSCORED.items()
    )

    return {
        "label_audit": {
            "quality": label_quality,
            "scored_rules": len(per_rule),
            "known_campaigns_present": sorted(present_campaigns),
            "distinct_labels": len(label_counts),
        },
        "per_rule": per_rule,
        "overall": (
            {**tot, **_prf(tot["tp"], tot["fp"], tot["fn"])} if per_rule else None
        ),
        "naive_failed_login_baseline": {
            "precision": (
                round(failed_burst / failed_total, 4)
                if failed_total and "FAILED_LOGIN_BURST" in present_campaigns
                else None
            ),
            "note": (
                f"Alerting on any FAILED login would flag {failed_total} rows to catch "
                f"{failed_burst} real burst rows. The distributed detector avoids that."
            ),
        },
        "unscored": unscored,
    }
