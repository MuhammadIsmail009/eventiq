"""HTML dashboard: renders, is self-contained, and is XSS-safe (R-5)."""

from __future__ import annotations

from typing import Any

from eventiq.render import build_html

_BASE: dict[str, Any] = {
    "generated_at": "2026-07-14 00:00:00",
    "input": {"file": "logs.csv", "rows": 1000000, "malformed": 0,
              "span_start": "2026-07-01 00:00:01", "span_end": "2026-08-04 17:00:00"},
    "summary": {"by_severity": {"HIGH": 5, "MEDIUM": 1}, "distinct_rules": [100100, 100200],
                "alert_count": 2481, "incident_count": 6, "entities_at_risk": 2481,
                "flagged_events": 79526, "benign_events": 920474},
    "overview": {
        "total_events": 1000000, "flagged_events": 79526, "benign_events": 920474,
        "flagged_pct": 7.95,
        "distinct": {"source_ips": 50000, "destination_ips": 423000, "usernames": 16,
                     "domains": 5060, "services": 23},
        "protocol": {"TCP": 719860, "UDP": 250112, "ICMP": 30028},
        "status": {"SUCCESS": 911199, "FAILED": 53812, "BLOCKED": 16842, "ALLOWED": 18147},
        "top_services": [["DNS", 159342], ["HTTP", 80000]],
        "top_source_ips": [["203.0.0.1", 5]],
        "top_destination_ips": [["10.10.20.15", 24925], ["172.16.10.25", 16848]],
        "top_usernames": [["admin", 8389]], "top_domains": [["github.com", 30]],
        "top_dstports": [["53", 159342]],
        "daily_volume": [["2026-07-01", 28000], ["2026-07-02", 28500]],
        "bytes": {"sent": 1, "received": 1},
    },
    "categories": [
        {"rule_id": 100600, "category": "C2 indicator", "basis": "known C2 port",
         "severity": "HIGH", "events": 19614, "alerts": 1, "mitre": ["T1571"]},
        {"rule_id": 100100, "category": "Brute force / password spray",
         "basis": "many sources one host", "severity": "HIGH", "events": 24923,
         "alerts": 1, "mitre": ["T1110.003"]},
    ],
    "incidents": [{
        "id": "INC-0001", "title": "t", "category": "Brute force / password spray",
        "basis": "Many distinct sources failing authentication on one host",
        "primary_entity": "10.10.20.15", "severity": "HIGH",
        "risk_score": 70, "techniques": ["T1110.003"], "first_seen": "2026-07-01 00:00:00",
        "last_seen": "2026-08-04 00:00:00", "alert_count": 1, "event_count": 24923,
        "affected_count": 1, "affected_entities": ["10.10.20.15"],
        "narrative": "Distributed brute force against 10.10.20.15.",
    }],
    "entity_risk": [{"entity": "10.10.20.15", "risk_score": 70, "severity": "HIGH",
                     "contributing_rules": [100100], "techniques": ["T1110.003"],
                     "alert_count": 1}],
    "alerts": [{"first_seen": "2026-07-01 00:00:00", "severity": "HIGH"}],
    "not_detected": [{"name": "exfiltration_by_volume", "reason": "uniform noise",
                      "numbers": "~3.5 MB"}],
    "validation": {
        "per_rule": {"brute_force": {"rule_id": 100100, "campaign": "X", "tp": 24923, "fp": 0,
                                     "fn": 0, "precision": 1.0, "recall": 1.0, "f1": 1.0,
                                     "alerts": 1, "alerts_valid": 1}},
        "overall": {"tp": 24923, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0, "f1": 1.0},
        "naive_failed_login_baseline": {"precision": 0.463, "note": "n"},
        "unscored": [],
    },
}


def test_renders_self_contained() -> None:
    html = build_html(_BASE)
    assert html.strip().startswith("<!doctype html>")
    assert "INC-0001" in html and "10.10.20.15" in html
    assert "Analysis trust and coverage" in html
    assert "No rule match" in html
    # no external requests: no http(s) links to remote hosts, no CDN
    lowered = html.lower()
    for needle in ("http://", "https://", "cdn.", "googleapis", "<link", "src="):
        assert needle not in lowered, f"external reference found: {needle}"


def test_xss_from_log_content_is_escaped() -> None:
    evil = dict(_BASE)
    evil["incidents"] = [dict(_BASE["incidents"][0])]
    evil["incidents"][0]["narrative"] = "<script>alert('xss')</script>"
    evil["incidents"][0]["primary_entity"] = "<img src=x onerror=alert(1)>"
    evil["entity_risk"] = [dict(_BASE["entity_risk"][0])]
    evil["entity_risk"][0]["entity"] = "<script>bad()</script>"
    html = build_html(evil)
    # the raw executable strings must not appear unescaped anywhere
    assert "<script>alert('xss')</script>" not in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;script&gt;" in html  # escaped form present


def test_json_island_neutralises_tag_breakout() -> None:
    evil = dict(_BASE)
    evil["input"] = dict(_BASE["input"])
    evil["input"]["file"] = "</script><script>alert(1)</script>"
    html = build_html(evil)
    # inside the JSON island the closing-tag sequence must be neutralised
    assert "</script><script>alert(1)</script>" not in html
    assert "\\u003c/script" in html
