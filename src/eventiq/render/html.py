"""Render the JSON report into one self-contained HTML dashboard (FR-16).

No external requests: all CSS and JS are inlined, the report is embedded as a
JSON island, charts are inline SVG, fonts are a system stack. The file opens
offline and survives a strict Content-Security-Policy. Jinja2 autoescape is on and
the JSON island escapes ``<`` so log content cannot inject script (R-5, NFR-4).
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATE_DIR = Path(__file__).parent / "templates"

# Technique id -> (tactic, readable name). Keyed on technique, since MITRE renamed
# tactics and Wazuh/Sigma still emit old strings (locked decision).
_TECHNIQUES = {
    "T1046": ("Discovery", "Network Service Discovery"),
    "T1110.003": ("Credential Access", "Password Spraying"),
    "T1071.004": ("Command & Control", "Application Layer Protocol: DNS"),
    "T1059.001": ("Execution", "PowerShell"),
    "T1571": ("Command & Control", "Non-Standard Port"),
    "T1105": ("Command & Control", "Ingress Tool Transfer"),
}

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


_CHART_W = 960.0
_CHART_H = 220.0
_CHART_PAD_TOP = 12.0
_CHART_PAD_BOTTOM = 4.0


def _build_chart(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    """Precompute a stacked-column chart of alerts per day by severity."""
    buckets: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for a in alerts:
        buckets[a["first_seen"][:10]][a["severity"]] += 1
    days = sorted(buckets)
    if not days:
        return {"width": _CHART_W, "height": _CHART_H, "cols": [],
                "max": 0, "first": "", "last": ""}

    max_total = max(sum(b.values()) for b in buckets.values()) or 1
    usable_h = _CHART_H - _CHART_PAD_TOP - _CHART_PAD_BOTTOM
    slot = _CHART_W / len(days)
    bar_w = max(2.0, min(22.0, slot * 0.62))

    cols = []
    for i, day in enumerate(days):
        counts = buckets[day]
        x = i * slot + (slot - bar_w) / 2
        y = _CHART_H - _CHART_PAD_BOTTOM
        segments = []
        for sev in _SEVERITY_ORDER:
            n = counts.get(sev, 0)
            if not n:
                continue
            h = n / max_total * usable_h
            y -= h
            segments.append({"sev": sev, "y": round(y, 2), "h": round(h, 2), "n": n})
        cols.append(
            {"x": round(x, 2), "w": round(bar_w, 2), "day": day,
             "total": sum(counts.values()), "segments": segments}
        )
    return {
        "width": _CHART_W, "height": _CHART_H, "cols": cols,
        "max": max_total, "first": days[0], "last": days[-1],
    }


def _volume_chart(overview: dict[str, Any]) -> dict[str, Any]:
    """An area line of all events per day (not just alerts)."""
    vol = overview.get("daily_volume", [])
    w, h = 960.0, 120.0
    if not vol:
        return {"width": w, "height": h, "line": "", "area": "", "max": 0,
                "first": "", "last": "", "avg": 0}
    maxv = max(c for _, c in vol) or 1
    n = len(vol)
    step = w / (n - 1) if n > 1 else 0.0
    pts = []
    for i, (_day, c) in enumerate(vol):
        x = i * step if n > 1 else w / 2
        y = h - (c / maxv) * (h - 8) - 4
        pts.append((round(x, 2), round(y, 2)))
    line = " ".join(f"{x},{y}" for x, y in pts)
    area = (f"M{pts[0][0]},{h} " + " ".join(f"L{x},{y}" for x, y in pts)
            + f" L{pts[-1][0]},{h} Z")
    return {"width": w, "height": h, "line": line, "area": area, "max": maxv,
            "first": vol[0][0], "last": vol[-1][0], "avg": round(sum(c for _, c in vol) / n)}


def _mitre_coverage(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group covered techniques by tactic for the coverage panel."""
    by_tactic: dict[str, list[dict[str, str]]] = defaultdict(list)
    seen: set[str] = set()
    for inc in incidents:
        for tid in inc.get("techniques", []):
            if tid in seen:
                continue
            seen.add(tid)
            tactic, name = _TECHNIQUES.get(tid, ("Other", tid))
            by_tactic[tactic].append({"id": tid, "name": name})
    order = ["Discovery", "Credential Access", "Execution", "Command & Control", "Other"]
    return [
        {"tactic": t, "techniques": by_tactic[t]}
        for t in order
        if t in by_tactic
    ]


def _json_island(report: dict[str, Any]) -> str:
    """Serialise the report for a <script type=application/json> island, with the
    three characters that could break out of the tag neutralised."""
    text = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def build_html(report: dict[str, Any]) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    env.filters["comma"] = lambda n: f"{int(n):,}" if isinstance(n, (int, float)) else n
    template = env.get_template("dashboard.html.j2")
    summary = report.get("summary", {})
    by_sev = summary.get("by_severity", {})
    overview = report.get("overview", {})
    return template.render(
        report=report,
        input=report.get("input", {}),
        summary=summary,
        by_severity=by_sev,
        overview=overview,
        categories=report.get("categories", []),
        volume=_volume_chart(overview),
        incidents=report.get("incidents", []),
        entity_risk=report.get("entity_risk", [])[:12],
        not_detected=report.get("not_detected", []),
        validation=report.get("validation"),
        coverage=report.get("coverage", {}),
        chart=_build_chart(report.get("alerts", [])),
        mitre=_mitre_coverage(report.get("incidents", [])),
        severity_order=_SEVERITY_ORDER,
        critical=by_sev.get("CRITICAL", 0),
        high=by_sev.get("HIGH", 0),
        json_island=_json_island(report),
    )


def render_report_file(report_path: str | Path, out_path: str | Path) -> None:
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    Path(out_path).write_text(build_html(report), encoding="utf-8")
