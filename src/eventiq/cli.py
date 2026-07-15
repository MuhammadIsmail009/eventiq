"""Command-line interface (FR-18, FR-19).

Subcommands: ``analyze`` (detect and report) and ``validate`` (detect and score
against held-out labels). Exit codes compose into a pipeline: 0 clean, 1 alerts
at or above the minimum severity, 2 input or config error.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import ConfigError, load_config
from .correlate import build_incidents
from .detectors import build_detectors
from .engine import run_analysis
from .export import build_sigma, build_wazuh_xml
from .model import Alert
from .render import build_html
from .render.html import render_report_file
from .report import build_report, write_json, write_jsonl
from .risk import score_entities
from .sources import get_source
from .sources.csv_source import MalformedRowError
from .validate import score_alerts

_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _run(input_path: str, config_path: str | None, engine: str | None, strict: bool) -> Any:
    config = load_config(config_path)
    if engine:
        config.engine = engine
    detectors = build_detectors(config)
    source = get_source(config.engine, input_path, strict=strict)
    result = run_analysis(source, detectors)
    return config, result


def _max_severity_rank(alerts: list[Alert]) -> int:
    return max((_SEVERITY_RANK[a.severity] for a in alerts), default=-1)


def cmd_analyze(args: argparse.Namespace) -> int:
    config, result = _run(args.input, args.config, args.engine, args.strict)
    entity_risk = score_entities(result.alerts)
    incidents = build_incidents(result.alerts, {e.entity: e.risk_score for e in entity_risk})
    validation = None
    if args.validate:
        validation = score_alerts(result.alerts, args.input)
    generated_at = args.generated_at or datetime.now().isoformat(sep=" ", timespec="seconds")
    report = build_report(
        result.alerts,
        result.stats,
        config,
        incidents=incidents,
        entity_risk=entity_risk,
        overview=result.overview,
        validation=validation,
        generated_at=generated_at,
    )
    write_json(report, args.out)
    if args.jsonl:
        write_jsonl(result.alerts, args.jsonl)
    if args.html:
        Path(args.html).write_text(build_html(report), encoding="utf-8")

    print(f"Analyzed {result.stats.rows} rows ({result.stats.malformed} malformed).")
    print(f"Alerts: {len(result.alerts)}  Incidents: {len(incidents)}  ->  {args.out}")
    for inc in incidents[:10]:
        print(f"  {inc.incident_id}  {inc.severity:8} risk {inc.risk_score:3}  {inc.narrative}")
    if validation:
        _print_validation(validation)

    threshold = _SEVERITY_RANK[args.min_severity.upper()]
    return 1 if _max_severity_rank(result.alerts) >= threshold else 0


def cmd_validate(args: argparse.Namespace) -> int:
    _config, result = _run(args.input, args.config, args.engine, args.strict)
    validation = score_alerts(result.alerts, args.input)
    _print_validation(validation)
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    Path(args.wazuh).write_text(build_wazuh_xml(config), encoding="utf-8")
    Path(args.sigma).write_text(build_sigma(config), encoding="utf-8")
    print(f"Wrote Wazuh rules -> {args.wazuh}")
    print(f"Wrote Sigma rules -> {args.sigma}")
    return 0


def cmd_render(args: argparse.Namespace) -> int:
    render_report_file(args.report, args.out)
    print(f"Wrote dashboard -> {args.out}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .server import serve

    serve(host=args.host, port=args.port, config_path=args.config)
    return 0


def _print_validation(v: dict[str, Any]) -> None:
    print("\nValidation (held-out event_type labels)")
    audit = v.get("label_audit", {})
    if audit:
        print(
            f"  label quality: {audit.get('quality', 'unknown')}  "
            f"scored rules: {audit.get('scored_rules', 0)}"
        )
    print(f"  {'rule':18} {'prec':>6} {'recall':>7} {'f1':>6} {'tp':>7} {'fp':>6} {'fn':>6}")
    for name, r in v["per_rule"].items():
        print(
            f"  {name:18} {r['precision']:>6.3f} {r['recall']:>7.3f} {r['f1']:>6.3f} "
            f"{r['tp']:>7} {r['fp']:>6} {r['fn']:>6}"
        )
    o = v["overall"]
    if o is not None:
        print(
            f"  {'OVERALL':18} {o['precision']:>6.3f} {o['recall']:>7.3f} {o['f1']:>6.3f} "
            f"{o['tp']:>7} {o['fp']:>6} {o['fn']:>6}"
        )
    else:
        print("  No supported campaign label is present; overall metrics are N/A.")
    nb = v["naive_failed_login_baseline"]
    if nb["precision"] is not None:
        print(f"  naive any-failed-login precision: {nb['precision']:.3f}  ({nb['note']})")
    for u in v["unscored"]:
        print(f"  not scored (rule {u['rule_id']}, {u['alerts']} alerts): {u['note']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="eventiq", description="Network security log analysis")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("input", help="path to the input CSV")
    common.add_argument("-c", "--config", default=None, help="YAML config path")
    common.add_argument("--engine", choices=["stdlib", "polars"], default=None)
    common.add_argument("--strict", action="store_true", help="fail on the first malformed row")

    a = sub.add_parser("analyze", parents=[common], help="detect and write a JSON report")
    a.add_argument("-o", "--out", default="report.json", help="JSON report output path")
    a.add_argument("--jsonl", default=None, help="also write JSON Lines alert stream here")
    a.add_argument("--validate", action="store_true", help="score against held-out labels inline")
    a.add_argument("--html", default=None, help="also write the self-contained HTML dashboard")
    a.add_argument("--min-severity", default="low", help="exit 1 if an alert at/above this fires")
    a.add_argument("--generated-at", default=None, help=argparse.SUPPRESS)
    a.set_defaults(func=cmd_analyze)

    v = sub.add_parser("validate", parents=[common], help="detect and score against labels")
    v.set_defaults(func=cmd_validate)

    e = sub.add_parser("export", help="write Wazuh rule XML and Sigma YAML from config")
    e.add_argument("-c", "--config", default=None, help="YAML config path")
    e.add_argument("--wazuh", default="eventiq_wazuh_rules.xml", help="Wazuh XML output path")
    e.add_argument("--sigma", default="eventiq_sigma.yml", help="Sigma YAML output path")
    e.set_defaults(func=cmd_export)

    r = sub.add_parser("render", help="render an existing JSON report to the HTML dashboard")
    r.add_argument("report", help="path to a report.json produced by analyze")
    r.add_argument("-o", "--out", default="dashboard.html", help="HTML output path")
    r.set_defaults(func=cmd_render)

    s = sub.add_parser("serve", help="local web app: upload a CSV, get the dashboard")
    s.add_argument("-c", "--config", default=None, help="YAML config path")
    s.add_argument("--host", default="127.0.0.1", help="bind host (localhost by default)")
    s.add_argument("--port", type=int, default=8000, help="bind port")
    s.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result: int = args.func(args)
        return result
    except (ConfigError, MalformedRowError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
