"""Both renderers must agree with the report schema.

There are two dashboards now: the React SPA under `web/` (the `serve`
experience) and the Jinja static export (the one-file artifact that attaches to
a ticket). They read the same report.json and nothing else. That is the only
thing stopping them from drifting apart, so it is worth a test rather than a
convention.

These tests fail when someone adds a field in Python and forgets the SPA, or
renames one in the SPA and forgets Python.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from eventiq.render import build_html

REPO = Path(__file__).resolve().parents[2]
REPORT_TS = REPO / "web" / "src" / "report.ts"
DIST = REPO / "src" / "eventiq" / "web"


def _ts_interface_fields(source: str, name: str) -> set[str]:
    """Pull the TOP-LEVEL field names out of one TypeScript interface.

    Depth matters. An interface like `Validation` nests an inline object
    (`label_audit: { quality: string; ... }`), and a flat line-by-line regex
    would report `quality` as a field of Validation itself.
    """
    match = re.search(rf"export interface {name} \{{(.*?)\n\}}", source, re.S)
    if not match:
        raise AssertionError(f"interface {name} not found in report.ts")
    fields = set()
    depth = 0
    for raw in match.group(1).splitlines():
        line = raw.strip()
        if not line or line.startswith(("//", "/*", "*")):
            continue
        if depth == 0:
            field = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\??\s*:", line)
            if field:
                fields.add(field.group(1))
        # Track nesting AFTER reading the field name on this line, so that
        # `label_audit: {` still registers label_audit but not its contents.
        depth += line.count("{") - line.count("}")
    return fields


def test_spa_report_type_matches_python_report_keys(sample_report: dict[str, object]) -> None:
    """The SPA's Report interface and build_report() must describe the same thing."""
    declared = _ts_interface_fields(REPORT_TS.read_text(encoding="utf-8"), "Report")
    actual = set(sample_report)
    missing_in_ts = actual - declared
    extra_in_ts = declared - actual
    assert not missing_in_ts, (
        f"build_report() emits {sorted(missing_in_ts)} but web/src/report.ts does not "
        "declare them. The SPA cannot render a field it does not know about."
    )
    assert not extra_in_ts, (
        f"web/src/report.ts declares {sorted(extra_in_ts)} but build_report() never "
        "emits them. The SPA would read undefined at runtime."
    )


@pytest.mark.parametrize(
    "interface,key",
    [("ReportInput", "input"), ("Summary", "summary"), ("Validation", "validation")],
)
def test_spa_nested_types_match(sample_report: dict[str, object], interface: str, key: str) -> None:
    declared = _ts_interface_fields(REPORT_TS.read_text(encoding="utf-8"), interface)
    actual = set(sample_report[key])  # type: ignore[arg-type]
    assert declared == actual, (
        f"web/src/report.ts:{interface} and report['{key}'] disagree: "
        f"only in TS {sorted(declared - actual)}, only in Python {sorted(actual - declared)}"
    )


def test_spa_incident_type_matches_python_report(sample_report: dict[str, object]) -> None:
    """Incident drill-down must use an explicit rule relationship, never text guessing."""
    declared = _ts_interface_fields(REPORT_TS.read_text(encoding="utf-8"), "Incident")
    incidents = sample_report["incidents"]
    assert isinstance(incidents, list) and incidents, "real sample report has no incidents"
    actual = set(incidents[0])
    assert declared == actual, (
        "web/src/report.ts:Incident and the Python incident envelope disagree: "
        f"only in TS {sorted(declared - actual)}, only in Python {sorted(actual - declared)}"
    )


def test_spa_models_validation_overall_as_nullable() -> None:
    """`overall` is null whenever no supported campaign label was present.

    This is not pedantry. The SPA once read `validation.overall.precision` behind
    a truthiness check on `validation` alone, which is non-null for a file whose
    event_type column carries only generic labels. Every hand-made test file
    looks like that, and the whole dashboard white-screened on all of them.
    """
    src = REPORT_TS.read_text(encoding="utf-8")
    match = re.search(r"^\s*overall:\s*(.+)$", src, re.M)
    assert match, "report.ts no longer declares Validation.overall"
    assert "null" in match.group(1), (
        f"Validation.overall is declared as {match.group(1).strip()!r}. It must admit null, "
        "or the SPA will crash on any file whose labels are all generic."
    )


# Two different requirements, so two different rules.
#
# Searching for a bare "http://" would be wrong for either: real log data
# contains URLs (a malicious PowerShell sample carries DownloadString('http://…'))
# and that string inside the embedded report is evidence, not a request. An SVG
# xmlns is likewise an identifier, not something a browser fetches.

# Fetches from another host. Neither artifact may do this: the point is that both
# work on an air-gapped box.
_EXTERNAL = (
    "src=http",
    'src="http',
    "href=http",
    'href="http',
    "url(http",
    "@import url(http",
    "//cdn.",
    "googleapis",
)

# Any subresource at all. Only the static export must satisfy this, because its
# whole value is being ONE file you can attach to a ticket. The SPA is served
# from disk by our own server, so its relative ./app.css link is fine.
_ANY_SUBRESOURCE = ("<script src=", "<link ", "@import")


def test_static_export_still_renders_the_same_report(sample_report: dict[str, object]) -> None:
    """The one-file artifact must survive everything the SPA work did to the server."""
    html = build_html(sample_report)
    assert html.lstrip().startswith("<!doctype html>")
    assert "Events evaluated" in html
    lowered = html.lower()
    for forbidden in _EXTERNAL + _ANY_SUBRESOURCE:
        assert forbidden not in lowered, (
            f"static export is no longer one self-contained file: found {forbidden!r}"
        )


def test_built_spa_bundle_is_committed() -> None:
    """`eventiq serve` must work from a clean clone with no npm install."""
    assert (DIST / "index.html").is_file(), (
        "src/eventiq/web/index.html is missing. Run `npm run build` in web/ and commit "
        "the result; serve depends on the bundle being checked in."
    )
    assert (DIST / "app.js").is_file(), "src/eventiq/web/app.js is missing; run npm run build"


def test_built_spa_makes_no_external_request() -> None:
    """Offline is a requirement, not a nice-to-have. Fonts are inlined, not fetched.

    Note an SVG xmlns ("http://www.w3.org/2000/svg") is an XML namespace
    identifier, not a URL a browser fetches, so it is deliberately not a failure.
    """
    index = (DIST / "index.html").read_text(encoding="utf-8").lower()
    css_path = DIST / "app.css"
    css = css_path.read_text(encoding="utf-8").lower() if css_path.is_file() else ""
    for blob, name in ((index, "index.html"), (css, "app.css")):
        for forbidden in _EXTERNAL:
            assert forbidden not in blob, f"built {name} loads {forbidden}; it must be offline"
    # The fonts must be embedded rather than linked, or an air-gapped box shows
    # a fallback face.
    if css:
        assert "data:font/woff2;base64" in css or "data:application/font" in css, (
            "no embedded font found in app.css; the build should inline woff2 as data URIs"
        )
