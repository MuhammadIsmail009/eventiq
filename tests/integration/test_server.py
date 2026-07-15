"""Reviewer upload flow: serve the SPA, accept a CSV, return a report.

`POST /analyze` returns JSON, which is what the React dashboard consumes.
`?static=1` keeps the server-rendered HTML, which is the no-JavaScript fallback.
Both paths run the same engine over the same report, so they cannot disagree
about what was detected.
"""

from __future__ import annotations

import csv
import io
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from eventiq import server as server_module
from eventiq.server import _Handler, _Server

REPO = Path(__file__).resolve().parents[2]


def _start_server() -> tuple[_Server, threading.Thread, str]:
    server = _Server(("127.0.0.1", 0), _Handler)
    server.config_path = str(REPO / "config" / "default.yml")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, thread, f"http://{host}:{port}"


def _stop_server(server: _Server, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def _post(base: str, name: str, data: bytes, *, static: bool = False) -> Any:
    suffix = "&static=1" if static else ""
    request = urllib.request.Request(
        f"{base}/analyze?name={name}{suffix}", data=data, method="POST"
    )
    response = urllib.request.urlopen(request, timeout=60)
    body = response.read().decode()
    return response, body


def test_upload_csv_returns_json_report(dataset_csv: Path) -> None:
    server, thread, base = _start_server()
    try:
        response, body = _post(base, "review.csv", dataset_csv.read_bytes())
        assert response.headers["Content-Type"].startswith("application/json")

        report = json.loads(body)
        assert report["input"]["file"] == "review.csv"
        assert report["input"]["rows"] > 0
        assert report["summary"]["alert_count"] > 0
        # The contract the SPA types against: these keys must exist.
        for key in ("generated_at", "input", "summary", "overview", "categories",
                    "incidents", "entity_risk", "alerts", "coverage",
                    "not_detected", "validation"):
            assert key in report, f"report is missing {key}, SPA types would break"
        assert report["validation"]["overall"]["f1"] == pytest.approx(1.0)
    finally:
        _stop_server(server, thread)


def test_static_fallback_still_returns_the_self_contained_dashboard(dataset_csv: Path) -> None:
    """The no-JS path. This is the artifact that attaches to a ticket."""
    server, thread, base = _start_server()
    try:
        response, body = _post(base, "review.csv", dataset_csv.read_bytes(), static=True)
        assert response.headers["Content-Type"].startswith("text/html")
        assert body.lstrip().startswith("<!doctype html>")
        assert "Events evaluated" in body
        assert "review.csv" in body
        assert "Respond in this order" in body
        assert "Overall F1" in body
    finally:
        _stop_server(server, thread)


def test_incompatible_csv_returns_json_error(tmp_path: Path) -> None:
    bad = tmp_path / "wrong-schema.csv"
    bad.write_text("timestamp,message\n2026-07-01,bad\n", encoding="utf-8")
    server, thread, base = _start_server()
    try:
        try:
            _post(base, "wrong-schema.csv", bad.read_bytes())
        except urllib.error.HTTPError as exc:
            assert exc.code == 400
            assert exc.headers["Content-Type"].startswith("application/json")
            payload = json.loads(exc.read().decode())
            assert payload["kind"] == "schema"
            assert "CSV missing required column" in payload["error"]
        else:
            raise AssertionError("incompatible CSV unexpectedly succeeded")
    finally:
        _stop_server(server, thread)


def test_incompatible_csv_static_path_returns_html_error(tmp_path: Path) -> None:
    bad = tmp_path / "wrong-schema.csv"
    bad.write_text("timestamp,message\n2026-07-01,bad\n", encoding="utf-8")
    server, thread, base = _start_server()
    try:
        try:
            _post(base, "wrong-schema.csv", bad.read_bytes(), static=True)
        except urllib.error.HTTPError as exc:
            assert exc.code == 400
            body = exc.read().decode()
            assert "CSV missing required column" in body
            assert body.lstrip().startswith("<!doctype html>")
        else:
            raise AssertionError("incompatible CSV unexpectedly succeeded")
    finally:
        _stop_server(server, thread)


def test_unlabelled_csv_reports_no_validation(dataset_csv: Path) -> None:
    """No labels in, no accuracy claim out. The tool must not invent a score."""
    rows = list(csv.DictReader(io.StringIO(dataset_csv.read_text(encoding="utf-8"))))
    raw_fields = [name for name in rows[0] if name not in {"event_type", "severity"}]
    upload = io.StringIO()
    writer = csv.DictWriter(upload, fieldnames=raw_fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)

    server, thread, base = _start_server()
    try:
        _, body = _post(base, "unlabelled.csv", upload.getvalue().encode())
        report = json.loads(body)
        assert report["validation"] is None
        assert report["summary"]["alert_count"] > 0
    finally:
        _stop_server(server, thread)


def test_root_serves_the_built_spa() -> None:
    server, thread, base = _start_server()
    try:
        page = urllib.request.urlopen(f"{base}/", timeout=5).read().decode()
        assert 'id="root"' in page, "GET / should serve the built SPA shell"
    finally:
        _stop_server(server, thread)


def test_root_falls_back_to_plain_uploader_without_a_build(monkeypatch: pytest.MonkeyPatch,
                                                           tmp_path: Path) -> None:
    """A source checkout that never ran `npm run build` must still serve."""
    monkeypatch.setattr(server_module, "_DIST", tmp_path / "absent")
    server, thread, base = _start_server()
    try:
        page = urllib.request.urlopen(f"{base}/", timeout=5).read().decode()
        assert "Analyse a log file" in page
    finally:
        _stop_server(server, thread)


def test_asset_request_cannot_escape_the_bundle_directory() -> None:
    """Path traversal must not read arbitrary files off the host."""
    server, thread, base = _start_server()
    try:
        for attempt in ("/../pyproject.toml", "/../../pyproject.toml", "/..%2fpyproject.toml"):
            try:
                urllib.request.urlopen(f"{base}{attempt}", timeout=5)
            except urllib.error.HTTPError as exc:
                assert exc.code == 404
            else:
                raise AssertionError(f"traversal {attempt} was not blocked")
    finally:
        _stop_server(server, thread)


def _strip_columns(csv_text: str, drop: set[str]) -> bytes:
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    fields = [f for f in rows[0] if f not in drop]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue().encode()


def _genericise_labels(csv_text: str) -> bytes:
    """Keep the event_type column but make every label a generic one.

    This is what a hand-written test file looks like: it HAS event_type, but the
    values are LOGIN / DNS_QUERY / system_event rather than a named campaign.
    """
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    for r in rows:
        r["event_type"] = "LOGIN"
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(rows[0]), extrasaction="ignore")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue().encode()


def test_three_label_states_are_distinct(dataset_csv: Path) -> None:
    """The contract the dashboard renders against.

    There are three states and the middle one is easy to miss: a file can carry
    an event_type column whose labels are all generic, in which case validation
    exists but nothing inside it is scorable. Anything reading `overall` must
    handle null, and the dashboard must not claim an accuracy it cannot compute.
    """
    text = dataset_csv.read_text(encoding="utf-8")
    server, thread, base = _start_server()
    try:
        # 1. No event_type column at all -> no validation object.
        _, body = _post(base, "no-labels.csv", _strip_columns(text, {"event_type", "severity"}))
        assert json.loads(body)["validation"] is None

        # 2. event_type present, all labels generic -> validation, but unscorable.
        _, body = _post(base, "generic-labels.csv", _genericise_labels(text))
        v = json.loads(body)["validation"]
        assert v is not None, "an event_type column should still produce a label audit"
        assert v["overall"] is None, "generic labels must not produce an overall score"
        assert v["per_rule"] == {}, "generic labels must not score any rule"
        assert v["label_audit"]["quality"] == "unsupported"
        assert v["naive_failed_login_baseline"]["precision"] is None

        # 3. Real campaign labels -> real scores.
        _, body = _post(base, "labelled.csv", text.encode())
        v = json.loads(body)["validation"]
        assert v["overall"] is not None
        assert v["overall"]["precision"] == pytest.approx(1.0)
        assert v["label_audit"]["quality"] == "fully_scorable"
    finally:
        _stop_server(server, thread)


def test_generic_labels_never_produce_an_accuracy_claim(dataset_csv: Path) -> None:
    """The static export must refuse to score rather than render a bogus number."""
    server, thread, base = _start_server()
    try:
        body = _post(
            base, "generic.csv", _genericise_labels(dataset_csv.read_text(encoding="utf-8")),
            static=True,
        )[1]
        assert "Accuracy check unavailable" in body
        assert "Overall F1" not in body
    finally:
        _stop_server(server, thread)
