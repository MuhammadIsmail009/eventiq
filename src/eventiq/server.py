"""A small local web app: upload a CSV, get the dashboard (FR-20 stretch).

This exists so a reviewer can test EventIQ on their own log file without
touching a command line. It wraps the exact same Python engine the CLI uses, so
there is one detection implementation, not a second one in the browser. It binds
to localhost only and is meant for local, single-user use. Pure standard library,
no new dependency.
"""

from __future__ import annotations

import csv
import json
import os
import tempfile
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .config import ConfigError, load_config
from .correlate import build_incidents
from .detectors import build_detectors
from .engine import run_analysis
from .render import build_html
from .report import build_report
from .risk import score_entities
from .sources import get_source
from .sources.csv_source import MalformedRowError
from .validate import score_alerts

_MAX_UPLOAD = 1024 * 1024 * 1024  # 1 GB ceiling

# The built SPA. Checked in and shipped as package data so `serve` needs Node at
# build time only, never at run time. If it is absent (source checkout that has
# not been built), GET / degrades to the plain uploader below.
_DIST = Path(__file__).parent / "web"

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2",
    ".json": "application/json; charset=utf-8",
    ".ico": "image/x-icon",
    ".png": "image/png",
}


def _content_type(path: Path) -> str:
    return _CONTENT_TYPES.get(path.suffix.lower(), "application/octet-stream")

_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EventIQ — analyse a log file</title>
<style>
  :root{--bg:#0E1116;--s1:#161B22;--bd:#2A313C;--tx:#E8ECF1;--tx2:#98A2B0;--tx3:#818C9B;--accent:#78A9FF;
    --mono:"Cascadia Code",Consolas,ui-monospace,monospace;--sans:system-ui,-apple-system,"Segoe UI",sans-serif;}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--tx);font-family:var(--sans);min-height:100vh;display:flex;
    align-items:center;justify-content:center;padding:24px;
    background-image:radial-gradient(800px 340px at 30% -10%,rgba(120,169,255,.10),transparent 60%);}
  .card{width:100%;max-width:560px}
  .brand{font-family:var(--mono);font-weight:700;letter-spacing:.34em;text-transform:uppercase;font-size:15px}
  .brand b{color:var(--accent)}
  h1{font-size:22px;margin:18px 0 6px;font-weight:600}
  p{color:var(--tx2);font-size:13px;line-height:1.6}
  .drop{margin-top:22px;border:1.5px dashed var(--bd);border-radius:14px;background:var(--s1);
    padding:44px 24px;text-align:center;cursor:pointer;transition:border-color .15s,background .15s}
  .drop.hot{border-color:var(--accent);background:#1a2230}
  .drop .big{font-family:var(--mono);font-size:14px;color:var(--tx)}
  .drop .sm{color:var(--tx3);font-size:12px;margin-top:8px}
  input[type=file]{display:none}
  .status{margin-top:16px;font-family:var(--mono);font-size:12px;color:var(--tx2);min-height:18px}
  .foot{margin-top:22px;color:var(--tx3);font-size:11px;font-family:var(--mono);line-height:1.7}
</style></head><body>
<div class="card">
  <div class="brand">EVENT<b>IQ</b></div>
  <h1>Analyse a log file</h1>
  <p>Drop a CSV or CSV-formatted TXT file. Required columns are <span style="font-family:var(--mono)">timestamp</span>,
  <span style="font-family:var(--mono)">source_ip</span>, and <span style="font-family:var(--mono)">destination_ip</span>
  (or <span style="font-family:var(--mono)">dest_ip</span>). Missing optional fields are disclosed in the dashboard.</p>
  <label class="drop" id="drop">
    <div class="big">Drop a CSV or TXT log here, or click to choose</div>
    <div class="sm">runs locally, nothing leaves this machine</div>
    <input type="file" id="file" accept=".csv,.txt,text/csv,text/plain">
  </label>
  <div class="status" id="status"></div>
  <div class="foot">Same engine as the command line. Detection reads raw fields only.
  Supported campaign labels are held out and scored after detection; generic labels are marked unscorable.</div>
</div>
<script>
  const drop=document.getElementById('drop'),input=document.getElementById('file'),status=document.getElementById('status');
  function send(file){
    if(!file){return;}
    status.textContent='Analysing '+file.name+' ('+(file.size/1e6).toFixed(1)+' MB)... this can take a moment.';
    fetch('/analyze?name='+encodeURIComponent(file.name),{method:'POST',body:file})
      .then(r=>r.text().then(t=>({ok:r.ok,t})))
      .then(o=>{if(o.ok){document.open();document.write(o.t);document.close();}else{status.textContent=o.t;}})
      .catch(e=>{status.textContent='Upload failed: '+e;});
  }
  input.addEventListener('change',()=>send(input.files[0]));
  ['dragenter','dragover'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add('hot');}));
  ['dragleave','drop'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.remove('hot');}));
  drop.addEventListener('drop',e=>send(e.dataTransfer.files[0]));
</script></body></html>"""


def _csv_has_labels(path: str) -> bool:
    try:
        with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
            header = [name.strip() for name in next(csv.reader(fh), [])]
    except (OSError, csv.Error):
        return False
    return "event_type" in header


def analyse_to_report(
    path: str, config_path: str | None, *, display_name: str | None = None
) -> dict[str, Any]:
    """Run the engine and return the report dict.

    This is the single source of truth for both artifacts. The SPA gets this as
    JSON; the static export renders it through Jinja. Neither renderer may read
    anything the report does not carry, so the two cannot drift apart.
    """
    config = load_config(config_path)
    result = run_analysis(get_source(config.engine, path), build_detectors(config))
    if display_name:
        result.stats.file = display_name
    entity_risk = score_entities(result.alerts)
    incidents = build_incidents(result.alerts, {e.entity: e.risk_score for e in entity_risk})
    validation = score_alerts(result.alerts, path) if _csv_has_labels(path) else None
    return build_report(
        result.alerts, result.stats, config,
        incidents=incidents, entity_risk=entity_risk, overview=result.overview,
        validation=validation,
        generated_at=datetime.now().isoformat(sep=" ", timespec="seconds"),
        include_dataset_notes=False,
    )


def analyse_to_html(
    path: str, config_path: str | None, *, display_name: str | None = None
) -> str:
    return build_html(analyse_to_report(path, config_path, display_name=display_name))


class _Server(ThreadingHTTPServer):
    config_path: str | None = None


class _Handler(BaseHTTPRequestHandler):
    server_version = "EventIQ/0.1"

    def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send(code, body, "application/json; charset=utf-8")

    def _send_error_page(self, code: int, message: str) -> None:
        safe = (
            message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        )
        body = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>EventIQ</title>
<style>body{{margin:0;background:#0e1116;color:#e8ecf1;font:14px system-ui;display:grid;
place-items:center;min-height:100vh}}main{{max-width:620px;margin:24px;padding:28px;border:1px solid #2a313c;
border-radius:14px;background:#161b22}}h1{{font-size:20px}}p{{color:#a8b2c0;line-height:1.6}}
code{{color:#ffb86b;word-break:break-word}}</style></head><body><main>
<h1>This file needs a schema check</h1><p>EventIQ could not safely map the upload.</p>
<code>{safe}</code><p>Required: timestamp, source_ip, and destination_ip (or dest_ip).
Other canonical fields are optional and will be disclosed as missing in the dashboard.</p></main></body></html>"""
        self._send(code, body.encode("utf-8"))

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            index = _DIST / "index.html"
            if index.is_file():
                self._send(200, index.read_bytes())
            else:
                # No built bundle: fall back to the plain uploader so `serve`
                # still works from a source checkout without running npm.
                self._send(200, _PAGE.encode("utf-8"))
            return
        asset = self._resolve_asset(path)
        if asset is None:
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        self._send(200, asset.read_bytes(), _content_type(asset))

    def _resolve_asset(self, path: str) -> Path | None:
        """Map a URL path to a file inside web/dist, refusing to escape it."""
        if not _DIST.is_dir():
            return None
        candidate = (_DIST / path.lstrip("/")).resolve()
        try:
            candidate.relative_to(_DIST.resolve())
        except ValueError:
            return None  # path traversal attempt
        return candidate if candidate.is_file() else None

    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        if urlsplit(self.path).path != "/analyze":
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        # The SPA wants JSON. ?static=1 keeps the original server-rendered HTML
        # response, which is the no-JavaScript fallback and what the CLI's
        # --html path exercises.
        static = parse_qs(urlsplit(self.path).query).get("static", ["0"])[0] == "1"
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._send(400, b"invalid content length", "text/plain; charset=utf-8")
            return
        if length <= 0 or length > _MAX_UPLOAD:
            self._send(400, b"upload missing or too large", "text/plain; charset=utf-8")
            return
        fd, tmp = tempfile.mkstemp(suffix=".csv")
        try:
            remaining = length
            with os.fdopen(fd, "wb") as out:
                while remaining > 0:
                    chunk = self.rfile.read(min(1 << 16, remaining))
                    if not chunk:
                        break
                    out.write(chunk)
                    remaining -= len(chunk)
            if remaining:
                self._send(400, b"upload ended before the declared size", "text/plain; charset=utf-8")
                return
            config_path = getattr(self.server, "config_path", None)
            query = parse_qs(urlsplit(self.path).query)
            requested_name = query.get("name", ["uploaded.csv"])[0]
            display_name = Path(requested_name).name or "uploaded.csv"
            report = analyse_to_report(tmp, config_path, display_name=display_name)
            if static:
                self._send(200, build_html(report).encode("utf-8"))
            else:
                self._send_json(200, report)
        except (MalformedRowError, ValueError, KeyError) as exc:
            message = f"analysis failed: {exc}"
            if static:
                self._send_error_page(400, message)
            else:
                self._send_json(400, {"error": message, "kind": "schema"})
        except (ConfigError, OSError) as exc:
            message = f"analysis failed: {exc}"
            if static:
                self._send(500, message.encode(), "text/plain; charset=utf-8")
            else:
                self._send_json(500, {"error": message, "kind": "internal"})
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def log_message(self, fmt: str, *args: object) -> None:
        pass  # keep the console quiet


def serve(host: str = "127.0.0.1", port: int = 8000, config_path: str | None = None) -> None:
    server = _Server((host, port), _Handler)
    server.config_path = config_path
    print(f"EventIQ web app on http://{host}:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
