"""Local analysis API, a read-only public gallery, and a protected hosted workspace.

Run with: uvicorn ipsec_analyzer.api.app:app --host 127.0.0.1 --port 8000
The default upload mode has no user accounts and must remain on loopback.
"""

from __future__ import annotations

import tempfile
import ipaddress
import json
import os
import base64
import binascii
import hmac
import hashlib
import time
from collections import OrderedDict
from pathlib import Path
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from starlette.datastructures import UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from ipsec_analyzer.assessment.analyze import analyze_capture
from ipsec_analyzer.ingestion.capture import CaptureError
from ipsec_analyzer.reporting.exports import report_document, report_text, report_html, report_pdf

MAX_UPLOAD_BYTES = 16 * 1024 * 1024
MAX_RESULTS = 16
def _repository_root() -> Path:
    # Render installs the package in a virtual environment, while the checked-out
    # dashboard and reviewed captures remain under the service working directory.
    for candidate in (Path.cwd(), *Path(__file__).resolve().parents):
        if (candidate / "dashboard" / "web").is_dir() and (candidate / "data" / "sample").is_dir():
            return candidate
    return Path(__file__).resolve().parents[3]


ROOT_DIR = _repository_root()
WEB_DIR = ROOT_DIR / "dashboard" / "web"
PUBLIC_DEMO = os.environ.get("IPSEC_DEPLOYMENT_MODE") == "public-demo"
PROTECTED_UPLOAD = os.environ.get("IPSEC_DEPLOYMENT_MODE") == "protected-upload"
PUBLIC_UPLOAD = os.environ.get("IPSEC_DEPLOYMENT_MODE") == "public-upload"
HOSTED_UPLOAD = PROTECTED_UPLOAD or PUBLIC_UPLOAD
UPLOAD_USER = os.environ.get("IPSEC_UPLOAD_USER", "analyst")
UPLOAD_PASSWORD = os.environ.get("IPSEC_UPLOAD_PASSWORD", "")
SESSION_COOKIE = "ipsec_workspace_session"
SESSION_SECONDS = 12 * 60 * 60
if PROTECTED_UPLOAD and (not UPLOAD_USER or not UPLOAD_PASSWORD):
    raise RuntimeError("Protected upload mode requires IPSEC_UPLOAD_USER and IPSEC_UPLOAD_PASSWORD")
DEMO_CAPTURES = {
    "modern-tunnel": ROOT_DIR / "data/sample/modern-tunnel.pcap",
    "cbc-no-pfs": ROOT_DIR / "data/sample/cbc-no-pfs.pcap",
    "voip-like": ROOT_DIR / "data/sample/phase4-voip-01.pcap",
    "plain-icmp": ROOT_DIR / "data/control/plain-icmp-01.pcap",
}
app = FastAPI(title="IPsec Analyzer", version="0.1.0", docs_url=None, redoc_url=None)
_results: OrderedDict[str, dict] = OrderedDict()
_demo_ids: dict[str, str] = {}


def _load_demo_results() -> None:
    if not PUBLIC_DEMO or _demo_ids:
        return
    for slug, capture_path in DEMO_CAPTURES.items():
        result = analyze_capture(capture_path).to_dict()
        analysis_id = result["capture"]["sha256"][:32]
        _results[analysis_id] = result
        _demo_ids[slug] = analysis_id


def _authenticated(request: Request) -> bool:
    session = request.cookies.get(SESSION_COOKIE, "")
    expiry, separator, signature = session.partition(".")
    if separator and expiry.isdecimal() and int(expiry) > time.time():
        expected = hmac.new(
            UPLOAD_PASSWORD.encode(), f"session:{UPLOAD_USER}:{expiry}".encode(), hashlib.sha256
        ).hexdigest()
        if hmac.compare_digest(signature, expected):
            return True
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "basic" or not token:
        return False
    try:
        username, password = base64.b64decode(token, validate=True).decode("utf-8").split(":", 1)
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False
    return hmac.compare_digest(username, UPLOAD_USER) and hmac.compare_digest(password, UPLOAD_PASSWORD)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    if PROTECTED_UPLOAD and request.url.path not in ("/api/health", "/login", "/assets/login.css") and not _authenticated(request):
        if request.method in ("GET", "HEAD") and not request.url.path.startswith("/api/"):
            return RedirectResponse("/login", status_code=303)
        return JSONResponse({"detail": "Authentication required"}, status_code=401)
    if PUBLIC_DEMO:
        _load_demo_results()
        if request.method not in ("GET", "HEAD"):
            return JSONResponse({"detail": "Public demo is read-only"}, status_code=405)
    elif not HOSTED_UPLOAD:
        host_header = request.headers.get("host", "").lower()
        host = host_header.split("]")[0] + "]" if host_header.startswith("[") else host_header.split(":")[0]
        if host not in ("127.0.0.1", "localhost", "[::1]"):
            return JSONResponse({"detail": "Local host name required"}, status_code=403)
        client_host = request.client.host if request.client else ""
        try:
            loopback = ipaddress.ip_address(client_host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            return JSONResponse({"detail": "Local access only"}, status_code=403)
    if request.method == "POST":
        origin = request.headers.get("origin")
        if origin and origin != f"{request.url.scheme}://{request.headers.get('host')}":
            return JSONResponse({"detail": "Cross-origin requests are not allowed"}, status_code=403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; "
        "script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'"
    )
    return response


def _login_page(error: bool = False) -> str:
    message = '<p class="error" role="alert">Incorrect username or password.</p>' if error else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · IPsec Analyzer</title><link rel="stylesheet" href="/assets/login.css"></head>
<body><main class="login-shell"><section class="login-panel">
<div class="eyebrow">IPSEC ANALYZER / PROTECTED WORKSPACE</div>
<h1>Sign in to analyze a capture.</h1>
<p class="intro">Use the workspace credentials configured in Render. Upload only captures you are authorized to analyze.</p>
{message}
<form action="/login" method="post">
<label for="username">Username</label><input id="username" name="username" autocomplete="username" required>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in <span aria-hidden="true">↗</span></button>
</form><p class="footnote">Results are temporary and may disappear when this service restarts.</p>
</section></main></body></html>"""


@app.get("/login", response_class=HTMLResponse)
def login_page():
    if not PROTECTED_UPLOAD:
        raise HTTPException(404)
    return HTMLResponse(_login_page())


@app.post("/login")
async def login(request: Request):
    if not PROTECTED_UPLOAD:
        raise HTTPException(404)
    async with request.form(max_fields=2, max_files=0) as form:
        username = form.get("username", "")
        password = form.get("password", "")
    if not isinstance(username, str) or not isinstance(password, str) or not (
        hmac.compare_digest(username, UPLOAD_USER) and hmac.compare_digest(password, UPLOAD_PASSWORD)
    ):
        return HTMLResponse(_login_page(error=True), status_code=401)
    expiry = str(int(time.time()) + SESSION_SECONDS)
    signature = hmac.new(
        UPLOAD_PASSWORD.encode(), f"session:{UPLOAD_USER}:{expiry}".encode(), hashlib.sha256
    ).hexdigest()
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE, f"{expiry}.{signature}", max_age=SESSION_SECONDS,
                        secure=True, httponly=True, samesite="strict", path="/")
    return response


@app.get("/api/health")
def health():
    mode = "public-demo" if PUBLIC_DEMO else "protected-upload" if PROTECTED_UPLOAD else "public-upload" if PUBLIC_UPLOAD else "local"
    return {"status": "ready", "version": "0.1.0", "mode": mode}


@app.head("/api/health")
def health_head():
    return Response(status_code=200)


@app.post("/api/analyses", status_code=201)
async def create_analysis(request: Request):
    content_type = request.headers.get("content-type", "").split(";")[0].strip()
    if content_type not in ("application/octet-stream", "application/vnd.tcpdump.pcap", "multipart/form-data"):
        raise HTTPException(415, "Send raw PCAP bytes or multipart capture and sanitized configuration files")
    size = 0
    configuration = None
    with tempfile.TemporaryDirectory(prefix="ipsec-analysis-") as directory:
        capture_path = Path(directory) / "capture"
        if content_type == "multipart/form-data":
            async with request.form(max_files=2, max_fields=0) as form:
                capture_file = form.get("capture")
                config_file = form.get("configuration")
                if len(form) != 2 or not isinstance(capture_file, UploadFile) or not isinstance(config_file, UploadFile):
                    raise HTTPException(400, "Provide capture and configuration files exactly once")
                raw_config = await config_file.read(16 * 1024 + 1)
                if len(raw_config) > 16 * 1024:
                    raise HTTPException(413, "Configuration exceeds 16 KiB limit")
                try:
                    configuration = json.loads(raw_config)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise HTTPException(422, "Configuration must be valid JSON") from exc
                with capture_path.open("wb") as temporary:
                    while chunk := await capture_file.read(1024 * 1024):
                        size += len(chunk)
                        if size > MAX_UPLOAD_BYTES:
                            raise HTTPException(413, "Capture exceeds 16 MiB local API limit")
                        temporary.write(chunk)
        else:
            with capture_path.open("wb") as temporary:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > MAX_UPLOAD_BYTES:
                        raise HTTPException(413, "Capture exceeds 16 MiB local API limit")
                    temporary.write(chunk)
        if size == 0:
            raise HTTPException(400, "Capture is empty")
        try:
            analysis = analyze_capture(capture_path, configuration)
        except (CaptureError, ValueError) as exc:
            raise HTTPException(422, str(exc)) from exc
    analysis_id = uuid4().hex
    _results[analysis_id] = analysis.to_dict()
    while len(_results) > MAX_RESULTS:
        _results.popitem(last=False)
    return {"id": analysis_id, "status": "complete", "result": _results[analysis_id]}


def _lookup(analysis_id: str) -> dict:
    if analysis_id not in _results:
        raise HTTPException(404, "Analysis not found or expired")
    return _results[analysis_id]


@app.get("/api/analyses/{analysis_id}")
def get_analysis(analysis_id: str):
    return _lookup(analysis_id)


@app.get("/api/analyses/{analysis_id}/status")
def get_status(analysis_id: str):
    _lookup(analysis_id)
    return {"id": analysis_id, "status": "complete"}


@app.get("/api/analyses/{analysis_id}/sessions")
def get_sessions(analysis_id: str):
    return _lookup(analysis_id)["sessions"]


@app.get("/api/analyses/{analysis_id}/flows")
def get_flows(analysis_id: str):
    return _lookup(analysis_id)["flows"]


@app.get("/api/analyses/{analysis_id}/findings")
def get_findings(analysis_id: str):
    return _lookup(analysis_id)["findings"]


@app.get("/api/analyses/{analysis_id}/evidence")
def get_evidence(analysis_id: str):
    return _lookup(analysis_id)["evidence"]


@app.get("/api/analyses/{analysis_id}/evidence/{evidence_id}")
def get_evidence_item(analysis_id: str, evidence_id: str):
    for item in _lookup(analysis_id)["evidence"]:
        if item["id"] == evidence_id:
            return item
    raise HTTPException(404, "Evidence not found")


@app.get("/api/analyses/{analysis_id}/report")
def get_report(analysis_id: str, format: Literal["text", "html", "pdf", "json"] = "text", redacted: bool = False):
    from ipsec_analyzer.assessment.analyze import Analysis
    data = _lookup(analysis_id)
    if format == "json":
        return JSONResponse(report_document(Analysis(data), redacted),
                            headers={"Content-Disposition": 'attachment; filename="ipsec-report.json"'})
    analysis = Analysis(data)
    if format == "html":
        return HTMLResponse(report_html(analysis, redacted))
    if format == "pdf":
        return Response(report_pdf(analysis, redacted), media_type="application/pdf",
                        headers={"Content-Disposition": 'attachment; filename="ipsec-report.pdf"'})
    return PlainTextResponse(report_text(analysis, redacted))


if WEB_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=WEB_DIR), name="assets")

    @app.head("/")
    def index_head():
        return Response(status_code=200)

    @app.get("/", response_class=HTMLResponse)
    def index():
        if PUBLIC_DEMO:
            return (WEB_DIR / "demo.html").read_text(encoding="utf-8")
        html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
        if HOSTED_UPLOAD:
            html = html.replace("LOCAL WORKSPACE", "PROTECTED WORKSPACE" if PROTECTED_UPLOAD else "PUBLIC UPLOAD WORKSPACE")
            html = html.replace("analyzed by the local service", "analyzed by the protected hosted service")
            html = html.replace("Choose a local capture", "Choose an authorized capture")
            html = html.replace("A local capture", "An authorized capture")
        return html

    @app.get("/demo/{slug}")
    def demo_analysis(slug: str):
        if not PUBLIC_DEMO or slug not in _demo_ids:
            raise HTTPException(404, "Demo capture not found")
        view = "inference" if slug == "voip-like" else "assessment"
        return RedirectResponse(f"/analyses/{_demo_ids[slug]}/{view}", status_code=302)

    @app.get("/analyses/{analysis_id}/{view}", response_class=HTMLResponse)
    def analysis_page(analysis_id: str, view: Literal["assessment", "threats", "sessions", "flows",
                                                  "inference", "evidence", "packets", "reports"]):
        _lookup(analysis_id)
        html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
        if PUBLIC_DEMO:
            html = html.replace("<body>", '<body class="public-demo">', 1)
            html = html.replace("LOCAL WORKSPACE", "PUBLIC LAB DEMO")
            html = html.replace("New capture</a>", "All lab cases</a>")
        elif HOSTED_UPLOAD:
            html = html.replace("LOCAL WORKSPACE", "PROTECTED WORKSPACE" if PROTECTED_UPLOAD else "PUBLIC UPLOAD WORKSPACE")
        return html

    @app.get("/privacy", response_class=HTMLResponse)
    def privacy():
        if PUBLIC_DEMO:
            return (WEB_DIR / "demo-privacy.html").read_text(encoding="utf-8")
        if HOSTED_UPLOAD:
            html = (WEB_DIR / "workspace-privacy.html").read_text(encoding="utf-8")
            if PUBLIC_UPLOAD:
                html = html.replace("PROTECTED WORKSPACE", "PUBLIC UPLOAD WORKSPACE").replace("Protected lab workspace", "Public upload workspace")
                html = html.replace("This password-protected prototype", "This public prototype")
                html = html.replace("The service uses a shared password over HTTPS. Anyone with that password can view stored results and reports.", "The service accepts uploads without a password over HTTPS. Anyone with a result link can view that result and its reports.")
                html = html.replace("Keep the password private and use only approved lab data.", "Use only approved lab data and do not share result links containing sensitive metadata.")
            return html
        return (WEB_DIR / "privacy.html").read_text(encoding="utf-8")

    @app.get("/terms", response_class=HTMLResponse)
    def terms():
        if PUBLIC_DEMO:
            return (WEB_DIR / "demo-terms.html").read_text(encoding="utf-8")
        if HOSTED_UPLOAD:
            html = (WEB_DIR / "workspace-terms.html").read_text(encoding="utf-8")
            if PUBLIC_UPLOAD:
                html = html.replace("PROTECTED WORKSPACE", "PUBLIC UPLOAD WORKSPACE").replace("Protected lab workspace", "Public upload workspace")
            return html
        return (WEB_DIR / "terms.html").read_text(encoding="utf-8")
