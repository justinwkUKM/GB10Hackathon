#!/usr/bin/env python3
"""Loopback-only web UI for agent_scan.py. Uses only the Python standard library."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

import agent_scan


ROOT = Path(__file__).resolve().parent
HTML_FILE = ROOT / "agent_scan_ui.html"
REPORT_DIR = ROOT / "agent-scan-results"
MAX_BODY_BYTES = 32_768
REPORT_NAME = re.compile(r"^agent-scan-\d{8}-\d{6}-utc\.(?:json|md)$")
JOBS: dict[str, dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()
SCANNER_LOCK = threading.Lock()
ACTIVE_JOB: str | None = None


def invoke_scanner(args: list[str]) -> tuple[int, str, str]:
    """Call scanner main in-process while capturing CLI output for the UI."""
    stdout, stderr = io.StringIO(), io.StringIO()
    # redirect_stdout is process-global; serialize it with concurrent plan requests.
    with SCANNER_LOCK:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                code = agent_scan.main(args)
            except SystemExit as exc:
                code = int(exc.code or 0)
    return code, stdout.getvalue(), stderr.getvalue()


def get_plan(target: str) -> dict[str, Any]:
    if not target.strip():
        raise ValueError("Enter a URL, GitHub repository URL, or local repository path.")
    code, stdout, stderr = invoke_scanner(["plan", target.strip(), "--json"])
    if code:
        raise ValueError(stderr.strip() or "Could not create a scan plan.")
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("The scanner returned an unreadable plan.") from exc


def execute_scan(target: str, authorized: bool, api_key_env: str, model: str) -> dict[str, Any]:
    args = ["scan", target.strip(), "--json", "--output-dir", str(REPORT_DIR)]
    if authorized:
        args.append("--authorized")
    if api_key_env.strip():
        args.extend(["--api-key-env", api_key_env.strip()])
    if model.strip():
        args.extend(["--model", model.strip()])
    code, stdout, stderr = invoke_scanner(args)
    if code:
        raise ValueError(stderr.strip() or "The scan did not complete.")
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("The scanner completed but returned an unreadable report.") from exc


def run_job(job_id: str, target: str, authorized: bool, api_key_env: str, model: str) -> None:
    global ACTIVE_JOB
    try:
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "running"
            JOBS[job_id]["started_at"] = datetime.now(timezone.utc).isoformat()
        result = execute_scan(target, authorized, api_key_env, model)
        with JOBS_LOCK:
            JOBS[job_id].update(status="completed", result=result,
                                finished_at=datetime.now(timezone.utc).isoformat())
    except Exception as exc:
        with JOBS_LOCK:
            JOBS[job_id].update(status="failed", error=str(exc),
                                finished_at=datetime.now(timezone.utc).isoformat())
    finally:
        with JOBS_LOCK:
            ACTIVE_JOB = None


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentScanUI/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Requests may contain sensitive query parameters in their path; keep targets out of logs.
        return

    def send_bytes(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def send_json(self, status: int, value: Any) -> None:
        data = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_bytes(status, data, "application/json; charset=utf-8")

    def read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid request size.") from exc
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError("Request is too large.")
        try:
            obj = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as exc:
            raise ValueError("Request must contain valid JSON.") from exc
        if not isinstance(obj, dict):
            raise ValueError("Request body must be a JSON object.")
        return obj

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/":
            try:
                self.send_bytes(200, HTML_FILE.read_bytes(), "text/html; charset=utf-8")
            except OSError:
                self.send_json(500, {"error": "UI file is missing."})
            return
        if path == "/api/reports":
            REPORT_DIR.mkdir(parents=True, exist_ok=True)
            reports = []
            for file in sorted(REPORT_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
                if file.is_file() and REPORT_NAME.fullmatch(file.name):
                    reports.append({"name": file.name, "kind": "json" if file.suffix == ".json" else "markdown",
                                    "modified": datetime.fromtimestamp(file.stat().st_mtime, timezone.utc).isoformat()})
            self.send_json(200, {"reports": reports[:30]})
            return
        if path == "/api/dvaa-summary":
            summary = ROOT / "redteam-results" / "dvaa-exhaustive-summary.md"
            if summary.is_file():
                self.send_bytes(200, summary.read_bytes(), "text/markdown; charset=utf-8")
            else:
                self.send_json(404, {"error": "DVAA exhaustive summary is not available yet."})
            return
        if path.startswith("/api/reports/"):
            name = unquote(path.removeprefix("/api/reports/"))
            if not REPORT_NAME.fullmatch(name):
                self.send_json(400, {"error": "Invalid report name."})
                return
            file = REPORT_DIR / name
            if not file.is_file():
                self.send_json(404, {"error": "Report not found."})
                return
            content_type = "application/json; charset=utf-8" if file.suffix == ".json" else "text/markdown; charset=utf-8"
            self.send_bytes(200, file.read_bytes(), content_type)
            return
        if path.startswith("/api/jobs/"):
            job_id = path.removeprefix("/api/jobs/")
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                snapshot = dict(job) if job else None
            if snapshot is None:
                self.send_json(404, {"error": "Scan job not found."})
            else:
                self.send_json(200, snapshot)
            return
        self.send_json(404, {"error": "Not found."})

    def do_POST(self) -> None:  # noqa: N802
        global ACTIVE_JOB
        path = urlparse(self.path).path
        try:
            data = self.read_json()
            if path == "/api/plan":
                self.send_json(200, get_plan(str(data.get("target", ""))))
                return
            if path == "/api/scan":
                target = str(data.get("target", "")).strip()
                if not target:
                    raise ValueError("Enter a target before starting the scan.")
                authorized = data.get("authorized") is True
                # Require the explicit checkbox for every non-loopback URL or Git remote.
                remote = agent_scan.is_github_repo_url(target) or agent_scan.is_remote_git(target)
                if agent_scan.is_url(target) and not agent_scan.is_github_repo_url(target):
                    parsed = agent_scan.validate_url(target)
                    remote = not agent_scan.local_host(parsed.hostname or "")
                if remote and not authorized:
                    raise ValueError("Confirm that you are authorized to assess this remote target before scanning.")
                api_key_env = str(data.get("api_key_env", ""))
                if api_key_env and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", api_key_env):
                    raise ValueError("API key must be supplied through a valid environment variable name, not pasted here.")
                model = str(data.get("model", "gpt-4o-mini"))[:200]
                with JOBS_LOCK:
                    if ACTIVE_JOB is not None:
                        raise ValueError("A scan is already running. Wait for it to finish before starting another.")
                    job_id = uuid.uuid4().hex
                    ACTIVE_JOB = job_id
                    JOBS[job_id] = {"id": job_id, "status": "queued",
                                    "target": agent_scan.display_target(target),
                                    "created_at": datetime.now(timezone.utc).isoformat()}
                thread = threading.Thread(target=run_job, args=(job_id, target, authorized, api_key_env, model), daemon=True)
                thread.start()
                self.send_json(202, {"job_id": job_id, "status": "queued"})
                return
            self.send_json(404, {"error": "Not found."})
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
        except Exception as exc:
            self.send_json(500, {"error": str(exc)})


def main() -> None:
    parser = argparse.ArgumentParser(description="Start the local agent scan web UI.")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Agent scan UI: http://127.0.0.1:{args.port}")
    print("Listening on loopback only. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping agent scan UI.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
