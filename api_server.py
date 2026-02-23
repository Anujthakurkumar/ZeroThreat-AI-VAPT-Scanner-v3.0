"""
ZeroThreat VAPT Scanner v3.0 - API Server
Pure Python HTTP server. No external dependencies.

Endpoints:
  GET  /                        → Dashboard HTML
  POST /api/scan                → Start scan
  GET  /api/status?job_id=X     → Poll scan status
  GET  /api/jobs                → All active/recent jobs
  GET  /api/history             → SQLite history list
  GET  /api/history?target=X    → History for specific target
  GET  /api/scan?scan_id=X      → Full result for stored scan
  POST /api/diff                → Diff two scan IDs
  GET  /api/trend?target=X      → Risk trend for target
  GET  /api/targets             → All scanned targets
  GET  /api/profiles            → Scan profiles
  GET  /api/report/pdf?job_id=X → Download PDF report
  GET  /api/report/sarif?job_id=X → Download SARIF report
  DELETE /api/scan              → Delete a scan from history
"""

import json
import time
import threading
import os
import sys
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from dataclasses import asdict

sys.path.insert(0, os.path.dirname(__file__))

from scanner_core import VAPTScanner, SCAN_PROFILES
from history_store import (
    save_scan, list_scans, get_scan, delete_scan,
    diff_scans, get_targets, get_risk_trend
)

# ✅ Correct import (your tests show: "from pdf_report import generate_pdf; import ok")
try:
    from pdf_report import generate_pdf
    PDF_OK = True
except Exception:
    PDF_OK = False
    _PDF_IMPORT_ERR = traceback.format_exc()


# In-memory job store for active/recent scans
scan_jobs = {}   # job_id -> job dict


# ─────────────────────────────────────────
#  BACKGROUND SCAN RUNNER
# ─────────────────────────────────────────

def run_scan_job(job_id, target, scan_type, profile_name, port_range,
                 owner_confirmed, internet_exposed, auth_cookies, passive_only):
    job = scan_jobs[job_id]
    job["status"] = "running"
    job["log"] = []
    job["progress"] = 5

    phases = {
        "Phase 0: Passive Recon": 10,
        "Phase 1: Port Discovery": 30,
        "Phase 2: Network Analysis": 50,
        "Phase 3a: Web Crawling": 65,
        "Phase 3b: Web Scanning": 80,
        "Phase 4: AI Analysis": 95,
    }

    def log_fn(msg, pct=None):
        job["log"].append(msg)
        job["progress_msg"] = msg
        if pct is not None:
            job["progress"] = int(pct)
            return

        # auto progress based on keywords
        low = (msg or "").lower()
        for phase, p in phases.items():
            key = phase.split(":", 1)[1].strip().lower()  # e.g. "port discovery"
            if key in low:
                job["progress"] = p
                break

    try:
        scanner = VAPTScanner(
            target=target,
            scan_type=scan_type,
            profile_name=profile_name,
            owner_confirmed=owner_confirmed,
            internet_exposed=internet_exposed,
            auth_cookies=auth_cookies,
            passive_only=passive_only,
            log_fn=log_fn,
        )

        result = scanner.run()
        result_dict = asdict(result)

        # Save to history DB
        try:
            save_scan(result_dict)
        except Exception as e:
            log_fn(f"[!] History save error: {e}")

        # SARIF (store in-memory for quick download)
        try:
            sarif = scanner.export_sarif(result)
            result_dict["_sarif"] = sarif
        except Exception:
            pass

        job["result"] = result_dict
        job["status"] = "complete"
        job["progress"] = 100
        log_fn(f"[✓] Scan complete. Risk: {result.risk_score}/10 ({result.risk_label})")

    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)
        log_fn(f"[!] Fatal error: {e}")


# ─────────────────────────────────────────
#  HTTP HANDLER
# ─────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        return

    def send_json(self, data, status=200):
        body = json.dumps(data, indent=2, default=str).encode("utf-8", errors="replace")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html):
        body = (html or "").encode("utf-8", errors="replace")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, data: bytes, mime: str, filename: str):
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def read_body(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw.decode("utf-8", errors="replace")) if raw else {}
        except Exception:
            return {}

    def _get_result_by_id(self, jid_or_scanid: str):
        """
        Tries:
          1) in-memory job store
          2) SQLite history store
        Returns result dict or None
        """
        if jid_or_scanid in scan_jobs and scan_jobs[jid_or_scanid].get("result"):
            return scan_jobs[jid_or_scanid]["result"]
        return get_scan(jid_or_scanid)

    # ─── GET ────────────────────────────────────────────────────────────

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        p = lambda k, d=None: params.get(k, [d])[0]

        if path in ("/", "/index.html"):
            dash = os.path.join(os.path.dirname(__file__), "dashboard.html")
            with open(dash, "r", encoding="utf-8", errors="replace") as f:
                self.send_html(f.read())
            return

        if path == "/api/status":
            jid = p("job_id")
            if jid and jid in scan_jobs:
                job = scan_jobs[jid]
                self.send_json({
                    "job_id": jid,
                    "status": job["status"],
                    "progress": job.get("progress", 0),
                    "progress_msg": job.get("progress_msg", ""),
                    "log": job.get("log", []),
                    "result": job.get("result"),
                    "error": job.get("error"),
                })
            else:
                self.send_json({"error": "Job not found"}, 404)
            return

        if path == "/api/jobs":
            self.send_json([{
                "job_id": jid,
                "target": j.get("target"),
                "status": j.get("status"),
                "risk_score": (j.get("result") or {}).get("risk_score") if j.get("result") else None,
                "risk_label": (j.get("result") or {}).get("risk_label") if j.get("result") else None,
                "started_at": j.get("started_at"),
            } for jid, j in scan_jobs.items()])
            return

        if path == "/api/history":
            target = p("target")
            self.send_json(list_scans(target=target, limit=100))
            return

        if path == "/api/scan":
            sid = p("scan_id")
            if not sid:
                self.send_json({"error": "scan_id required"}, 400)
                return
            data = get_scan(sid)
            self.send_json(data or {"error": "Not found"}, 200 if data else 404)
            return

        if path == "/api/targets":
            self.send_json(get_targets())
            return

        if path == "/api/trend":
            target = p("target")
            if not target:
                self.send_json({"error": "target required"}, 400)
                return
            self.send_json(get_risk_trend(target, limit=20))
            return

        if path == "/api/profiles":
            self.send_json({
                k: {
                    "description": v.get("description", ""),
                    "threads": v.get("threads"),
                    "timeout": v.get("timeout"),
                    "crawl_depth": v.get("crawl_depth"),
                } for k, v in SCAN_PROFILES.items()
            })
            return

        if path == "/api/report/pdf":
            jid = p("job_id")
            if not jid:
                self.send_json({"error": "job_id required"}, 400)
                return

            if not PDF_OK:
                self.send_json({
                    "error": "PDF generator import failed",
                    "hint": "Run: python -m pip install reportlab",
                    "details": _PDF_IMPORT_ERR if "_PDF_IMPORT_ERR" in globals() else "unknown",
                }, 500)
                return

            result = self._get_result_by_id(jid)
            if not result:
                self.send_json({"error": "Scan not found"}, 404)
                return

            try:
                pdf_bytes = generate_pdf(result)

                safe = (result.get("target", "report") or "report")
                safe = safe.replace("http://", "").replace("https://", "")
                safe = safe.replace("/", "_").replace(":", "_")

                self.send_file(
                    pdf_bytes,
                    "application/pdf",
                    f"zerothreat_{safe}_{jid[-6:]}.pdf"
                )
            except Exception:
                self.send_json({
                    "error": "PDF generation failed",
                    "details": traceback.format_exc(),
                }, 500)
            return

        if path == "/api/report/sarif":
            jid = p("job_id")
            if not jid:
                self.send_json({"error": "job_id required"}, 400)
                return

            result = self._get_result_by_id(jid)
            if not result:
                self.send_json({"error": "Scan not found"}, 404)
                return

            sarif = None
            if jid in scan_jobs and scan_jobs[jid].get("result"):
                sarif = (scan_jobs[jid]["result"] or {}).get("_sarif")

            if not sarif:
                # regenerate SARIF from stored dict using scanner_core exporter
                try:
                    from scanner_core import SARIFExporter, ScanResult
                    fs = ScanResult(**{k: result.get(k) for k in ScanResult.__dataclass_fields__.keys() if k in result})
                    sarif = SARIFExporter().export(fs)
                except Exception as e:
                    self.send_json({"error": f"SARIF gen failed: {e}"}, 500)
                    return

            body = json.dumps(sarif, indent=2).encode("utf-8", errors="replace")
            safe = (result.get("target", "report") or "report").replace("/", "_").replace(":", "_")
            self.send_file(body, "application/json", f"zerothreat_{safe}_{jid[-6:]}.sarif")
            return

        self.send_json({"error": "Not found"}, 404)

    # ─── POST ───────────────────────────────────────────────────────────

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        data = self.read_body()

        if path == "/api/scan":
            target = (data.get("target") or "").strip()
            if not target:
                self.send_json({"error": "target required"}, 400)
                return

            scan_type = data.get("scan_type", "both")
            profile_name = data.get("profile", "normal")
            owner_confirmed = bool(data.get("owner_confirmed", False))
            internet_exposed = bool(data.get("internet_exposed", False))
            auth_cookies = data.get("auth_cookies", "") or ""
            passive_only = bool(data.get("passive_only", False))
            port_start = int(data.get("port_start", 1))
            port_end = int(data.get("port_end", 1024))

            if profile_name not in SCAN_PROFILES:
                profile_name = "normal"

            job_id = f"job_{int(time.time() * 1000)}"
            scan_jobs[job_id] = {
                "status": "queued",
                "target": target,
                "progress": 0,
                "log": [],
                "result": None,
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }

            t = threading.Thread(
                target=run_scan_job,
                args=(
                    job_id, target, scan_type, profile_name,
                    (port_start, port_end),
                    owner_confirmed, internet_exposed,
                    auth_cookies, passive_only
                ),
                daemon=True
            )
            t.start()

            self.send_json({"job_id": job_id, "message": "Scan started"})
            return

        if path == "/api/diff":
            old_id = (data.get("old_scan_id") or "").strip()
            new_id = (data.get("new_scan_id") or "").strip()
            if not old_id or not new_id:
                self.send_json({"error": "old_scan_id and new_scan_id required"}, 400)
                return
            self.send_json(diff_scans(old_id, new_id))
            return

        if path == "/api/scan/cancel":
            jid = (data.get("job_id") or "").strip()
            if jid in scan_jobs:
                scan_jobs[jid]["status"] = "cancelled"
                self.send_json({"message": "Cancelled"})
            else:
                self.send_json({"error": "Not found"}, 404)
            return

        self.send_json({"error": "Not found"}, 404)

    # ─── DELETE ─────────────────────────────────────────────────────────

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        p = lambda k, d=None: params.get(k, [d])[0]

        if path == "/api/scan":
            jid = p("job_id") or p("scan_id")
            if not jid:
                self.send_json({"error": "job_id or scan_id required"}, 400)
                return

            if jid in scan_jobs:
                del scan_jobs[jid]
            try:
                delete_scan(jid)
            except Exception:
                pass

            self.send_json({"message": "Deleted"})
            return

        self.send_json({"error": "Not found"}, 404)


# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────

def run_server(host="0.0.0.0", port=8080):
    server = HTTPServer((host, port), Handler)
    print(f"""
╔══════════════════════════════════════════════════════════╗
║     ZeroThreat AI VAPT Scanner v3.0                     ║
║     Dashboard  → http://localhost:{port}                     ║
║     API Docs   → /api/* endpoints                       ║
║     History DB → zerothreat_history.db                  ║
║     Plugins    → checks/network/*.py  checks/web/*.py   ║
║     Press Ctrl+C to stop                                ║
╚══════════════════════════════════════════════════════════╝
""")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
        server.server_close()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port=port)