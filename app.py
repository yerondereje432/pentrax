from __future__ import annotations

import csv
import ipaddress
import io
import json
import os
import secrets
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, jsonify, redirect, render_template, request, send_file, session, url_for

from parser import compare_reports, finding_key, flatten_findings, load_report, report_metadata, summarise_report


BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = Path(os.environ.get("YERSCAN_REPORT_DIR", BASE_DIR / "reports"))
REPORT_DIR.mkdir(parents=True, exist_ok=True)
STATUS_FILE = Path(os.environ.get("YERSCAN_STATUS_FILE", BASE_DIR / "statuses.json"))
STATUS_VALUES = ("Open", "In Progress", "Resolved")

app = Flask(__name__)
app.config.from_mapping(
    SECRET_KEY=os.environ.get("YERSCAN_SECRET_KEY") or secrets.token_hex(32),
    YERSCAN_PASSWORD=os.environ.get("YERSCAN_PASSWORD"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024


def _safe_next_url(value: str | None) -> str | None:
    """Only allow redirects back into this dashboard after login."""
    if not value:
        return None
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc or not parsed.path.startswith("/"):
        return None
    return value


@app.before_request
def require_authentication():
    if request.endpoint in {"login", "static"}:
        return None
    if session.get("authenticated") is not True:
        return redirect(url_for("login", next=request.full_path.rstrip("?")))
    return None


@app.route("/login", methods=["GET", "POST"])
def login():
    next_url = request.form.get("next") or request.args.get("next")
    error = None
    if request.method == "POST":
        configured_password = app.config.get("YERSCAN_PASSWORD")
        submitted_password = request.form.get("password", "")
        if configured_password and secrets.compare_digest(submitted_password, configured_password):
            session.clear()
            session["authenticated"] = True
            return redirect(_safe_next_url(next_url) or url_for("reports_list"))
        error = "Invalid password." if configured_password else "Authentication is not configured. Set YERSCAN_PASSWORD before starting the dashboard."
    return render_template("login.html", error=error, next_url=next_url or "")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


def report_paths() -> list[Path]:
    return sorted((path for path in REPORT_DIR.glob("*.json") if path.is_file()), key=lambda path: path.stat().st_mtime, reverse=True)


def available_reports() -> list[dict]:
    items = []
    for path in report_paths():
        try:
            report = load_report(path)
        except (OSError, ValueError, TypeError):
            continue
        items.append(report_metadata(path.name, report))
    return items


def _scan_sort_key(item: dict) -> tuple[datetime, str]:
    value = str(item.get("scan_time") or "")
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        timestamp = datetime.min
    return timestamp, str(item.get("name") or "")


def history_context() -> dict:
    """Build chronological scan entries, same-target diffs, and chart series."""
    reports = available_reports()
    reports_by_target: dict[str, list[dict]] = {}
    for item in reports:
        reports_by_target.setdefault(str(item.get("target") or "Unknown target"), []).append(item)

    entries = []
    chart_data = {}
    for target, target_reports in reports_by_target.items():
        ordered = sorted(target_reports, key=_scan_sort_key)
        chart_data[target] = [
            {
                "name": item["name"],
                "scan_time": item.get("scan_time", ""),
                "open_ports": item.get("open_ports", 0),
                "cves_found": item.get("cves_found", 0),
            }
            for item in ordered
        ]
        previous_report = None
        previous_item = None
        for item in ordered:
            current_report = load_report(REPORT_DIR / item["name"])
            entries.append(
                {
                    **item,
                    "previous": previous_item,
                    "diff": compare_reports(previous_report, current_report) if previous_report is not None else None,
                }
            )
            previous_report = current_report
            previous_item = item

    entries.sort(key=_scan_sort_key)
    return {"entries": entries, "chart_data": chart_data, "targets": sorted(chart_data)}


def safe_report_path(name: str) -> Path | None:
    path = Path(name)
    if path.name != name or path.suffix.lower() != ".json":
        return None
    candidate = (REPORT_DIR / path.name).resolve()
    try:
        candidate.relative_to(REPORT_DIR.resolve())
    except ValueError:
        return None
    return candidate


def load_statuses() -> dict[str, str]:
    """Load remediation statuses without modifying the read-only scan reports."""
    if not STATUS_FILE.is_file():
        return {}
    try:
        payload = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        app.logger.warning("Could not read remediation status file: %s", STATUS_FILE)
        return {}
    if not isinstance(payload, dict):
        return {}
    return {str(key): value for key, value in payload.items() if value in STATUS_VALUES}


def save_statuses(statuses: dict[str, str]) -> None:
    """Atomically save statuses so a partial write cannot corrupt the local store."""
    STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=STATUS_FILE.parent,
            prefix=f".{STATUS_FILE.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            json.dump(statuses, temporary_file, indent=2, sort_keys=True)
            temporary_file.write("\n")
        temporary_path.replace(STATUS_FILE)
    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()


def finding_statuses(summary: dict) -> None:
    """Attach display-only keys and statuses to flattened findings."""
    statuses = load_statuses()
    for row in summary["findings"]:
        row["finding_key"] = finding_key(row)
        row["status"] = statuses.get(row["finding_key"], "Open")


@app.get("/")
def reports_list():
    return render_template("reports_list.html", reports=available_reports())


@app.get("/history")
def scan_history():
    context = history_context()
    return render_template("history.html", reports=available_reports(), **context)


def render_reports_page(*, scan_error: str | None = None, scan_target: str = "", scan_preset: str = "quick"):
    return render_template(
        "reports_list.html",
        reports=available_reports(),
        scan_error=scan_error,
        scan_target=scan_target,
        scan_preset=scan_preset,
    )


@app.post("/scans")
def run_scan():
    target = request.form.get("target", "").strip()
    preset = request.form.get("preset", "").strip().lower()
    allowed_presets = {"quick", "fast", "full", "stealth"}

    if not target:
        return render_reports_page(scan_error="Enter an IP address or CIDR target.", scan_target=target, scan_preset=preset)
    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError:
        return render_reports_page(scan_error="Target must be a valid IP address or CIDR range.", scan_target=target, scan_preset=preset)
    if preset not in allowed_presets:
        return render_reports_page(scan_error="Choose a valid scan preset.", scan_target=target, scan_preset="quick")

    output_base = REPORT_DIR / f"yerscan_{datetime.now():%Y%m%d_%H%M%S_%f}"
    output_path = Path(f"{output_base}.json")
    command = [sys.executable, "yerscan.py", target, f"--{preset}", "-y", "-o", str(output_base)]
    try:
        result = subprocess.run(
            command,
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        return render_reports_page(
            scan_error=f"Could not start yerscan.py: {exc}",
            scan_target=target,
            scan_preset=preset,
        )

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "The scanner exited without a diagnostic.").strip()
        return render_reports_page(
            scan_error=f"Scan failed: {detail[-500:]}",
            scan_target=target,
            scan_preset=preset,
        )
    if not output_path.is_file():
        return render_reports_page(
            scan_error="Scan finished but did not produce a JSON report.",
            scan_target=target,
            scan_preset=preset,
        )
    try:
        load_report(output_path)
    except (OSError, ValueError, TypeError) as exc:
        return render_reports_page(
            scan_error=f"Scan produced an invalid JSON report: {exc}",
            scan_target=target,
            scan_preset=preset,
        )
    return redirect(url_for("report_detail", name=output_path.name))


@app.get("/reports/<name>")
def report_detail(name: str):
    path = safe_report_path(name)
    if path is None or not path.is_file():
        return redirect(url_for("reports_list"))
    report = load_report(path)
    return render_template("report_detail.html", report=report, report_name=name, summary=summarise_report(report), reports=available_reports())


@app.get("/reports/<name>/findings")
def findings(name: str):
    path = safe_report_path(name)
    if path is None or not path.is_file():
        return redirect(url_for("reports_list"))
    report = load_report(path)
    summary = summarise_report(report)
    finding_statuses(summary)
    return render_template("findings.html", report=report, report_name=name, summary=summary, reports=available_reports())


@app.get("/api/reports")
def reports_api():
    return jsonify({"reports": available_reports(), "directory": str(REPORT_DIR)})


@app.get("/api/reports/<name>")
def report_api(name: str):
    path = safe_report_path(name)
    if path is None or not path.is_file():
        return jsonify({"error": "Report not found"}), 404
    report = load_report(path)
    return jsonify({"name": name, "report": report, "summary": summarise_report(report)})


@app.post("/api/findings/status")
def update_finding_status():
    payload = request.get_json(silent=True) or {}
    key = str(payload.get("key") or "").strip()
    status = payload.get("status")
    if not key:
        return jsonify({"error": "A finding key is required"}), 400
    if status not in STATUS_VALUES:
        return jsonify({"error": "Status must be Open, In Progress, or Resolved"}), 400
    statuses = load_statuses()
    statuses[key] = status
    try:
        save_statuses(statuses)
    except OSError:
        app.logger.exception("Could not save remediation status file: %s", STATUS_FILE)
        return jsonify({"error": "Could not save remediation status"}), 500
    return jsonify({"key": key, "status": status})


@app.post("/api/reports/upload")
def upload_report():
    upload = request.files.get("report")
    if upload is None or not upload.filename:
        return jsonify({"error": "Choose a yerscan JSON report first"}), 400
    filename = Path(upload.filename).name
    if not filename.lower().endswith(".json"):
        return jsonify({"error": "Upload a .json report file"}), 400
    try:
        payload = json.load(upload.stream)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return jsonify({"error": "The uploaded file is not valid JSON"}), 400
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), dict):
        return jsonify({"error": "This does not look like a yerscan JSON report"}), 400
    path = REPORT_DIR / filename
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return jsonify({"name": filename, "redirect": url_for("report_detail", name=filename)})


@app.get("/reports/<name>/download")
def download_report(name: str):
    path = safe_report_path(name)
    if path is None or not path.is_file():
        return jsonify({"error": "Report not found"}), 404
    return send_file(path, as_attachment=True, download_name=path.name, mimetype="application/json")


@app.get("/reports/<name>/pdf")
def download_pdf(name: str):
    """Render and download a clean PDF report summary."""
    path = safe_report_path(name)
    if path is None or not path.is_file():
        return redirect(url_for("reports_list"))

    try:
        from xhtml2pdf import pisa
    except ImportError:
        app.logger.exception("xhtml2pdf is unavailable; install the application requirements.")
        return jsonify({"error": "PDF export is unavailable because xhtml2pdf is not installed."}), 503

    report = load_report(path)
    html = render_template(
        "report_print.html",
        report=report,
        report_name=name,
        summary=summarise_report(report),
        print_css=(BASE_DIR / "static" / "css" / "print.css").read_text(encoding="utf-8"),
    )
    pdf_buffer = io.BytesIO()
    try:
        status = pisa.CreatePDF(html, dest=pdf_buffer, path=str(BASE_DIR))
    except (OSError, ValueError, TypeError):
        app.logger.exception("xhtml2pdf could not render the PDF.")
        return jsonify({"error": "PDF export failed while rendering the report."}), 500
    if status.err:
        app.logger.error("xhtml2pdf reported errors while rendering the PDF.")
        return jsonify({"error": "PDF export failed while rendering the report."}), 500
    pdf_buffer.seek(0)
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f"{path.stem}_summary.pdf",
        mimetype="application/pdf",
    )


@app.get("/reports/<name>/findings.csv")
def findings_csv(name: str):
    path = safe_report_path(name)
    if path is None or not path.is_file():
        return jsonify({"error": "Report not found"}), 404
    output = io.StringIO()
    statuses = load_statuses()
    fields = ["host_ip", "port", "service", "version", "risk_level", "cve_id", "cvss_score", "description", "status"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(
        {
            **{key: row.get(key, "") for key in fields if key != "status"},
            "status": statuses.get(finding_key(row), "Open"),
        }
        for row in flatten_findings(load_report(path))
    )
    return send_file(io.BytesIO(output.getvalue().encode("utf-8")), as_attachment=True, download_name=f"{Path(name).stem}_findings.csv", mimetype="text/csv")


@app.context_processor
def inject_globals():
    return {"report_dir": str(REPORT_DIR), "current_year": datetime.now().year}


if __name__ == "__main__":
    app.run(host=os.environ.get("YERSCAN_HOST", "127.0.0.1"), port=int(os.environ.get("YERSCAN_PORT", "5000")), debug=True)
