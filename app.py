from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path
from datetime import datetime

from flask import Flask, jsonify, redirect, render_template, request, send_file, url_for

from parser import load_report, report_metadata, summarise_report


BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = Path(os.environ.get("YERSCAN_REPORT_DIR", BASE_DIR / "reports"))
REPORT_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024


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


@app.get("/")
def reports_list():
    return render_template("reports_list.html", reports=available_reports())


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
    return render_template("findings.html", report=report, report_name=name, summary=summarise_report(report), reports=available_reports())


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


@app.get("/reports/<name>/findings.csv")
def findings_csv(name: str):
    from parser import flatten_findings

    path = safe_report_path(name)
    if path is None or not path.is_file():
        return jsonify({"error": "Report not found"}), 404
    output = io.StringIO()
    fields = ["host_ip", "port", "service", "version", "risk_level", "cve_id", "cvss_score", "description"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows({key: row.get(key, "") for key in fields} for row in flatten_findings(load_report(path)))
    return send_file(io.BytesIO(output.getvalue().encode("utf-8")), as_attachment=True, download_name=f"{Path(name).stem}_findings.csv", mimetype="text/csv")


@app.context_processor
def inject_globals():
    return {"report_dir": str(REPORT_DIR), "current_year": datetime.now().year}


if __name__ == "__main__":
    app.run(host=os.environ.get("YERSCAN_HOST", "127.0.0.1"), port=int(os.environ.get("YERSCAN_PORT", "5000")), debug=True)
