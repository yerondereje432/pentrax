"""Starlette Application and REST / WebSocket API for PENTRAX Web."""

import asyncio
import io
import json
import logging
import os
import platform
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Dict, Any, Optional, List

logger = logging.getLogger("pentrax.web")

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse, HTMLResponse, FileResponse, Response
from starlette.routing import Route, WebSocketRoute, Mount
from starlette.staticfiles import StaticFiles
from starlette.websockets import WebSocket, WebSocketDisconnect

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enforces hardening security headers (CSP, X-Frame-Options, X-Content-Type-Options, etc.)."""
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' cdn.tailwindcss.com cdnjs.cloudflare.com unpkg.com; "
            "style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' ws: wss:; "
            "font-src 'self' cdnjs.cloudflare.com;"
        )
        return response

class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """Enforces API Key verification if PENTRAX_API_KEY environment variable is set."""
    async def dispatch(self, request, call_next):
        required_key = os.environ.get("PENTRAX_API_KEY")
        # If no key configured in environment, keep open for local usage
        if not required_key:
            return await call_next(request)

        # Allow index and static assets without authentication
        path = request.url.path
        if path == "/" or path.startswith("/static"):
            return await call_next(request)

        # Allow websocket connections to authenticate via query param or header
        provided_key = request.headers.get("X-API-Key")
        if not provided_key:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                provided_key = auth_header[7:].strip()
        if not provided_key:
            provided_key = request.query_params.get("api_key")

        if provided_key != required_key:
            return JSONResponse({"error": "Unauthorized: Invalid or missing PENTRAX_API_KEY"}, status_code=401)

        return await call_next(request)

# Ensure ROOT_DIR in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
from pentrax import *
import pentrax as ys
from scanner.reporting import generate_executive_summary, generate_markdown as generate_tech_markdown
from scanner.recon import PassiveRecon
from scanner.threat_intel import threat_intel
from scanner.tls_audit import tls_auditor
from scanner.vuln_feed import CVEFeedUpdater
from web.manager import scan_manager, ScanInstance
from web.db import db_manager
from web.rate_limiter import rate_limiter

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)


def get_current_user(request) -> Optional[Dict[str, Any]]:
    """Resolve active user from session cookie or X-Session-Token header."""
    token = request.headers.get("X-Session-Token")
    if not token:
        token = request.cookies.get("pentrax_session")
    if token:
        user = db_manager.get_user_from_session(token)
        if user:
            return user
    return None


async def index(request):
    """Serve the single-page Cyber SOC web interface."""
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse("<h1>PENTRAX Web UI under construction</h1>", status_code=200)
    with open(index_file, "r", encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content)


async def get_system_capabilities(request):
    """Return host platform capabilities and privilege status."""
    is_root = ys.IS_ROOT
    return JSONResponse({
        "version": ys.VERSION,
        "is_root": is_root,
        "platform": platform.platform(),
        "python_version": sys.version.split()[0],
        "active_scans": sum(1 for s in scan_manager.scans.values() if s.status == "running"),
        "total_scans": len(scan_manager.scans),
        "supported_scan_types": [
            {"id": "connect", "name": "TCP Connect", "requires_root": False, "recommended": not is_root},
            {"id": "syn", "name": "SYN Stealth Scan", "requires_root": True, "recommended": is_root},
            {"id": "ack", "name": "ACK Firewall Probe", "requires_root": True, "recommended": False},
            {"id": "fin", "name": "FIN Scan", "requires_root": True, "recommended": False},
            {"id": "xmas", "name": "XMAS Scan", "requires_root": True, "recommended": False},
            {"id": "null", "name": "NULL Scan", "requires_root": True, "recommended": False},
            {"id": "window", "name": "TCP Window Scan", "requires_root": True, "recommended": False},
        ],
        "default_scan_type": "syn" if is_root else "connect",
    })


async def api_login(request):
    """Authenticate user with username and password, issuing session token with rate limit protection."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    if not rate_limiter.is_allowed(client_ip):
        return JSONResponse(
            {"error": "Too many failed attempts. Temporary lockout in effect (try again in 15 minutes)."},
            status_code=429,
            headers={"Retry-After": "900"}
        )

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    username = body.get("username", "")
    password = body.get("password", "")
    user = db_manager.authenticate_user(username, password)
    if not user:
        rate_limiter.record_failure(client_ip)
        return JSONResponse({"error": "Invalid username or password"}, status_code=401)

    rate_limiter.reset(client_ip)
    token = db_manager.create_session(user, ip=client_ip)
    db_manager.log_audit(user["id"], "LOGIN", ip=client_ip)
    response = JSONResponse({
        "message": "Authentication successful",
        "user": user,
        "token": token
    })
    response.set_cookie("pentrax_session", token, httponly=True, samesite="lax", max_age=86400 * 7)
    return response


async def api_logout(request):
    """Revoke user session."""
    user = get_current_user(request)
    token = request.headers.get("X-Session-Token") or request.cookies.get("pentrax_session")
    if token:
        db_manager.revoke_session(token)
    if user:
        db_manager.log_audit(user["id"], "LOGOUT", ip=request.client.host if request.client else None)
    response = JSONResponse({"message": "Logged out successfully"})
    response.delete_cookie("pentrax_session")
    return response


async def api_current_user(request):
    """Return currently authenticated user profile."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"authenticated": False, "user": None}, status_code=401)
    return JSONResponse({"authenticated": True, "user": user})


async def list_scans(request):
    """List scans filtered by user role (Admin sees all; Operator sees only own), with optional pagination."""
    current_user = get_current_user(request)
    params = request.query_params
    page_param = params.get("page")
    if page_param:
        try:
            page = int(page_param)
            per_page = int(params.get("per_page", 25))
            sort = params.get("sort", "created_at")
            order = params.get("order", "desc")
            return JSONResponse(db_manager.list_scans(user=current_user, page=page, per_page=per_page, sort=sort, order=order))
        except ValueError:
            pass
    return JSONResponse(scan_manager.list_scans(user=current_user))


async def diff_scans_endpoint(request):
    """Compute network drift, port deltas, and vulnerability changes between two scans."""
    scan_id_a = request.path_params.get("scan_id")
    scan_id_b = request.path_params.get("other_scan_id")
    diff_data = db_manager.diff_scans(scan_id_a, scan_id_b)
    if not diff_data:
        return JSONResponse({"error": "One or both scans not found"}, status_code=404)
    return JSONResponse(diff_data)


async def start_scan(request):
    """Validate input parameters and start a new scan job respecting RBAC roles."""
    current_user = get_current_user(request)
    if current_user and current_user.get("role") == "viewer":
        return JSONResponse({"error": "Forbidden: Viewers are not authorized to launch scans"}, status_code=403)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    target = body.get("target", "").strip()
    if not target:
        return JSONResponse({"error": "Target IP, CIDR, or hostname is required"}, status_code=400)

    # Concurrency gate: enforce single active scan to prevent module-level race conditions
    if scan_manager.is_busy():
        return JSONResponse({"error": "Another scan is currently in progress. Please wait for it to complete or stop it first."}, status_code=409)

    # Validate target using pentrax.parse_target
    resolved_hosts = ys.parse_target(target)
    if not resolved_hosts:
        return JSONResponse({"error": f"Invalid target or host could not be resolved: '{target}'"}, status_code=400)

    # Cloud metadata SSRF protection
    if any(ys.is_cloud_metadata_ip(h) for h in resolved_hosts):
        return JSONResponse({"error": "Scanning cloud metadata endpoints (169.254.169.254) is forbidden (SSRF protection)."}, status_code=400)

    # Build scan config with pinned IPs to prevent DNS rebinding TOCTOU
    config = {
        "target": target,
        "pinned_ips": resolved_hosts,
        "ports": body.get("ports", "top100"),
        "scan_type": body.get("scan_type", "syn" if ys.IS_ROOT else "connect"),
        "timing": body.get("timing", "T3"),
        "concurrency": int(body.get("concurrency", 2000)),
        "timeout": float(body.get("timeout", 1.5)),
        "deep": bool(body.get("deep", True)),
        "dast": bool(body.get("dast", True)),
        "ssl_audit": bool(body.get("ssl_audit", True)),
        "verify": bool(body.get("verify", True)),
        "udp": bool(body.get("udp", False)),
        "icmp": bool(body.get("icmp", False)),
        "evasive": bool(body.get("evasive", False)),
        "max_delay": float(body.get("max_delay", 2.0)),
        "decoy": body.get("decoy") or None,
        "mtu": int(body.get("mtu", 0)),
        "exclude": body.get("exclude") or None,
        "authorized": bool(body.get("authorized", True)),
    }

    owner_id = current_user.get("id") if current_user else None
    instance = scan_manager.create_scan(config, owner_id=owner_id)
    scan_manager.start_scan(instance)
    if current_user:
        db_manager.log_audit(current_user["id"], "START_SCAN", target=target, ip=request.client.host if request.client else None)

    return JSONResponse({
        "message": "Scan initiated",
        "scan": instance.to_dict(full=False),
    }, status_code=202)


async def get_scan_details(request):
    """Fetch complete details, progress, logs, and results of a scan."""
    scan_id = request.path_params.get("scan_id")
    instance = scan_manager.get_scan(scan_id, full=True)
    if not instance:
        return JSONResponse({"error": "Scan not found"}, status_code=404)
    return JSONResponse(instance.to_dict(full=True))


async def stop_scan(request):
    """Stop an in-progress scan."""
    scan_id = request.path_params.get("scan_id")
    success = scan_manager.cancel_scan(scan_id)
    if not success:
        return JSONResponse({"error": "Scan not found or not currently running"}, status_code=400)
    return JSONResponse({"message": "Scan cancellation signal sent", "scan_id": scan_id})


async def delete_scan(request):
    """Delete a scan from history."""
    current_user = get_current_user(request)
    if current_user and current_user.get("role") == "viewer":
        return JSONResponse({"error": "Forbidden: Viewers cannot delete scan records"}, status_code=403)

    scan_id = request.path_params.get("scan_id")
    success = scan_manager.delete_scan(scan_id, user=current_user)
    if not success:
        return JSONResponse({"error": "Scan not found or permission denied"}, status_code=404)
    if current_user:
        db_manager.log_audit(current_user["id"], "DELETE_SCAN", target=scan_id, ip=request.client.host if request.client else None)
    return JSONResponse({"message": "Scan deleted", "scan_id": scan_id})


def generate_ciso_pdf_html(scan_id: str, data: Dict[str, Any]) -> str:
    """Generate high-contrast, publication-quality CISO Executive Dossier with print CSS."""
    import html as _html
    def _e(val):
        return _html.escape(str(val or ""))

    target = data.get("target", "127.0.0.1")
    scan_time = data.get("scan_time", "N/A")
    duration = data.get("duration_seconds", 0)
    scan_type = data.get("scan_type", "connect").upper()
    results = data.get("results", {})
    total_hosts = len(results)
    total_ports = data.get("total_open_ports", 0)

    crit_count = 0
    high_count = 0
    med_count = 0
    low_count = 0
    rows = []

    for ip, host_info in sorted(results.items()):
        h_risk = host_info.get("risk_level", "LOW")
        for p in host_info.get("ports", []):
            p_num = p.get("port")
            p_svc = p.get("service", "unknown")
            p_ver = p.get("version", "-")
            p_risk = p.get("risk_level", "INFO")

            cve_texts = [f"⚠ {c.get('cve')} (CVSS {c.get('cvss_score')})" for c in p.get("cves", [])]
            for c in p.get("cves", []):
                cvss = float(c.get("cvss_score", 7.5))
                if cvss >= 9.0: crit_count += 1
                elif cvss >= 7.0: high_count += 1
                else: med_count += 1

            for v in p.get("vulns", []):
                v_title = v.get("title", str(v)) if isinstance(v, dict) else str(v)
                cve_texts.append(f"⚡ {v_title}")
                sev = v.get("risk_level", "MEDIUM") if isinstance(v, dict) else "MEDIUM"
                if sev == "CRITICAL": crit_count += 1
                elif sev == "HIGH": high_count += 1
                elif sev == "MEDIUM": med_count += 1
                else: low_count += 1

            finding_summary = "<br>".join([_e(t) for t in cve_texts]) if cve_texts else "<span style='color:#6b7280'>No known CVEs</span>"
            risk_color = "#dc2626" if p_risk == "CRITICAL" else ("#ea580c" if p_risk == "HIGH" else ("#ca8a04" if p_risk == "MEDIUM" else "#16a34a"))

            rows.append(f"""
            <tr>
              <td style="font-family:monospace;font-weight:600">{_e(ip)}</td>
              <td style="font-family:monospace">{p_num} / {_e(p.get('protocol', 'tcp'))}</td>
              <td style="font-weight:600">{_e(p_svc)}</td>
              <td style="font-size:11px;color:#4b5563">{_e(p_ver)}</td>
              <td><span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:bold;color:#fff;background:{risk_color}">{_e(p_risk)}</span></td>
              <td style="font-size:11px">{finding_summary}</td>
            </tr>
            """)

    total_vulns = crit_count + high_count + med_count + low_count
    penalty = crit_count * 15 + high_count * 5 + med_count * 1
    posture_score = max(15, 100 - penalty) if total_hosts > 0 else 100
    grade = "A" if posture_score >= 90 else ("B" if posture_score >= 75 else ("C" if posture_score >= 60 else "F"))
    grade_color = "#16a34a" if grade == "A" else ("#0284c7" if grade == "B" else ("#d97706" if grade == "C" else "#dc2626"))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PENTRAX CISO Executive Dossier — {_e(target)}</title>
  <style>
    @page {{ size: A4; margin: 12mm 15mm; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; color: #111827; background: #ffffff; margin: 0; padding: 20px; font-size: 12px; line-height: 1.5; }}
    .no-print {{ background: #0f172a; color: #ffffff; padding: 12px 20px; margin: -20px -20px 20px -20px; display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #dc2626; }}
    .btn-print {{ background: #dc2626; color: #ffffff; border: none; padding: 8px 16px; font-weight: bold; border-radius: 6px; cursor: pointer; }}
    @media print {{ .no-print {{ display: none !important; }} body {{ padding: 0; }} .page-break {{ page-break-after: always; }} }}
    .header-box {{ border-bottom: 3px solid #dc2626; padding-bottom: 12px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: flex-end; }}
    .classification {{ display: inline-block; background: #fef2f2; color: #991b1b; border: 1px solid #f87171; padding: 2px 8px; font-size: 10px; font-weight: 800; letter-spacing: 1px; text-transform: uppercase; border-radius: 4px; margin-bottom: 6px; }}
    .posture-badge {{ display: flex; align-items: center; border: 2px solid {grade_color}; border-radius: 8px; padding: 10px 16px; background: #f8fafc; text-align: right; }}
    .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }}
    .kpi-card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px; }}
    .kpi-num {{ font-size: 20px; font-weight: 800; font-family: monospace; color: #0f172a; }}
    .sla-table, .data-table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 11px; }}
    .sla-table th, .data-table th {{ background: #f1f5f9; color: #334155; font-weight: 700; text-transform: uppercase; font-size: 10px; padding: 8px 10px; border-bottom: 2px solid #cbd5e1; text-align: left; }}
    .sla-table td, .data-table td {{ padding: 8px 10px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
    .section-title {{ font-size: 13px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; color: #0f172a; border-left: 4px solid #dc2626; padding-left: 8px; margin: 20px 0 10px 0; }}
    .footer-notice {{ font-size: 10px; color: #64748b; margin-top: 30px; border-top: 1px solid #e2e8f0; padding-top: 10px; display: flex; justify-content: space-between; }}
  </style>
</head>
<body>
  <div class="no-print">
    <div><strong>PENTRAX Executive Dossier Preview</strong> — Publication-Ready CISO Report</div>
    <button onclick="window.print()" class="btn-print">🖨️ Print / Save as PDF</button>
  </div>
  <div class="header-box">
    <div>
      <div class="classification">TLP:AMBER · EXECUTIVE CONFIDENTIAL</div>
      <h1 style="margin:0;font-size:22px;color:#0f172a;font-weight:900">ENTERPRISE ATTACK SURFACE & THREAT DOSSIER</h1>
      <div style="color:#64748b;font-size:11px;margin-top:4px">
        Assessment ID: <code>{_e(scan_id)}</code> · Target Scope: <strong>{_e(target)}</strong> · Executed: {_e(scan_time)}
      </div>
    </div>
    <div class="posture-badge">
      <div>
        <div style="font-size:10px;font-weight:bold;color:#64748b;text-transform:uppercase">Global Posture</div>
        <div style="font-size:24px;font-weight:900;color:{grade_color};font-family:monospace">GRADE {grade} ({posture_score}/100)</div>
      </div>
    </div>
  </div>
  <div class="kpi-grid">
    <div class="kpi-card">
      <div style="font-size:10px;color:#64748b;font-weight:bold;text-transform:uppercase">Perimeter Scope</div>
      <div class="kpi-num">{total_hosts} <span style="font-size:11px;color:#64748b;font-weight:normal">Hosts Mapped</span></div>
    </div>
    <div class="kpi-card">
      <div style="font-size:10px;color:#64748b;font-weight:bold;text-transform:uppercase">Exposed Surface</div>
      <div class="kpi-num">{total_ports} <span style="font-size:11px;color:#64748b;font-weight:normal">Open Ports</span></div>
    </div>
    <div class="kpi-card">
      <div style="font-size:10px;color:#64748b;font-weight:bold;text-transform:uppercase">Critical Vulnerabilities</div>
      <div class="kpi-num" style="color:#dc2626">{crit_count} <span style="font-size:11px;color:#dc2626;font-weight:normal">48h SLA</span></div>
    </div>
    <div class="kpi-card">
      <div style="font-size:10px;color:#64748b;font-weight:bold;text-transform:uppercase">Total Flaws</div>
      <div class="kpi-num">{total_vulns} <span style="font-size:11px;color:#64748b;font-weight:normal">Findings</span></div>
    </div>
  </div>
  <div class="section-title">Remediation SLA & Compliance Governance</div>
  <table class="sla-table">
    <thead>
      <tr>
        <th>Severity Category</th>
        <th>Discovered Flaws</th>
        <th>Mandatory SLA</th>
        <th>Governing Frameworks</th>
        <th>Remediation Priority</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td style="color:#dc2626;font-weight:bold">🔴 Critical</td>
        <td><strong>{crit_count}</strong></td>
        <td>48 Hours</td>
        <td>NIST CSF PR.IP-12, PCI-DSS 11.2</td>
        <td>Immediate containment / patch</td>
      </tr>
      <tr>
        <td style="color:#ea580c;font-weight:bold">🟠 High</td>
        <td><strong>{high_count}</strong></td>
        <td>14 Days</td>
        <td>CIS Control 7.5</td>
        <td>Sprint priority patch cycle</td>
      </tr>
      <tr>
        <td style="color:#ca8a04;font-weight:bold">🟡 Medium</td>
        <td><strong>{med_count}</strong></td>
        <td>30 Days</td>
        <td>ISO/IEC 27001 A.12.6</td>
        <td>Routine patching window</td>
      </tr>
    </tbody>
  </table>
  <div class="section-title">Exposed Assets & Vulnerability Findings Inventory</div>
  <table class="data-table">
    <thead>
      <tr>
        <th>Host IP</th>
        <th>Port / Proto</th>
        <th>Service</th>
        <th>Version / Banner</th>
        <th>Risk Rating</th>
        <th>Vulnerability Details & MITRE ATT&CK</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows) if rows else '<tr><td colspan="6" style="text-align:center;color:#64748b;padding:16px">No exposed ports detected.</td></tr>'}
    </tbody>
  </table>
  <div class="footer-notice">
    <span>PENTRAX v8.2 Enterprise Attack Surface Intelligence Engine</span>
    <span>Confidential — For Internal CISO & Security Operations Use Only</span>
  </div>
</body>
</html>"""


async def export_scan(request):
    """Export scan results in requested format."""
    scan_id = request.path_params.get("scan_id")
    export_format = request.path_params.get("format", "json").lower()
    instance = scan_manager.get_scan(scan_id, full=True)

    if not instance:
        return JSONResponse({"error": "Scan not found"}, status_code=404)

    if not instance.result:
        return JSONResponse({"error": "No scan results available to export"}, status_code=400)

    result_data = instance.result

    if export_format in ("pdf", "dossier"):
        pdf_html = generate_ciso_pdf_html(scan_id, result_data)
        return HTMLResponse(pdf_html)

    if export_format == "json":
        json_bytes = json.dumps(result_data, indent=2).encode("utf-8")
        return Response(
            content=json_bytes,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="pentrax_{scan_id}.json"'},
        )

    with tempfile.NamedTemporaryFile(suffix=f".{export_format}", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        if export_format == "csv":
            ys.export_csv(result_data, tmp_path)
            with open(tmp_path, "rb") as f:
                content = f.read()
            return Response(
                content=content,
                media_type="text/csv",
                headers={"Content-Disposition": f'attachment; filename="pentrax_{scan_id}.csv"'},
            )
        elif export_format in ("md", "markdown"):
            md_text = ys.generate_markdown(result_data)
            return Response(
                content=md_text.encode("utf-8"),
                media_type="text/markdown",
                headers={"Content-Disposition": f'attachment; filename="README_{scan_id}.md"'},
            )
        elif export_format in ("executive", "exec"):
            exec_text = generate_executive_summary(result_data)
            return Response(
                content=exec_text.encode("utf-8"),
                media_type="text/markdown",
                headers={"Content-Disposition": f'attachment; filename="Executive_Summary_{scan_id}.md"'},
            )
        elif export_format in ("technical", "tech"):
            tech_text = generate_tech_markdown(result_data)
            return Response(
                content=tech_text.encode("utf-8"),
                media_type="text/markdown",
                headers={"Content-Disposition": f'attachment; filename="Technical_Report_{scan_id}.md"'},
            )
        elif export_format == "html":
            ys.export_html(result_data, tmp_path)
            with open(tmp_path, "rb") as f:
                content = f.read()
            return Response(
                content=content,
                media_type="text/html",
                headers={"Content-Disposition": f'attachment; filename="pentrax_{scan_id}.html"'},
            )
        else:
            return JSONResponse({"error": f"Unsupported format: '{export_format}'"}, status_code=400)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


async def api_passive_recon(request):
    """Run passive OSINT reconnaissance on domain or IP."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    domain = body.get("domain", "").strip()
    if not domain:
        return JSONResponse({"error": "Domain or target is required"}, status_code=400)
    recon = PassiveRecon()
    res = await recon.run(domain)
    return JSONResponse(res.to_dict())


async def api_threat_intel(request):
    """Query threat intelligence reputation and Tor exit status for an IP."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    ip_addr = body.get("ip", "").strip()
    if not ip_addr:
        return JSONResponse({"error": "IP address is required"}, status_code=400)
    profile = await threat_intel.check(ip_addr)
    return JSONResponse(profile.to_dict())


async def api_tls_audit(request):
    """Perform cryptographic TLS certificate and cipher suite audit."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    host = body.get("host", "").strip()
    port = int(body.get("port", 443))
    if not host:
        return JSONResponse({"error": "Host is required"}, status_code=400)
    report = tls_auditor.audit(host, port)
    return JSONResponse(report.to_dict())


async def api_cve_sync(request):
    """Trigger background or on-demand CVE catalog synchronization."""
    current_user = get_current_user(request)
    if current_user and current_user.get("role") != "admin":
        return JSONResponse({"error": "Forbidden: Admin role required for CVE sync"}, status_code=403)
    updater = CVEFeedUpdater()
    count = updater.sync(days_back=7)
    stats = updater.get_stats()
    return JSONResponse({"message": f"Synced {count} CVE records", "stats": stats})


async def api_cve_stats(request):
    """Retrieve local vulnerability catalog statistics."""
    updater = CVEFeedUpdater()
    return JSONResponse(updater.get_stats())


async def api_dashboard_stats(request):
    """Retrieve aggregate security posture metrics for the dashboard command center."""
    return JSONResponse(db_manager.get_dashboard_stats())


async def api_verify_node(request):
    """Safely verify if a target port/service is actively reachable and generate benign reproduction curl."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    host = body.get("host")
    port = body.get("port")
    service = body.get("service", "unknown")
    if not host or not port:
        return JSONResponse({"error": "Host and port are required"}, status_code=400)

    t0 = time.time()
    reachable = False
    banner = ""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, int(port)), timeout=2.0)
        reachable = True
        latency_ms = round((time.time() - t0) * 1000, 2)
        try:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=1.0)
            banner = data.decode("utf-8", errors="replace").split("\r\n")[0]
        except Exception:
            pass
        writer.close()
        await writer.wait_closed()
    except Exception:
        latency_ms = round((time.time() - t0) * 1000, 2)
        reachable = False

    scheme = "https" if int(port) in (443, 8443) or "ssl" in str(service).lower() else "http"
    safe_curl = f"curl -i -k -s --connect-timeout 3 \"{scheme}://{host}:{port}/\""

    return JSONResponse({
        "host": host,
        "port": port,
        "service": service,
        "reachable": reachable,
        "latency_ms": latency_ms,
        "banner": banner or ("TCP SYN/ACK open" if reachable else "Connection refused / timed out"),
        "safe_curl": safe_curl,
        "remediation": f"Isolate port {port} via firewall or network ACL if not intended for public access.",
        "cis_control": "CIS Control 4: Secure Configuration of Enterprise Assets and Software",
        "mitre_technique": "T1190: Exploit Public-Facing Application"
    })


async def dispatch_webhook(webhook_url: str, title: str, text: str, fields: list = None):
    """Dispatch formatted webhook alert to Discord, Slack, or generic HTTP receiver."""
    if not webhook_url:
        return
    payload = {}
    if "discord.com" in webhook_url:
        payload = {
            "embeds": [{
                "title": f"🚨 PENTRAX Alert: {title}",
                "description": text,
                "color": 16724548,
                "fields": [{"name": f.get("name"), "value": f.get("value"), "inline": True} for f in (fields or [])]
            }]
        }
    elif "slack.com" in webhook_url:
        payload = {
            "text": f"*PENTRAX Security Alert: {title}*\n{text}",
            "attachments": [{
                "color": "danger",
                "fields": [{"title": f.get("name"), "value": f.get("value"), "short": True} for f in (fields or [])]
            }]
        }
    else:
        payload = {"title": title, "text": text, "fields": fields or []}

    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "PENTRAX-ASM-Monitor/8.2"}
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        logger.warning(f"Webhook dispatch failed: {e}")


async def api_list_schedules(request):
    """List all automated perimeter schedules."""
    return JSONResponse(db_manager.list_schedules())


async def api_create_schedule(request):
    """Create a new automated perimeter schedule."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    name = body.get("name", "Perimeter Monitor")
    target = body.get("target")
    if not target:
        return JSONResponse({"error": "Target is required"}, status_code=400)
    ports = body.get("ports", "top100")
    scan_type = body.get("scan_type", "connect")
    interval = int(body.get("interval_minutes", 1440))
    webhook = body.get("webhook_url")
    sched_id = db_manager.create_schedule(name, target, ports, scan_type, interval, webhook)
    return JSONResponse({"id": sched_id, "status": "created"}, status_code=201)


async def api_delete_schedule(request):
    """Delete an automated perimeter schedule."""
    sched_id = request.path_params.get("schedule_id")
    deleted = db_manager.delete_schedule(sched_id)
    if deleted:
        return JSONResponse({"status": "deleted"})
    return JSONResponse({"error": "Schedule not found"}, status_code=404)


async def api_trigger_schedule(request):
    """Manually trigger an automated perimeter schedule."""
    sched_id = request.path_params.get("schedule_id")
    sched = db_manager.get_schedule(sched_id)
    if not sched:
        return JSONResponse({"error": "Schedule not found"}, status_code=404)
    instance = scan_manager.create_scan({
        "target": sched["target"],
        "ports": sched["ports"],
        "scan_type": sched["scan_type"]
    })
    scan_manager.start_scan(instance)
    db_manager.update_schedule_after_run(sched_id, sched["interval_minutes"])
    if sched.get("webhook_url"):
        await dispatch_webhook(
            sched["webhook_url"],
            f"Scheduled Scan Started: {sched['name']}",
            f"Triggered automated perimeter assessment on {sched['target']}",
            [{"name": "Target", "value": sched["target"]}, {"name": "Scan ID", "value": instance.id}]
        )
    return JSONResponse({"status": "triggered", "scan_id": instance.id})


async def scan_websocket(websocket: WebSocket):
    """WebSocket endpoint streaming live scan events and terminal logs."""
    await websocket.accept()
    scan_id = websocket.path_params.get("scan_id")
    instance = scan_manager.get_scan(scan_id, full=True)

    if not instance:
        await websocket.send_json({"type": "error", "message": f"Scan '{scan_id}' not found"})
        await websocket.close()
        return

    queue = asyncio.Queue(maxsize=100)
    instance._subscribers.add(queue)

    # Initial sync state
    try:
        await websocket.send_json({
            "type": "sync_state",
            "scan": instance.to_dict(full=True),
        })

        async def sender():
            while True:
                event = await queue.get()
                await websocket.send_json(event)

        async def receiver():
            while True:
                try:
                    msg = await websocket.receive_text()
                    try:
                        data = json.loads(msg)
                        if data.get("action") == "stop":
                            scan_manager.cancel_scan(scan_id)
                    except Exception:
                        pass
                except WebSocketDisconnect:
                    break

        sender_task = asyncio.create_task(sender())
        receiver_task = asyncio.create_task(receiver())

        done, pending = await asyncio.wait(
            [sender_task, receiver_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.debug(f"WebSocket closed with exception: {e}")
    finally:
        instance._subscribers.discard(queue)


routes = [
    Route("/", endpoint=index, methods=["GET"]),
    Route("/api/auth/login", endpoint=api_login, methods=["POST"]),
    Route("/api/auth/logout", endpoint=api_logout, methods=["POST"]),
    Route("/api/auth/me", endpoint=api_current_user, methods=["GET"]),
    Route("/api/system/capabilities", endpoint=get_system_capabilities, methods=["GET"]),
    Route("/api/scans", endpoint=list_scans, methods=["GET"]),
    Route("/api/scans/start", endpoint=start_scan, methods=["POST"]),
    Route("/api/scans/{scan_id}", endpoint=get_scan_details, methods=["GET"]),
    Route("/api/scans/{scan_id}/stop", endpoint=stop_scan, methods=["POST"]),
    Route("/api/scans/{scan_id}", endpoint=delete_scan, methods=["DELETE"]),
    Route("/api/scans/{scan_id}/export/{format}", endpoint=export_scan, methods=["GET"]),
    Route("/api/scans/{scan_id}/diff/{other_scan_id}", endpoint=diff_scans_endpoint, methods=["GET"]),
    Route("/api/recon", endpoint=api_passive_recon, methods=["POST"]),
    Route("/api/threat-intel", endpoint=api_threat_intel, methods=["POST"]),
    Route("/api/tls-audit", endpoint=api_tls_audit, methods=["POST"]),
    Route("/api/admin/cve-sync", endpoint=api_cve_sync, methods=["POST"]),
    Route("/api/admin/cve-catalog/stats", endpoint=api_cve_stats, methods=["GET"]),
    Route("/api/dashboard/stats", endpoint=api_dashboard_stats, methods=["GET"]),
    Route("/api/verify-node", endpoint=api_verify_node, methods=["POST"]),
    Route("/api/schedules", endpoint=api_list_schedules, methods=["GET"]),
    Route("/api/schedules", endpoint=api_create_schedule, methods=["POST"]),
    Route("/api/schedules/{schedule_id}", endpoint=api_delete_schedule, methods=["DELETE"]),
    Route("/api/schedules/{schedule_id}/trigger", endpoint=api_trigger_schedule, methods=["POST"]),
    WebSocketRoute("/ws/scans/{scan_id}", endpoint=scan_websocket),
    Mount("/static", app=StaticFiles(directory=str(STATIC_DIR)), name="static"),
]

middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    ),
    Middleware(SecurityHeadersMiddleware),
    Middleware(APIKeyAuthMiddleware),
]

app = Starlette(routes=routes, middleware=middleware)
