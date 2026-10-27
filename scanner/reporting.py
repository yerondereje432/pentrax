"""Dual-Mode Reporting Module for PENTRAX: CISO Executive Summary & Technical Dossiers."""
import csv
import html
import io
import json
from datetime import datetime
from typing import Any, Dict, List, Optional


def generate_executive_summary(data: Dict[str, Any]) -> str:
    """Generates an executive-level CISO summary with risk scoring, RAG rating, and business impact."""
    target = data.get("target", "Target Network")
    scan_time = data.get("scan_time", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    duration = data.get("duration_seconds", 0)
    hosts_alive = data.get("hosts_alive", len(data.get("results", {})))
    total_open = data.get("total_open_ports", 0)
    cves_found = data.get("cves_found", 0)
    vulns_found = data.get("vulns_found", 0)
    risky_services = data.get("risky_services", 0)

    # Collect all findings
    critical_findings: List[Dict[str, Any]] = []
    high_findings: List[Dict[str, Any]] = []
    medium_findings: List[Dict[str, Any]] = []

    results = data.get("results", {})
    for ip, host_info in results.items():
        for p in host_info.get("ports", []):
            for v in p.get("vulns", []):
                v_dict = v if isinstance(v, dict) else {"title": str(v), "severity": "MEDIUM", "cvss": 5.0}
                item = {
                    "host": ip,
                    "port": p.get("port"),
                    "service": p.get("service", "unknown"),
                    "title": v_dict.get("title", "Vulnerability"),
                    "severity": v_dict.get("severity", "MEDIUM").upper(),
                    "cvss": v_dict.get("cvss", 5.0),
                    "remediation": v_dict.get("remediation", "Update software or adjust configuration."),
                    "sla": v_dict.get("remediation_sla", "30 Days"),
                }
                sev = item["severity"]
                if sev == "CRITICAL":
                    critical_findings.append(item)
                elif sev == "HIGH":
                    high_findings.append(item)
                else:
                    medium_findings.append(item)

            for c in p.get("cves", []):
                item = {
                    "host": ip,
                    "port": p.get("port"),
                    "service": p.get("service", "unknown"),
                    "title": f"{c.get('cve', 'CVE')} — {c.get('description', '')[:70]}...",
                    "severity": "CRITICAL" if float(c.get("cvss_score", 0)) >= 9.0 else "HIGH",
                    "cvss": float(c.get("cvss_score", 7.5)),
                    "remediation": "Apply vendor security patch immediately.",
                    "sla": "7 Days" if float(c.get("cvss_score", 0)) >= 9.0 else "14 Days",
                }
                if item["severity"] == "CRITICAL":
                    critical_findings.append(item)
                else:
                    high_findings.append(item)

    crit_cnt = len(critical_findings)
    high_cnt = len(high_findings)

    # Determine RAG Status
    if crit_cnt > 0:
        rag_badge = "🔴 CRITICAL RISK"
        executive_posture = "IMMEDIATE ATTENTION REQUIRED: Exploitable critical vulnerabilities were identified that may allow unauthorized code execution or perimeter compromise."
    elif high_cnt > 0:
        rag_badge = "🟠 HIGH RISK"
        executive_posture = "ELEVATED RISK: Significant security deficiencies or outdated protocols were discovered that expose the infrastructure to targeted exploitation."
    elif total_open > 0:
        rag_badge = "🟡 MEDIUM RISK"
        executive_posture = "MODERATE POSTURE: Standard service endpoints detected. Ensure principle of least privilege and enforce hardened access controls."
    else:
        rag_badge = "🟢 LOW RISK"
        executive_posture = "STRONG POSTURE: Minimal perimeter footprint detected with no known critical vulnerabilities identified."

    lines = [
        "# 🛡️ Executive Cyber Security Assessment",
        f"**Target Scope**: `{target}` | **Classification**: Highly Confidential",
        f"**Report Generated**: `{scan_time}` | **Duration**: `{duration}s`",
        "",
        "---",
        "",
        "## 1. Executive Summary & Overall Risk Rating",
        "",
        f"### **Current Security Posture**: {rag_badge}",
        "",
        f"> **CISO Briefing**: {executive_posture}",
        "",
        "### Key Exposure Indicators",
        "| Indicator | Count | Business Risk Impact |",
        "| :--- | :---: | :--- |",
        f"| **Active Targets Scanned** | `{hosts_alive}` | Total infrastructure endpoints evaluated |",
        f"| **Exposed Open Services** | `{total_open}` | Network entry points reachable across perimeter |",
        f"| **Critical Vulnerabilities** | `{crit_cnt}` | High-probability breach vectors requiring urgent patching |",
        f"| **High Severity Flaws** | `{high_cnt}` | Significant flaws exposing confidential data or services |",
        f"| **Risky Unencrypted Services** | `{risky_services}` | Sensitive cleartext or management protocols (Telnet, Redis, SMB) |",
        "",
        "---",
        "",
        "## 2. Priority Remediation Action Matrix",
        "",
        "The following remediation actions are ordered by business impact and recommended Service Level Agreement (SLA):",
        "",
        "| Priority | Host / Port | Finding | Remediation Guidance | SLA Window |",
        "| :---: | :--- | :--- | :--- | :---: |",
    ]

    top_priorities = (critical_findings + high_findings)[:10]
    if not top_priorities:
        lines.append("| - | - | *No critical or high severity vulnerabilities discovered* | Maintain continuous monitoring | - |")
    else:
        for idx, f in enumerate(top_priorities, 1):
            prio_badge = "🔴 P1" if f["severity"] == "CRITICAL" else "🟠 P2"
            lines.append(f"| {prio_badge} | `{f['host']}:{f['port']}` | **{f['title']}** | {f['remediation']} | `{f['sla']}` |")

    lines.extend([
        "",
        "---",
        "",
        "## 3. Compliance & Governance Benchmarks",
        "",
        "- **CIS Critical Security Controls (v8)**: Controls 4.1 (Inventory) & 7.1 (Vulnerability Management)",
        "- **NIST CSF 2.0**: PR.PS-01 (Asset Protection) & DE.CM-01 (Perimeter Monitoring)",
        "- **PCI-DSS v4.0 Requirement 11**: Quarterly internal & external perimeter vulnerability scanning",
        "",
        "---",
        "",
        "## 4. Assessment Certification",
        "",
        "*Assessment performed autonomously by PENTRAX Enterprise Red Team Framework.*",
        "*Confidential report prepared for Security Operations (SecOps) & IT Management.*",
    ])

    return "\n".join(lines)


def generate_markdown(data: Dict[str, Any]) -> str:
    """Generate technical GitHub-flavored Markdown README / report string."""
    target = data.get("target", "Unknown")
    scan_time = data.get("scan_time", "N/A")
    duration = data.get("duration_seconds", 0)
    scan_type = data.get("scan_type", "connect").upper()
    hosts_alive = data.get("hosts_alive", len(data.get("results", {})))
    total_open = data.get("total_open_ports", 0)
    risky_services = data.get("risky_services", 0)
    cves_found = data.get("cves_found", 0)
    vulns_found = data.get("vulns_found", 0)

    lines = [
        "# 🛡️ PENTRAX Technical Security Assessment Dossier",
        f"### **TARGET: `{target}`**",
        "",
        f"- **Assessment Date**: `{scan_time}`",
        f"- **Scan Type**: `{scan_type}`",
        f"- **Duration**: `{duration}s`",
        "- **Engine**: PENTRAX v10.0 (Enterprise Red Team & Attack Surface Discovery)",
        "",
        "---",
        "",
        "## 📊 Metrics Overview",
        "",
        "| Metric | Count | Description |",
        "| :--- | :---: | :--- |",
        f"| **Hosts Discovered Alive** | `{hosts_alive}` | Total responsive targets in perimeter |",
        f"| **Open Ports Found** | `{total_open}` | Exposed external service endpoints |",
        f"| **Vulnerabilities Detected** | `{vulns_found}` | Exploits, weak configs, & DAST findings |",
        f"| **CVE Cross-References** | `{cves_found}` | Verified public CVE matches |",
        f"| **Inherently Risky Services** | `{risky_services}` | Sensitive services (e.g. Telnet, SMB, Redis) |",
        "",
        "---",
        "",
        "## 🔍 Port & Service Inventory",
        "",
        "| Host IP | Port / Proto | State | Service | Version / Banner | Findings & CVEs |",
        "| :--- | :---: | :---: | :--- | :--- | :--- |",
    ]

    results = data.get("results", {})
    if not results:
        lines.append("| - | - | - | - | *No open ports discovered* | - |")
    else:
        for ip, info in sorted(results.items()):
            ports = info.get("ports", [])
            for p in ports:
                port_num = p.get("port")
                proto = p.get("protocol", "tcp")
                state = p.get("state", "open")
                service = p.get("service", "unknown")
                version = p.get("version", "").strip() or "-"

                findings_parts = []
                for v in p.get("vulns", []):
                    title = v.get("title", str(v)) if isinstance(v, dict) else str(v)
                    findings_parts.append(f"⚠️ {title}")
                for c in p.get("cves", []):
                    cve_id = c.get("cve", "CVE")
                    cvss = c.get("cvss_score", "")
                    findings_parts.append(f"🛑 {cve_id} (CVSS {cvss})")

                findings_str = "<br>".join(findings_parts) if findings_parts else "-"
                lines.append(f"| `{ip}` | `{port_num}/{proto}` | `{state}` | `{service}` | {version} | {findings_str} |")

    return "\n".join(lines)


def export_json(data: Dict[str, Any], path: Optional[str] = None, indent: int = 2) -> str:
    """Exports scan data to JSON formatted string or file."""
    content = json.dumps(data, indent=indent, default=str)
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    return content


def sanitize_csv_cell(value: Any) -> str:
    """Sanitize a cell value to prevent CSV Formula Injection / DDE attacks in Excel/Sheets.

    Mirrors pentrax.sanitize_csv_cell: any cell whose text starts with
    =, +, -, @, a tab, or a carriage return is prefixed with a single
    quote so spreadsheet applications treat it as text, not a formula.
    Service banners and version strings are attacker-controlled, so a
    scanned host must not be able to weaponize the analyst's report.
    """
    if value is None:
        return ""
    cell = str(value)
    if cell and cell[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + cell
    return cell


def export_csv(data: Dict[str, Any], path: Optional[str] = None) -> str:
    """Exports scan findings and open ports to CSV string or file."""
    output = io.StringIO()
    writer = csv.writer(output)

    def _write_row(row):
        writer.writerow([sanitize_csv_cell(cell) for cell in row])
    writer.writerow([
        "Host", "Port", "Protocol", "State", "Service", "Version", "Vulnerability", "CVE", "Severity", "CVSS", "Remediation", "SLA"
    ])

    results = data.get("results", {})
    for ip, info in results.items():
        for p in info.get("ports", []):
            vulns = p.get("vulns", [])
            cves = p.get("cves", [])
            if not vulns and not cves:
                _write_row([
                    ip, p.get("port"), p.get("protocol", "tcp"), p.get("state", "open"),
                    p.get("service", "unknown"), p.get("version", ""), "", "", "INFO", "0.0", "", ""
                ])
            else:
                for v in vulns:
                    v_dict = v if isinstance(v, dict) else {"title": str(v), "severity": "MEDIUM", "cvss": 5.0}
                    _write_row([
                        ip, p.get("port"), p.get("protocol", "tcp"), p.get("state", "open"),
                        p.get("service", "unknown"), p.get("version", ""), v_dict.get("title", ""),
                        "", v_dict.get("severity", "MEDIUM"), v_dict.get("cvss", 5.0),
                        v_dict.get("remediation", ""), v_dict.get("remediation_sla", "")
                    ])
                for c in cves:
                    _write_row([
                        ip, p.get("port"), p.get("protocol", "tcp"), p.get("state", "open"),
                        p.get("service", "unknown"), p.get("version", ""), c.get("description", ""),
                        c.get("cve", ""), "CRITICAL" if float(c.get("cvss_score", 0)) >= 9 else "HIGH",
                        c.get("cvss_score", 7.5), "Apply vendor patch", "7 Days"
                    ])

    content = output.getvalue()
    if path:
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(content)
    return content


def export_html(data: Dict[str, Any], path: Optional[str] = None) -> str:
    """Exports self-contained dark-mode HTML report."""
    def _e(val):
        return html.escape(str(val) if val is not None else "")

    rows = []
    results = data.get("results", {})
    for ip, info in results.items():
        for p in info.get("ports", []):
            vulns = p.get("vulns", [])
            cves = p.get("cves", [])
            findings = []
            for v in vulns:
                findings.append(f"⚠️ {_e(v.get('title', str(v)) if isinstance(v, dict) else str(v))}")
            for c in cves:
                findings.append(f"🛑 {_e(c.get('cve', 'CVE'))} (CVSS {_e(c.get('cvss_score', ''))})")
            findings_html = "<br>".join(findings) if findings else "<span style='color:#666'>-</span>"

            rows.append(f"""
            <tr>
                <td><b>{_e(ip)}</b></td>
                <td>{_e(p.get('port'))}</td>
                <td><code>{_e(p.get('protocol', 'tcp'))}</code></td>
                <td><span style="color:#10b981">{_e(p.get('state', 'open'))}</span></td>
                <td><b>{_e(p.get('service', 'unknown'))}</b></td>
                <td>{_e(p.get('version', '-'))}</td>
                <td>{findings_html}</td>
            </tr>
            """)

    content = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PENTRAX Security Report — {_e(data.get('target', 'Target'))}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f3f4f6; padding: 24px; margin: 0; }}
.header {{ border-bottom: 1px solid #1f2937; padding-bottom: 20px; margin-bottom: 24px; }}
h1 {{ color: #06b6d4; margin: 0 0 8px 0; }}
.badge {{ background: #1e293b; padding: 4px 10px; border-radius: 4px; font-size: 13px; color: #94a3b8; border: 1px solid #334155; }}
table {{ width: 100%; border-collapse: collapse; background: #111827; border-radius: 8px; overflow: hidden; margin-top: 16px; font-size: 13px; }}
th {{ background: #1e293b; color: #38bdf8; text-align: left; padding: 12px; border-bottom: 1px solid #334155; }}
td {{ padding: 10px 12px; border-bottom: 1px solid #1f2937; }}
tr:hover {{ background: #1a2234; }}
</style>
</head>
<body>
<div class="header">
    <h1>⚡ PENTRAX Security Assessment Report</h1>
    <span class="badge">Target: {_e(data.get('target', 'Unknown'))}</span>
    <span class="badge">Hosts: {_e(data.get('hosts_alive', len(results)))}</span>
    <span class="badge">Open Ports: {_e(data.get('total_open_ports', 0))}</span>
    <span class="badge">Vulns: {_e(data.get('vulns_found', 0))}</span>
</div>
<table>
    <thead>
        <tr><th>Host IP</th><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Version</th><th>Vulnerabilities & CVEs</th></tr>
    </thead>
    <tbody>
        {''.join(rows) if rows else '<tr><td colspan="7">No open ports found.</td></tr>'}
    </tbody>
</table>
</body>
</html>
"""
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    return content

