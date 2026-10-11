"""Dependency-free parsing helpers for yerscan JSON reports."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


RISK_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
RISK_RANK = {level: len(RISK_LEVELS) - index for index, level in enumerate(RISK_LEVELS)}


def load_report(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as report_file:
        report = json.load(report_file)
    if not isinstance(report, dict) or not isinstance(report.get("results", {}), dict):
        raise ValueError("Not a valid yerscan report")
    return report


def _level(*values: Any) -> str:
    values = [str(value or "").upper() for value in values]
    return max((value for value in values if value in RISK_RANK), key=lambda value: RISK_RANK[value], default="INFO")


def _row(host_ip: str, port: dict, vulnerability: dict, cve: dict | None) -> dict[str, Any]:
    cvss = vulnerability.get("cvss") if isinstance(vulnerability.get("cvss"), dict) else {}
    score = cvss.get("base_score", (cve or {}).get("cvss_score", ""))
    return {
        "host_ip": host_ip,
        "port": port.get("port", ""),
        "protocol": port.get("protocol", "tcp"),
        "service": port.get("service", "unknown"),
        "version": port.get("version", ""),
        "risk_level": _level(port.get("risk_level"), vulnerability.get("risk_level"), cvss.get("severity"), (cve or {}).get("severity")),
        "cve_id": str(vulnerability.get("id") or (cve or {}).get("cve") or ""),
        "cvss_score": score,
        "description": vulnerability.get("description") or (cve or {}).get("description") or port.get("risk_reason", ""),
        "cvss_vector": cvss.get("vector", ""),
        "cis": vulnerability.get("cis") or {},
        "evidence": vulnerability.get("evidence", ""),
        "remediation": vulnerability.get("remediation", "") or (vulnerability.get("cis") or {}).get("remediation", ""),
        "references": vulnerability.get("references", []),
    }


def flatten_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten all open ports into table rows, retaining clean ports too."""
    rows: list[dict[str, Any]] = []
    for host_ip, raw_host in (report.get("results") or {}).items():
        host = raw_host if isinstance(raw_host, dict) else {}
        host_vulns = [v for v in host.get("vulns", []) if isinstance(v, dict)]
        for port in host.get("ports", []) or []:
            if not isinstance(port, dict) or str(port.get("state", "open")).lower() != "open":
                continue
            cves = [cve for cve in port.get("cves", []) if isinstance(cve, dict)]
            vulns = [v for v in port.get("vulns", []) if isinstance(v, dict)]
            vulns += [v for v in host_vulns if str(v.get("affected_port", "")) == str(port.get("port", ""))]
            if vulns:
                for vuln in vulns:
                    cve = next((item for item in cves if item.get("cve") == vuln.get("id")), None)
                    rows.append(_row(host_ip, port, vuln, cve))
                used = {v.get("id") for v in vulns}
                rows.extend(_row(host_ip, port, {}, cve) for cve in cves if cve.get("cve") not in used)
            elif cves:
                rows.extend(_row(host_ip, port, {}, cve) for cve in cves)
            else:
                rows.append(_row(host_ip, port, {}, None))
    return rows


def summarise_report(report: dict[str, Any]) -> dict[str, Any]:
    hosts = []
    for ip, raw_host in (report.get("results") or {}).items():
        host = dict(raw_host or {})
        host["ip"] = ip
        host["ports"] = [port for port in host.get("ports", []) if isinstance(port, dict)]
        hosts.append(host)
    hosts.sort(key=lambda host: (host.get("risk_score", 0), RISK_RANK.get(str(host.get("risk_level", "INFO")).upper(), 0)), reverse=True)
    findings = flatten_findings(report)
    risk_distribution = Counter(str(host.get("risk_level", "INFO")).upper() for host in hosts)
    cve_distribution = Counter(str(row.get("risk_level", "INFO")).upper() for row in findings if row.get("cve_id"))
    service_counts = Counter(str(row.get("service", "unknown")) for row in findings if row.get("cve_id"))
    return {
        "hosts": hosts,
        "findings": findings,
        "risk_distribution": {level: risk_distribution.get(level, 0) for level in RISK_LEVELS},
        "cve_distribution": {level: cve_distribution.get(level, 0) for level in RISK_LEVELS},
        "most_common_service": service_counts.most_common(1)[0] if service_counts else ("—", 0),
        "open_ports": len({(row["host_ip"], row["port"]) for row in findings}),
        "risk_summary": ", ".join(f"{level.title()} {risk_distribution[level]}" for level in RISK_LEVELS if risk_distribution[level]) or "No hosts",
    }


def report_metadata(name: str, report: dict[str, Any]) -> dict[str, Any]:
    summary = summarise_report(report)
    return {
        "name": name,
        "target": report.get("target", "Unknown target"),
        "scan_time": report.get("scan_time", ""),
        "duration_seconds": report.get("duration_seconds", 0),
        "hosts_alive": report.get("hosts_alive", len(summary["hosts"])),
        "open_ports": report.get("total_open_ports", summary["open_ports"]),
        "cves_found": report.get("cves_found", sum(1 for row in summary["findings"] if row["cve_id"])),
        "risk_summary": summary["risk_summary"],
    }
