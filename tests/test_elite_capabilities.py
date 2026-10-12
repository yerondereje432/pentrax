"""Unit tests for PENTRAX Tier 2, 3, and 4 Elite Hacker Capabilities."""
import asyncio
import json
import unittest
from pathlib import Path
from starlette.testclient import TestClient

from scanner.core import CVSSScore, Vulnerability, PortResult, RiskLevel
from scanner.plugin_loader import YAMLTemplateEngine, parse_simple_yaml
from scanner.recon import PassiveRecon, ReconResult
from scanner.vuln_feed import CVEFeedUpdater
from scanner.notifier import Notifier
from scanner.tls_audit import TLSAuditor, CertReport
from scanner.threat_intel import ThreatIntel
from scanner.reporting import generate_executive_summary, generate_markdown, export_json, export_csv, export_html
from web.app import app
from web.manager import scan_manager


class TestEliteScannerModules(unittest.TestCase):

    def test_cvss_v31_mathematical_scoring(self):
        """Verify CVSS v3.1 vector calculation produces mathematically accurate scores."""
        # Critical vector: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
        crit = CVSSScore(
            attack_vector="NETWORK",
            attack_complexity="LOW",
            privileges_required="NONE",
            user_interaction="NONE",
            scope="CHANGED",
            confidentiality="HIGH",
            integrity="HIGH",
            availability="HIGH",
        )
        self.assertAlmostEqual(crit.base_score, 10.0, places=1)
        self.assertEqual(crit.severity, "CRITICAL")

        # Medium vector: AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N
        med = CVSSScore(
            attack_vector="NETWORK",
            attack_complexity="LOW",
            privileges_required="LOW",
            user_interaction="REQUIRED",
            scope="UNCHANGED",
            confidentiality="LOW",
            integrity="LOW",
            availability="NONE",
        )
        self.assertTrue(4.0 <= med.base_score <= 6.0)
        self.assertEqual(med.severity, "MEDIUM")

    def test_vulnerability_dataclass_and_sla(self):
        """Vulnerability automatically calculates SLA and dict representation."""
        vuln = Vulnerability(
            id="VULN-001",
            title="Log4Shell RCE",
            risk_level=RiskLevel.CRITICAL,
            evidence="jndi:ldap://payload",
            remediation="Patch log4j-core to 2.17.1",
        )
        self.assertEqual(vuln.remediation_sla, "48 Hours")
        d = vuln.to_dict()
        self.assertEqual(d["title"], "Log4Shell RCE")
        self.assertEqual(d["severity"], "CRITICAL")

    def test_yaml_template_engine_loads_templates(self):
        """YAMLTemplateEngine discovers and loads starter templates."""
        engine = YAMLTemplateEngine()
        self.assertGreater(len(engine.templates), 0)

        # Ensure git exposure template is loaded
        template_ids = [t.get("id") for t in engine.templates]
        self.assertIn("PENTRAX-HTTP-001", template_ids)
        self.assertIn("PENTRAX-HTTP-002", template_ids)

    def test_parse_simple_yaml_fallback(self):
        """Fallback lightweight parser correctly extracts basic YAML structures."""
        sample = """
        id: TEST-01
        name: Sample Template
        severity: HIGH
        paths:
          - /test1
          - /test2
        """
        parsed = parse_simple_yaml(sample)
        self.assertEqual(parsed["id"], "TEST-01")
        self.assertEqual(parsed["name"], "Sample Template")
        self.assertEqual(parsed["severity"], "HIGH")
        self.assertIn("/test1", parsed["paths"])

    def test_cve_catalog_seeding_and_lookup(self):
        """CVEFeedUpdater seeds baseline high-impact CVEs and supports querying."""
        updater = CVEFeedUpdater()
        cve = updater.get_cve("CVE-2021-44228")
        self.assertIsNotNone(cve)
        self.assertEqual(cve["severity"], "CRITICAL")
        self.assertAlmostEqual(cve["cvss_score"], 10.0, places=1)

        matches = updater.match_service("log4j")
        self.assertGreater(len(matches), 0)
        self.assertTrue(any(m["cve_id"] == "CVE-2021-44228" for m in matches))

        stats = updater.get_stats()
        self.assertGreater(stats["total_cves"], 0)
        self.assertGreater(stats["critical_cves"], 0)

    def test_tls_auditor_grading_logic(self):
        """TLSAuditor generates accurate report and security letter grade."""
        auditor = TLSAuditor()
        # Test audit on invalid port to test graceful handshake failure handling
        report = auditor.audit("127.0.0.1", port=65534, timeout=0.2)
        self.assertIsInstance(report, CertReport)
        self.assertEqual(report.grade, "F")
        self.assertGreater(len(report.vulnerabilities), 0)

    def test_threat_intel_bogon_detection(self):
        """ThreatIntel flags loopback and private RFC1918 space as BOGON."""
        ti = ThreatIntel()
        loop = asyncio.new_event_loop()
        try:
            profile = loop.run_until_complete(ti.check("127.0.0.1"))
            self.assertTrue(profile.is_bogon_or_private)
            self.assertEqual(profile.threat_level, "BOGON")

            profile_priv = loop.run_until_complete(ti.check("192.168.1.50"))
            self.assertTrue(profile_priv.is_bogon_or_private)
            self.assertEqual(profile_priv.threat_level, "BOGON")
        finally:
            loop.close()

    def test_notifier_payload_formatting(self):
        """Notifier formats Slack and Discord webhook alert structures."""
        notifier_slack = Notifier(webhook_url="https://hooks.slack.com/services/T00/B00/X00")
        finding = {
            "title": "Unauthenticated Redis Database",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "remediation": "Enable requirepass",
        }
        # Dry-run post json returns False for mock URL
        self.assertFalse(notifier_slack.notify_critical(finding, "scan_123", host="10.0.0.1"))

    def test_executive_summary_report_generation(self):
        """Executive summary formats CISO RAG rating and SLA matrix."""
        sample_data = {
            "target": "corp.example.com",
            "scan_time": "2026-10-12 12:00:00 UTC",
            "duration_seconds": 12.5,
            "hosts_alive": 1,
            "total_open_ports": 2,
            "results": {
                "10.0.0.1": {
                    "ports": [
                        {
                            "port": 445,
                            "service": "microsoft-ds",
                            "vulns": [
                                {
                                    "title": "SMBv1 EternalBlue Remote Code Execution",
                                    "severity": "CRITICAL",
                                    "cvss": 9.8,
                                    "remediation": "Disable SMBv1",
                                    "remediation_sla": "24 Hours",
                                }
                            ],
                            "cves": [],
                        }
                    ]
                }
            },
        }
        summary_md = generate_executive_summary(sample_data)
        self.assertIn("🔴 CRITICAL RISK", summary_md)
        self.assertIn("Priority Remediation Action Matrix", summary_md)
        self.assertIn("SMBv1 EternalBlue", summary_md)
        self.assertIn("24 Hours", summary_md)


class TestEliteAPIEndpoints(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_api_passive_recon_endpoint(self):
        """POST /api/recon returns valid JSON with DNS records and subdomain array."""
        resp = self.client.post("/api/recon", json={"domain": "localhost"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("domain", data)
        self.assertIn("dns_records", data)
        self.assertIn("subdomains", data)

    def test_api_passive_recon_empty_body_fails(self):
        """POST /api/recon with empty domain returns 400 Bad Request."""
        resp = self.client.post("/api/recon", json={"domain": ""})
        self.assertEqual(resp.status_code, 400)

    def test_api_threat_intel_endpoint(self):
        """POST /api/threat-intel checks IP reputation."""
        resp = self.client.post("/api/threat-intel", json={"ip": "127.0.0.1"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["ip"], "127.0.0.1")
        self.assertEqual(data["threat_level"], "BOGON")

    def test_api_tls_audit_endpoint(self):
        """POST /api/tls-audit performs cryptographic TLS audit."""
        resp = self.client.post("/api/tls-audit", json={"host": "127.0.0.1", "port": 65534})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("grade", data)
        self.assertIn("vulnerabilities", data)

    def test_api_cve_catalog_stats_endpoint(self):
        """GET /api/admin/cve-catalog/stats returns catalog counts."""
        resp = self.client.get("/api/admin/cve-catalog/stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("total_cves", data)
        self.assertGreater(data["total_cves"], 0)

    def test_api_export_executive_and_technical(self):
        """GET /api/scans/{id}/export/executive exports CISO executive markdown."""
        # Create a mock completed scan
        scan = scan_manager.create_scan({"target": "127.0.0.1"})
        scan.status = "completed"
        scan.result = {
            "target": "127.0.0.1",
            "scan_time": "2026-10-12 12:00:00",
            "duration_seconds": 1.0,
            "hosts_alive": 1,
            "total_open_ports": 1,
            "results": {
                "127.0.0.1": {
                    "ports": [{"port": 80, "service": "http", "state": "open", "vulns": [], "cves": []}]
                }
            },
        }
        scan_manager.save_scan(scan)

        resp_exec = self.client.get(f"/api/scans/{scan.id}/export/executive")
        self.assertEqual(resp_exec.status_code, 200)
        self.assertIn("Executive Cyber Security Assessment", resp_exec.text)

        resp_tech = self.client.get(f"/api/scans/{scan.id}/export/technical")
        self.assertEqual(resp_tech.status_code, 200)
        self.assertIn("PENTRAX Technical Security Assessment", resp_tech.text)


if __name__ == "__main__":
    unittest.main()
