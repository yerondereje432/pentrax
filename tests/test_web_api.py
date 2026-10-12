"""Unit and integration tests for Yerscan Web API and WebSockets."""

import asyncio
import json
import os
import unittest
from pathlib import Path
from starlette.testclient import TestClient

from web.app import app
from web.manager import scan_manager, ScanInstance


class TestWebAPI(unittest.TestCase):
    """Test suite for Yerscan Web API endpoints."""

    def setUp(self):
        self.client = TestClient(app)

    def test_index_page_loads(self):
        """GET / should serve the HTML dashboard."""
        resp = self.client.get("/")
        self.assertIn("PENTRAX", resp.text)
        self.assertIn("MITRE ATT&CK", resp.text)

    def test_system_capabilities(self):
        """GET /api/system/capabilities returns system info and supported scan types."""
        resp = self.client.get("/api/system/capabilities")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("version", data)
        self.assertIn("is_root", data)
        self.assertIn("supported_scan_types", data)
        self.assertTrue(any(st["id"] == "connect" for st in data["supported_scan_types"]))

    def test_list_scans(self):
        """GET /api/scans returns a list of scans."""
        resp = self.client.get("/api/scans")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)

    def test_start_scan_validation_fails_on_empty_target(self):
        """POST /api/scans/start with empty target should return 400."""
        resp = self.client.post("/api/scans/start", json={"target": ""})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("required", resp.json()["error"])

    def test_start_scan_validation_fails_on_invalid_host(self):
        """POST /api/scans/start with unresolvable host returns 400."""
        resp = self.client.post("/api/scans/start", json={"target": "this_domain_definitely_does_not_exist_9999.xyz"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("could not be resolved", resp.json()["error"])

    def test_start_and_get_scan_details(self):
        """POST /api/scans/start with valid localhost target initiates scan and allows querying status."""
        resp = self.client.post("/api/scans/start", json={
            "target": "127.0.0.1",
            "ports": "80",
            "concurrency": 100,
            "timeout": 0.5,
            "deep": False,
            "verify": False
        })
        self.assertEqual(resp.status_code, 202)
        scan_data = resp.json()["scan"]
        scan_id = scan_data["id"]
        self.assertEqual(scan_data["target"], "127.0.0.1")

        # Query details
        detail_resp = self.client.get(f"/api/scans/{scan_id}")
        self.assertEqual(detail_resp.status_code, 200)
        detail_data = detail_resp.json()
        self.assertEqual(detail_data["id"], scan_id)
        self.assertIn("progress", detail_data)
        self.assertIn("logs", detail_data)

    def test_stop_scan(self):
        """POST /api/scans/{scan_id}/stop stops an ongoing scan."""
        # Create a mock running scan instance directly in manager
        instance = scan_manager.create_scan({"target": "127.0.0.1"})
        instance.status = "running"

        resp = self.client.post(f"/api/scans/{instance.id}/stop")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(instance.status, "stopped")

    def test_delete_scan(self):
        """DELETE /api/scans/{scan_id} deletes the scan."""
        instance = scan_manager.create_scan({"target": "127.0.0.1"})
        scan_id = instance.id

        resp = self.client.delete(f"/api/scans/{scan_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(scan_manager.get_scan(scan_id))

        # Trying to delete again returns 404
        resp404 = self.client.delete(f"/api/scans/{scan_id}")
        self.assertEqual(resp404.status_code, 404)

    def test_export_scan_formats(self):
        """GET /api/scans/{scan_id}/export/{format} exports JSON, CSV, and HTML."""
        instance = scan_manager.create_scan({"target": "127.0.0.1"})
        instance.status = "completed"
        instance.result = {
            "target": "127.0.0.1",
            "scan_time": "2026-10-12T09:00:00",
            "duration_seconds": 1.5,
            "scan_type": "connect",
            "ports_scanned": 1,
            "port_range": "80",
            "total_checks": 1,
            "hosts_alive": 1,
            "hosts_with_ports": 1,
            "total_open_ports": 1,
            "filtered": 0,
            "closed": 0,
            "udp_ports": 0,
            "deep_probed": 0,
            "risky_services": 0,
            "cves_found": 0,
            "vulns_found": 0,
            "results": {
                "127.0.0.1": {
                    "mac": "",
                    "risk_score": 0,
                    "risk_level": "LOW",
                    "vulns": [],
                    "ports": [{
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http",
                        "version": "nginx",
                        "os_hint": "",
                        "risk_level": "LOW",
                        "cves": []
                    }]
                }
            }
        }
        scan_manager.save_scan(instance)

        # JSON Export
        resp_json = self.client.get(f"/api/scans/{instance.id}/export/json")
        self.assertEqual(resp_json.status_code, 200)
        self.assertEqual(resp_json.json()["target"], "127.0.0.1")

        # HTML Export
        resp_html = self.client.get(f"/api/scans/{instance.id}/export/html")
        self.assertEqual(resp_html.status_code, 200)
        self.assertIn("<!doctype html>", resp_html.text.lower())
        self.assertIn("Yerscan Report", resp_html.text)

        # CSV Export
        resp_csv = self.client.get(f"/api/scans/{instance.id}/export/csv")
        self.assertEqual(resp_csv.status_code, 200)
        self.assertIn("127.0.0.1", resp_csv.text)

    def test_websocket_sync(self):
        """WebSocket /ws/scans/{scan_id} receives initial sync state."""
        instance = scan_manager.create_scan({"target": "127.0.0.1"})
        with self.client.websocket_connect(f"/ws/scans/{instance.id}") as ws:
            data = ws.receive_json()
            self.assertEqual(data["type"], "sync_state")
            self.assertEqual(data["scan"]["id"], instance.id)

    def test_start_scan_validation_fails_on_cloud_metadata_ip(self):
        """POST /api/scans/start with cloud metadata 169.254.169.254 must be blocked."""
        resp = self.client.post("/api/scans/start", json={"target": "169.254.169.254"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("cloud metadata", resp.json()["error"].lower())

    def test_start_scan_with_dast_and_ssl_flags(self):
        """POST /api/scans/start accepts and propagates dast and ssl_audit configuration flags."""
        resp = self.client.post("/api/scans/start", json={
            "target": "127.0.0.1",
            "ports": "80",
            "dast": True,
            "ssl_audit": True,
            "deep": False,
            "verify": False
        })
        self.assertEqual(resp.status_code, 202)
        scan = resp.json()["scan"]
        self.assertTrue(scan["config"]["dast"])
        self.assertTrue(scan["config"]["ssl_audit"])

    def test_vulnerability_sla_auto_assignment(self):
        """Vulnerability objects automatically assign industry standard SLAs based on risk level."""
        import pentrax as ys
        v_crit = ys.Vulnerability(id="CRIT-1", title="RCE", risk_level="CRITICAL")
        self.assertEqual(v_crit.remediation_sla, "48 Hours")

        v_high = ys.Vulnerability(id="HIGH-1", title="SQLi", risk_level="HIGH")
        self.assertEqual(v_high.remediation_sla, "14 Days")

        v_med = ys.Vulnerability(id="MED-1", title="CSRF", risk_level="MEDIUM")
        self.assertEqual(v_med.remediation_sla, "30 Days")

        v_low = ys.Vulnerability(id="LOW-1", title="Info", risk_level="LOW")
        self.assertEqual(v_low.remediation_sla, "90 Days")

    def test_audit_web_dast_logic(self):
        """audit_web_dast accurately catches missing headers, CORS reflection, and exposed paths."""
        import pentrax as ys
        import socket
        import threading

        # Spin up a mock HTTP server on a free port
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(5)

        def run_server():
            for _ in range(10):
                try:
                    conn, _ = srv.accept()
                    req = conn.recv(1024).decode("utf-8", errors="ignore")
                    if "GET /.env" in req:
                        body = "DB_PASSWORD=SecretP@ssw0rd123!\nAWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"
                        resp = f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n{body}"
                    elif "Origin:" in req:
                        body = '{"auth": true}'
                        resp = (
                            "HTTP/1.1 200 OK\r\n"
                            "Access-Control-Allow-Origin: https://pentrax-attacker-audit.com\r\n"
                            "Access-Control-Allow-Credentials: true\r\n"
                            f"Content-Length: {len(body)}\r\n\r\n{body}"
                        )
                    else:
                        body = "<html><body>Hello</body></html>"
                        resp = f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n{body}"
                    conn.sendall(resp.encode("utf-8"))
                    conn.close()
                except:
                    break

        th = threading.Thread(target=run_server, daemon=True)
        th.start()

        try:
            vulns, dast_info = asyncio.run(ys.audit_web_dast("127.0.0.1", port, timeout=1.0))
            self.assertTrue(any(v.id == "DAST-EXPOSED-ENV" for v in vulns))
            self.assertTrue(any(v.id == "DAST-CORS-REFLECTED-CREDS" for v in vulns))
            self.assertTrue(any(v.id == "DAST-CSP-MISSING" for v in vulns))
        finally:
            srv.close()

    def test_audit_web_dast_robots_discovery(self):
        """audit_web_dast extracts routes from /robots.txt."""
        import pentrax as ys
        import socket
        import threading

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(5)

        def run_server():
            for _ in range(15):
                try:
                    conn, _ = srv.accept()
                    req = conn.recv(1024).decode("utf-8", errors="ignore")
                    if "GET /robots.txt" in req:
                        body = "User-agent: *\nDisallow: /admin-panel\nAllow: /public-api\n"
                        resp = f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n{body}"
                    else:
                        body = "<html>OK</html>"
                        resp = f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n{body}"
                    conn.sendall(resp.encode("utf-8"))
                    conn.close()
                except:
                    break

        th = threading.Thread(target=run_server, daemon=True)
        th.start()

        try:
            vulns, dast_info = asyncio.run(ys.audit_web_dast("127.0.0.1", port, timeout=1.0))
            self.assertIn("/admin-panel", dast_info.get("discovered_routes", []))
            self.assertIn("/public-api", dast_info.get("discovered_routes", []))
        finally:
            srv.close()

    def test_concurrency_conflict_409(self):
        """POST /api/scans/start returns 409 Conflict if a scan is currently active."""
        # Simulate active scan
        fake_scan = ScanInstance("test_active", {"target": "127.0.0.1"})
        fake_scan.status = "running"
        scan_manager.scans["test_active"] = fake_scan

        try:
            resp = self.client.post("/api/scans/start", json={"target": "127.0.0.1"})
            self.assertEqual(resp.status_code, 409)
            self.assertIn("Another scan is currently in progress", resp.json()["error"])
        finally:
            scan_manager.scans.pop("test_active", None)

    def test_api_key_auth_middleware(self):
        """Requests to protected endpoints enforce PENTRAX_API_KEY if configured in environment."""
        os.environ["PENTRAX_API_KEY"] = "super-secret-key-1337"
        try:
            # Unauthenticated request should fail with 401
            resp = self.client.get("/api/scans")
            self.assertEqual(resp.status_code, 401)
            self.assertIn("Unauthorized", resp.json()["error"])

            # Valid header authentication should pass
            resp = self.client.get("/api/scans", headers={"X-API-Key": "super-secret-key-1337"})
            self.assertEqual(resp.status_code, 200)

            # Valid Bearer authorization should pass
            resp = self.client.get("/api/scans", headers={"Authorization": "Bearer super-secret-key-1337"})
            self.assertEqual(resp.status_code, 200)

            # Frontend index.html should remain accessible without authentication
            resp_index = self.client.get("/")
            self.assertEqual(resp_index.status_code, 200)
        finally:
            os.environ.pop("PENTRAX_API_KEY", None)


if __name__ == "__main__":
    unittest.main()

