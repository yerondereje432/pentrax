"""
Unit and integration tests for SQLite persistence and Role-Based Access Control (RBAC).
"""

import os
import tempfile
import unittest
from starlette.testclient import TestClient

from web.db import DatabaseManager, hash_password, verify_password
from web.manager import ScanManager
from web.app import app


class TestSQLiteAndRBAC(unittest.TestCase):
    """Test suite for SQLite schema, users, sessions, and RBAC isolation."""

    def setUp(self):
        # Create a temporary database for each test run
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.db = DatabaseManager(db_path=self.temp_db.name)

    def tearDown(self):
        if os.path.exists(self.temp_db.name):
            try:
                os.unlink(self.temp_db.name)
            except OSError:
                pass

    def test_password_hashing(self):
        pw = "SuperSecretPassword1337!"
        h, salt = hash_password(pw)
        self.assertTrue(verify_password(pw, h, salt))
        self.assertFalse(verify_password("WrongPassword", h, salt))

    def test_default_users_seeded(self):
        admin = self.db.authenticate_user("admin", "pentrax1337")
        self.assertIsNotNone(admin)
        self.assertEqual(admin["role"], "admin")

        operator = self.db.authenticate_user("operator", "operator123")
        self.assertIsNotNone(operator)
        self.assertEqual(operator["role"], "operator")

        bad_auth = self.db.authenticate_user("admin", "wrongpass")
        self.assertIsNone(bad_auth)

    def test_session_lifecycle(self):
        admin = self.db.get_user_by_username("admin")
        token = self.db.create_session(admin["id"], duration_hours=1)
        self.assertIsNotNone(token)

        user = self.db.get_user_from_session(token)
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "admin")

        self.db.revoke_session(token)
        user_after = self.db.get_user_from_session(token)
        self.assertIsNone(user_after)

    def test_scan_isolation_by_user(self):
        user_a = self.db.create_user("operator_a", "passA123", role="operator")
        user_b = self.db.create_user("operator_b", "passB123", role="operator")
        admin = self.db.get_user_by_username("admin")

        # Save scan for user A
        self.db.save_scan(
            scan_id="SCAN-A01",
            owner_id=user_a["id"],
            target="10.0.0.1",
            status="completed",
            config={"target": "10.0.0.1"},
            summary={"hosts_alive": 1, "total_open_ports": 2}
        )

        # Save scan for user B
        self.db.save_scan(
            scan_id="SCAN-B01",
            owner_id=user_b["id"],
            target="10.0.0.2",
            status="completed",
            config={"target": "10.0.0.2"},
            summary={"hosts_alive": 1, "total_open_ports": 1}
        )

        # User A only sees scan A
        scans_a = self.db.list_scans(user=user_a)
        self.assertEqual(len(scans_a), 1)
        self.assertEqual(scans_a[0]["id"], "SCAN-A01")

        # User B only sees scan B
        scans_b = self.db.list_scans(user=user_b)
        self.assertEqual(len(scans_b), 1)
        self.assertEqual(scans_b[0]["id"], "SCAN-B01")

        # Admin sees all scans
        scans_admin = self.db.list_scans(user=admin)
        self.assertEqual(len(scans_admin), 2)

        # User A cannot delete User B's scan
        self.assertFalse(self.db.delete_scan("SCAN-B01", user=user_a))
        # User A can delete their own scan
        self.assertTrue(self.db.delete_scan("SCAN-A01", user=user_a))

    def test_audit_logging(self):
        admin = self.db.get_user_by_username("admin")
        self.db.log_audit(admin["id"], "LOGIN_SUCCESS", target=None, ip="127.0.0.1")
        logs = self.db.get_audit_logs(limit=10)
        self.assertTrue(any(l["action"] == "LOGIN_SUCCESS" for l in logs))

    def test_session_persists_across_database_instances(self):
        """Verify that sessions survive process restarts and are read from SQLite."""
        admin = self.db.get_user_by_username("admin")
        token = self.db.create_session(admin["id"], duration_hours=2)

        # Simulate fresh process restart by creating a new DatabaseManager pointing to same file
        new_db_instance = DatabaseManager(db_path=self.temp_db.name)
        user = new_db_instance.get_user_from_session(token)
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "admin")

    def test_diff_scans_between_two_records(self):
        """Verify scan diffing accurately identifies new/closed ports and vulnerability deltas."""
        self.db.save_scan(
            scan_id="SCAN-DIFF-1",
            owner_id=None,
            target="10.0.0.1",
            status="completed",
            config={"target": "10.0.0.1"},
            summary={"results": {"10.0.0.1": {"ports": [
                {"port": 80, "service": "HTTP", "risk_level": "LOW", "cves": [], "vulns": []}
            ]}}}
        )
        self.db.save_scan(
            scan_id="SCAN-DIFF-2",
            owner_id=None,
            target="10.0.0.1",
            status="completed",
            config={"target": "10.0.0.1"},
            summary={"results": {"10.0.0.1": {"ports": [
                {"port": 80, "service": "HTTP", "risk_level": "LOW", "cves": [], "vulns": []},
                {"port": 443, "service": "HTTPS", "risk_level": "HIGH", "cves": [{"cve": "CVE-2024-TEST"}], "vulns": []}
            ]}}}
        )
        diff = self.db.diff_scans("SCAN-DIFF-1", "SCAN-DIFF-2")
        self.assertIsNotNone(diff)
        self.assertEqual(len(diff["new_ports"]), 1)
        self.assertEqual(diff["new_ports"][0]["port"], 443)
        self.assertEqual(len(diff["new_vulnerabilities"]), 1)
        self.assertEqual(diff["net_drift_summary"]["ports_delta"], 1)


class TestWebAPIAuthAndRBAC(unittest.TestCase):
    """Integration tests for web authentication and RBAC endpoints."""

    def setUp(self):
        self.client = TestClient(app)

    def test_auth_login_and_me_endpoints(self):
        # Invalid credentials
        res = self.client.post("/api/auth/login", json={"username": "admin", "password": "badpassword"})
        self.assertEqual(res.status_code, 401)

        # Valid credentials
        res = self.client.post("/api/auth/login", json={"username": "admin", "password": "pentrax1337"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("token", data)
        token = data["token"]

        # Check /api/auth/me with session token header
        res_me = self.client.get("/api/auth/me", headers={"X-Session-Token": token})
        self.assertEqual(res_me.status_code, 200)
        data_me = res_me.json()
        self.assertTrue(data_me["authenticated"])
        self.assertEqual(data_me["user"]["username"], "admin")
        self.assertEqual(data_me["user"]["role"], "admin")

        # Logout
        res_out = self.client.post("/api/auth/logout", headers={"X-Session-Token": token})
        self.assertEqual(res_out.status_code, 200)

        # Me should now fail
        res_me_after = self.client.get("/api/auth/me", headers={"X-Session-Token": token})
        self.assertEqual(res_me_after.status_code, 401)

    def test_rate_limiting_login_lockout(self):
        """Verify rate limiting blocks brute force after 5 failed attempts."""
        from web.rate_limiter import rate_limiter
        test_ip = "192.0.2.42"
        rate_limiter.reset(test_ip)

        for _ in range(5):
            rate_limiter.record_failure(test_ip)

        self.assertFalse(rate_limiter.is_allowed(test_ip))
        rate_limiter.reset(test_ip)
        self.assertTrue(rate_limiter.is_allowed(test_ip))

    def test_security_headers_present_on_responses(self):
        """Verify CSP, X-Frame-Options, nosniff headers are returned on all endpoints."""
        res = self.client.get("/")
        self.assertIn("Content-Security-Policy", res.headers)
        self.assertEqual(res.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(res.headers.get("X-Content-Type-Options"), "nosniff")

    def test_viewer_role_cannot_start_scan(self):
        # Create a viewer user in DB
        from web.app import db_manager
        db_manager.create_user("test_viewer_role", "viewer123", role="viewer")

        # Login as viewer
        res = self.client.post("/api/auth/login", json={"username": "test_viewer_role", "password": "viewer123"})
        self.assertEqual(res.status_code, 200)
        token = res.json()["token"]

        # Attempt to start scan
        res_start = self.client.post(
            "/api/scans/start",
            headers={"X-Session-Token": token},
            json={"target": "127.0.0.1", "ports": "80", "authorized": True}
        )
        self.assertEqual(res_start.status_code, 403)
        self.assertIn("Viewers are not authorized to launch scans", res_start.json()["error"])


if __name__ == "__main__":
    unittest.main()
