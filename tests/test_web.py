"""Web dashboard tests: API auth, shared-database recording, SSE, and the startup reaper.

These exercise the FastAPI app with fastapi's TestClient (no browser). They also confirm that a
plain `python3 yerscan.py` scan is recorded in the same SQLite database the dashboard reads, so it
shows up live — and that `--no-record` writes nothing at all.

Run from the repository root:
    python3 -m unittest discover -s tests
"""

import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import web.app as web_app  # noqa: E402

try:
    from fastapi.testclient import TestClient  # noqa: E402
    HAVE_WEB = True
    WEB_IMPORT_ERROR = ""
except Exception as e:  # pragma: no cover
    HAVE_WEB = False
    WEB_IMPORT_ERROR = str(e)

from yerscan_store import Database, ScanRecorder  # noqa: E402

PASSWORD = "test-password-1234"


def _settings(tmp):
    return web_app.Settings(
        db_path=Path(tmp) / "yerscan_web.sqlite3",
        scans_dir=Path(tmp) / "scans",
        password=PASSWORD,
        max_concurrent=4,
        max_hosts=1024,
        max_ports=1000,
    )


def _listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    return srv


@unittest.skipUnless(HAVE_WEB, f"web dependencies not installed ({WEB_IMPORT_ERROR})")
class AuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.app = web_app.create_app(_settings(self.tmp))
        self.client = TestClient(self.app)

    def tearDown(self):
        self.app.state.db.close()

    def test_login_requires_password(self):
        r = self.client.post("/api/login", json={"password": "wrong"})
        self.assertEqual(r.status_code, 401)
        r = self.client.post("/api/login", json={"password": PASSWORD})
        self.assertEqual(r.status_code, 200)
        self.assertIn("csrf", r.json())

    def test_protected_endpoints_need_auth(self):
        self.assertEqual(self.client.get("/api/scans").status_code, 401)
        r = self.client.post("/api/login", json={"password": PASSWORD})
        token = r.cookies.get("yerscan_session")
        self.assertIsNotNone(token)
        self.assertEqual(self.client.get("/api/scans").status_code, 200)


@unittest.skipUnless(HAVE_WEB, f"web dependencies not installed ({WEB_IMPORT_ERROR})")
class TerminalRecordingTests(unittest.TestCase):
    """A plain CLI scan is recorded in the shared database and shows up in the dashboard."""

    def test_cli_scan_is_recorded_and_visible_in_dashboard(self):
        with tempfile.TemporaryDirectory() as tmp:
            srv = _listener()
            port = srv.getsockname()[1]
            env = dict(os.environ, YERSCAN_DATA_DIR=tmp)
            out = os.path.join(tmp, "cli_report")
            try:
                proc = subprocess.run(
                    [sys.executable, str(ROOT / "yerscan.py"), "127.0.0.1", "-p", str(port), "-y",
                     "--no-mac", "-o", out, "-f", "json"],
                    env=env, capture_output=True, text=True, timeout=180)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            finally:
                srv.close()
            # The terminal run still writes its normal report.
            self.assertTrue(os.path.exists(out + ".json"))

            app = web_app.create_app(_settings(tmp))
            client = TestClient(app)
            csrf = client.post("/api/login", json={"password": PASSWORD}).json()["csrf"]
            self.assertIsNotNone(csrf)
            scans = client.get("/api/scans").json()["scans"]
            self.assertEqual(len(scans), 1)
            self.assertEqual(scans[0]["source"], "cli")
            self.assertEqual(scans[0]["status"], "done")
            sid = scans[0]["id"]
            detail = client.get(f"/api/scans/{sid}").json()
            self.assertIn("127.0.0.1", [h["ip"] for h in detail["hosts"]])
            with client.stream("GET", f"/api/scans/{sid}/events") as resp:
                body = "".join(resp.iter_text())
            self.assertIn("event: port_open", body)
            self.assertIn("event: done", body)
            self.assertIn("event: end", body)
            app.state.db.close()

    def test_no_record_flag_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            srv = _listener()
            port = srv.getsockname()[1]
            env = dict(os.environ, YERSCAN_DATA_DIR=tmp)
            try:
                proc = subprocess.run(
                    [sys.executable, str(ROOT / "yerscan.py"), "127.0.0.1", "-p", str(port), "-y",
                     "--no-mac", "--no-record", "-o", os.path.join(tmp, "r"), "-f", "json"],
                    env=env, capture_output=True, text=True, timeout=180)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            finally:
                srv.close()
            self.assertFalse(os.path.exists(os.path.join(tmp, "yerscan_web.sqlite3")))

    def test_startup_keeps_live_scans_and_reaps_dead_ones(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "yerscan_web.sqlite3")
            live = db.create_scan("10.0.0.1", "22", False, False, pid=os.getpid(), source="cli")
            dead_proc = subprocess.Popen([sys.executable, "-c", "pass"])
            dead_proc.wait()
            dead = db.create_scan("10.0.0.2", "22", False, False, pid=dead_proc.pid, source="cli")
            db.close()
            app = web_app.create_app(_settings(tmp))
            self.assertEqual(app.state.db.get_scan(live)["status"], "running")
            self.assertEqual(app.state.db.get_scan(dead)["status"], "interrupted")
            app.state.db.close()

    def test_recorder_saves_hosts_and_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec = ScanRecorder(Path(tmp) / "yerscan_web.sqlite3", "10.0.0.5", "22", False, False)
            rec.event("phase", {"name": "discovery", "label": "Host discovery"})
            rec.finish("done", {"10.0.0.5": {"risk_score": 12, "risk_level": "MEDIUM", "ports": [], "vulns": []}})
            db = Database(Path(tmp) / "yerscan_web.sqlite3")
            scan = db.get_scan(rec.scan_id)
            self.assertEqual((scan["status"], scan["source"], scan["host_count"]), ("done", "cli", 1))
            self.assertEqual(db.events_after(rec.scan_id)[0]["type"], "phase")
            db.close()


@unittest.skipUnless(HAVE_WEB, f"web dependencies not installed ({WEB_IMPORT_ERROR})")
class DashboardScanTests(unittest.TestCase):
    """A scan started from the dashboard form runs a yerscan.py worker and is tracked live."""

    def test_new_scan_starts_worker_and_tracks_it(self):
        srv = _listener()
        self.addCleanup(srv.close)
        port = srv.getsockname()[1]
        with tempfile.TemporaryDirectory() as tmp:
            app = web_app.create_app(_settings(tmp))
            client = TestClient(app)
            login = client.post("/api/login", json={"password": PASSWORD}).json()
            csrf = login["csrf"]
            r = client.post("/api/scans", json={"target": "127.0.0.1", "ports": str(port),
                                               "verify": False, "authorized": False},
                            headers={"X-CSRF-Token": csrf})
            self.assertEqual(r.status_code, 200, r.text)
            sid = r.json()["id"]
            # Wait for the worker to finish.
            for _ in range(120):
                scan = client.get(f"/api/scans/{sid}").json()["scan"]
                if scan["status"] != "running":
                    break
                time.sleep(1)
            self.assertEqual(scan["status"], "done")
            self.assertEqual(scan["source"], "dashboard")
            detail = client.get(f"/api/scans/{sid}").json()
            self.assertIn("127.0.0.1", [h["ip"] for h in detail["hosts"]])
            app.state.db.close()


if __name__ == "__main__":
    unittest.main()
