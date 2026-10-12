"""Launch and supervise yerscan.py worker subprocesses for dashboard-started scans.

Each dashboard scan is a real yerscan.py process: connect scan only (no raw sockets from the web
UI), with --no-record (the dashboard already owns the scan row) and --events writing a JSON-lines
stream the dashboard tails for SSE. A background watcher finalizes the scan row and imports the
worker's JSON report into the shared database when the process exits.
"""

import json
import subprocess
import sys
import threading
import time
from pathlib import Path

from yerscan_store import pid_alive

REPO_ROOT = Path(__file__).resolve().parent.parent


class JobManager:
    def __init__(self, settings, db):
        self.settings = settings
        self.db = db
        self._procs = {}  # scan_id -> Popen
        self._lock = threading.Lock()
        self._start_watcher()

    def start(self, target: str, ports: str, verify: bool, authorized: bool) -> str:
        """Create the scan row (capacity-checked) and launch the worker. Returns the scan id."""
        scan_id = self.db.create_scan(target, ports, verify, authorized, self.settings.max_concurrent,
                                      source="dashboard")
        scan_dir = self.settings.scans_dir / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)
        cmd = self._worker_cmd(scan_dir, target, ports, verify, authorized)
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=True)
        with self._lock:
            self._procs[scan_id] = proc
        self.db.set_scan_pid(scan_id, proc.pid)
        return scan_id

    def _worker_cmd(self, scan_dir: Path, target: str, ports: str, verify: bool, authorized: bool):
        cmd = [sys.executable, str(REPO_ROOT / "yerscan.py"), target,
               "-p", ports, "-s", "connect", "--no-mac", "-y",
               "-f", "json", "-o", str(scan_dir / "report"),
               "--log", str(scan_dir / "audit.log"),
               "--events", str(scan_dir / "events.jsonl"), "--no-record"]
        if verify:
            cmd.append("--verify")
        if authorized:
            cmd.append("--authorize")
        return cmd

    def _start_watcher(self):
        t = threading.Thread(target=self._watch, daemon=True)
        t.start()

    def _watch(self):
        while True:
            time.sleep(2)
            with self._lock:
                ids = list(self._procs.keys())
            for sid in ids:
                proc = self._procs.get(sid)
                if proc is None:
                    continue
                if proc.poll() is not None:
                    self._finalize(sid)
                    with self._lock:
                        self._procs.pop(sid, None)

    def _finalize(self, scan_id: str):
        scan_dir = self.settings.scans_dir / scan_id
        proc = self._procs.get(scan_id)
        returncode = proc.returncode if proc else 1
        report = scan_dir / "report.json"
        status, error, hosts = "done", None, {}
        if returncode != 0:
            status = "failed"
            error = f"worker exited with code {returncode}"
        if report.exists():
            try:
                data = json.loads(report.read_text(encoding="utf-8"))
                hosts = data.get("results", {})
            except (ValueError, OSError) as e:
                error = error or f"could not read worker report: {e}"
        for ip, block in hosts.items():
            block = dict(block)
            block["ip"] = ip
            self.db.save_host(scan_id, block)
        self.db.finish_scan(scan_id, status, error=error, host_count=len(hosts))
