"""Shared scan storage (SQLite) used by the CLI and the web dashboard.

Both processes open the same database file under the data directory, so a scan started in a
terminal shows up in the dashboard, and its events stream live while it runs. SQLite in WAL mode
allows one writer and several readers across processes.

Risk history needs no separate table: a host's history is its rows in `hosts` joined to `scans`.
"""

import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           TEXT PRIMARY KEY,
    target       TEXT NOT NULL,
    ports        TEXT NOT NULL,
    verify       INTEGER NOT NULL DEFAULT 0,
    authorized   INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL,              -- queued | running | done | failed | cancelled | interrupted
    created_at   REAL NOT NULL,
    started_at   REAL,
    finished_at  REAL,
    host_count   INTEGER NOT NULL DEFAULT 0,
    error        TEXT,
    pid          INTEGER,                    -- process running the scan; used to detect dead scans
    source       TEXT NOT NULL DEFAULT 'dashboard'   -- dashboard | cli
);
CREATE TABLE IF NOT EXISTS events (
    scan_id  TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    seq      INTEGER NOT NULL,
    ts       REAL NOT NULL,
    type     TEXT NOT NULL,
    data     TEXT NOT NULL,
    PRIMARY KEY (scan_id, seq)
);
CREATE TABLE IF NOT EXISTS hosts (
    scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip          TEXT NOT NULL,
    risk_score  REAL NOT NULL DEFAULT 0,
    risk_level  TEXT NOT NULL DEFAULT '',
    vulns       INTEGER NOT NULL DEFAULT 0,
    open_ports  INTEGER NOT NULL DEFAULT 0,
    data        TEXT NOT NULL,              -- full host block from the JSON export
    PRIMARY KEY (scan_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
"""

ACTIVE = ("queued", "running")
REPO_ROOT = Path(__file__).resolve().parent
DB_NAME = "yerscan_web.sqlite3"
PID_GRACE_SECONDS = 30


class CapacityError(RuntimeError):
    pass


def default_data_dir() -> Path:
    """YERSCAN_DATA_DIR if set, otherwise <repo>/data. CLI and dashboard must agree on this."""
    env = os.environ.get("YERSCAN_DATA_DIR", "")
    return Path(env) if env else REPO_ROOT / "data"


def pid_alive(pid: Optional[int]) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by someone else
    return True


class Database:
    def __init__(self, path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA busy_timeout = 10000")
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self):
        """Add columns introduced after the first schema (databases created by earlier versions)."""
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(scans)").fetchall()}
        if "source" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN source TEXT NOT NULL DEFAULT 'dashboard'")

    def close(self):
        with self._lock:
            self._conn.close()

    def _query(self, sql, params=()):
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def _one(self, sql, params=()):
        rows = self._query(sql, params)
        return rows[0] if rows else None

    def _exec(self, sql, params=()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur.rowcount

    # ── scans ──────────────────────────────────────────────────────
    def create_scan(self, target, ports, verify, authorized, max_concurrent=None,
                    pid=None, source="dashboard") -> str:
        """Insert a running scan. If max_concurrent is given, enforce it atomically."""
        scan_id = uuid.uuid4().hex[:12]
        self.reap_stale()
        with self._lock:
            if max_concurrent is not None:
                active = self._conn.execute(
                    "SELECT COUNT(*) FROM scans WHERE status IN (?,?)", ACTIVE).fetchone()[0]
                if active >= max_concurrent:
                    raise CapacityError(f"{active} scan(s) already running (limit {max_concurrent})")
            now = time.time()
            self._conn.execute(
                "INSERT INTO scans (id, target, ports, verify, authorized, status, created_at, started_at, pid, source)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (scan_id, target, ports, int(bool(verify)), int(bool(authorized)),
                 "running", now, now, pid, source))
            self._conn.commit()
        return scan_id

    def get_scan(self, scan_id) -> Optional[Dict[str, Any]]:
        return self._one("SELECT * FROM scans WHERE id = ?", (scan_id,))

    def list_scans(self, limit=50) -> List[Dict[str, Any]]:
        self.reap_stale()
        return self._query("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,))

    def set_scan_pid(self, scan_id, pid):
        self._exec("UPDATE scans SET pid = ? WHERE id = ?", (pid, scan_id))

    def finish_scan(self, scan_id, status, error=None, host_count=0):
        self._exec("UPDATE scans SET status = ?, finished_at = ?, error = ?, host_count = ?, pid = NULL"
                   " WHERE id = ?", (status, time.time(), error, host_count, scan_id))

    def reap_stale(self) -> int:
        """Mark scans as 'interrupted' when their process is gone. Scans whose process is still
        alive (for example a terminal scan running right now) are left alone."""
        rows = self._query("SELECT id, pid, created_at FROM scans WHERE status IN (?,?)", ACTIVE)
        reaped = 0
        now = time.time()
        for r in rows:
            if r["pid"] is None and now - r["created_at"] < PID_GRACE_SECONDS:
                continue  # the process is still being started and has not recorded its pid yet
            if not pid_alive(r["pid"]):
                reaped += self._exec(
                    "UPDATE scans SET status = 'interrupted', finished_at = ?,"
                    " error = 'scan process ended unexpectedly' WHERE id = ? AND status IN (?,?)",
                    (time.time(), r["id"]) + ACTIVE)
        return reaped

    def count_active(self) -> int:
        self.reap_stale()
        return self._one("SELECT COUNT(*) AS n FROM scans WHERE status IN (?,?)", ACTIVE)["n"]

    # ── events ─────────────────────────────────────────────────────
    def append_event(self, scan_id, seq, ts, etype, data: dict):
        self._exec("INSERT INTO events (scan_id, seq, ts, type, data) VALUES (?,?,?,?,?)",
                   (scan_id, seq, ts, etype, json.dumps(data, default=str)))

    def events_after(self, scan_id, after_seq=0, limit=500) -> List[Dict[str, Any]]:
        rows = self._query("SELECT seq, ts, type, data FROM events WHERE scan_id = ? AND seq > ?"
                           " ORDER BY seq LIMIT ?", (scan_id, after_seq, limit))
        for r in rows:
            r["data"] = json.loads(r["data"])
        return rows

    def last_seq(self, scan_id) -> int:
        row = self._one("SELECT MAX(seq) AS m FROM events WHERE scan_id = ?", (scan_id,))
        return row["m"] or 0

    # ── hosts ──────────────────────────────────────────────────────
    def save_host(self, scan_id, host: dict):
        self._exec("INSERT OR REPLACE INTO hosts (scan_id, ip, risk_score, risk_level, vulns, open_ports, data)"
                   " VALUES (?,?,?,?,?,?,?)",
                   (scan_id, host["ip"], host.get("risk_score") or 0, host.get("risk_level") or "",
                    len(host.get("vulns") or []), len(host.get("ports") or []),
                    json.dumps(host, default=str)))

    def scan_hosts(self, scan_id) -> List[Dict[str, Any]]:
        rows = self._query("SELECT ip, risk_score, risk_level, vulns, open_ports, data FROM hosts"
                           " WHERE scan_id = ? ORDER BY risk_score DESC, ip", (scan_id,))
        return [_host_row(r) for r in rows]

    def host_detail(self, scan_id, ip) -> Optional[Dict[str, Any]]:
        r = self._one("SELECT ip, risk_score, risk_level, vulns, open_ports, data FROM hosts"
                      " WHERE scan_id = ? AND ip = ?", (scan_id, ip))
        return _host_row(r) if r else None

    def host_history(self, ip, limit=50) -> List[Dict[str, Any]]:
        """Risk history for one IP: its rows in hosts, joined to finished scans, oldest first."""
        return self._query(
            "SELECT s.id AS scan_id, s.created_at, s.target, h.risk_score, h.risk_level, h.vulns, h.open_ports"
            " FROM hosts h JOIN scans s ON s.id = h.scan_id"
            " WHERE h.ip = ? AND s.status = 'done' ORDER BY s.created_at LIMIT ?", (ip, limit))

    def latest_hosts(self, limit=500) -> List[Dict[str, Any]]:
        """Most recent finished result for each IP."""
        return self._query(
            "SELECT ip, scan_id, created_at, risk_score, risk_level, vulns, open_ports FROM ("
            "  SELECT h.ip, h.scan_id, s.created_at, h.risk_score, h.risk_level, h.vulns, h.open_ports,"
            "         ROW_NUMBER() OVER (PARTITION BY h.ip ORDER BY s.created_at DESC) AS rn"
            "  FROM hosts h JOIN scans s ON s.id = h.scan_id WHERE s.status = 'done'"
            ") WHERE rn = 1 ORDER BY risk_score DESC, ip LIMIT ?", (limit,))

    def summary(self) -> Dict[str, Any]:
        latest = self.latest_hosts(limit=100000)
        return {
            "scans_total": self._one("SELECT COUNT(*) AS n FROM scans")["n"],
            "scans_active": self.count_active(),
            "hosts_seen": len(latest),
            "hosts_high_risk": sum(1 for h in latest if h["risk_level"] in ("CRITICAL", "HIGH")),
            "open_ports_latest": sum(h["open_ports"] for h in latest),
        }


def _host_row(r):
    data = json.loads(r.pop("data"))
    out = dict(r)
    out["ports"] = data.get("ports", [])
    out["verifications"] = data.get("verifications", [])
    out["attack_paths"] = data.get("attack_paths", [])
    out["mac"] = data.get("mac", "")
    return out


def hand_back_to_sudo_user(path):
    """Under `sudo`, files created as root would be unwritable for the dashboard user.
    Give the data directory and its database files back to the user who ran sudo."""
    if os.geteuid() != 0 or not os.environ.get("SUDO_UID"):
        return
    uid, gid = int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", os.environ["SUDO_UID"]))
    p = Path(path)
    targets = [p.parent] + [q for q in p.parent.glob(p.name + "*")]
    for t in targets:
        try:
            os.chown(t, uid, gid)
        except OSError:
            pass


class ScanRecorder:
    """Records one CLI scan into the shared database so the dashboard can show it live.

    Every event goes to the events table as it happens; the host results and the final status
    are written by finish(). Failures here never stop the scan: recording is switched off with a
    warning instead.
    """

    def __init__(self, db_path, target, ports, verify, authorized):
        self.db = Database(db_path)
        self.scan_id = self.db.create_scan(target, ports, verify, authorized,
                                           max_concurrent=None, pid=os.getpid(), source="cli")
        self._seq = 0
        self.finished = False
        self.broken = False
        hand_back_to_sudo_user(db_path)

    def event(self, etype, data: dict):
        if self.broken or self.finished:
            return
        self._seq += 1
        try:
            self.db.append_event(self.scan_id, self._seq, time.time(), etype, data)
        except sqlite3.Error as e:
            self.broken = True
            print(f"  [recording disabled: {e}]")

    def finish(self, status, hosts: Optional[Dict[str, dict]] = None, error=None):
        if self.finished:
            return
        self.finished = True
        hosts = hosts or {}
        try:
            for ip, block in hosts.items():
                host = dict(block)
                host["ip"] = ip
                self.db.save_host(self.scan_id, host)
            self.db.finish_scan(self.scan_id, status, error=error, host_count=len(hosts))
        except sqlite3.Error as e:
            print(f"  [recording could not save results: {e}]")
        finally:
            self.db.close()
            hand_back_to_sudo_user(self.db.path)
