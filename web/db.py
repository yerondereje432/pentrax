"""Database and RBAC Authentication module for PENTRAX.

Embedded SQLite storage with WAL mode, PBKDF2 password security,
per-user scan isolation, and structured vulnerability findings inventory.
"""

import hashlib
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union

ROOT_DIR = Path(__file__).resolve().parent.parent
DB_PATH = ROOT_DIR / "pentrax.db"


def get_db_connection() -> sqlite3.Connection:
    """Return an active SQLite connection configured with WAL mode and foreign keys."""
    conn = sqlite3.connect(str(DB_PATH), timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Hash password using PBKDF2-HMAC-SHA256 (100,000 iterations)."""
    if not salt:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000
    ).hex()
    return pw_hash, salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verify candidate password against stored PBKDF2 hash."""
    computed_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(computed_hash, stored_hash)


class DatabaseManager:
    """Manages SQLite schema initialization, user management, and scan persistence."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DB_PATH
        self._active_sessions: Dict[str, Dict[str, Any]] = {}
        self.init_schema()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def init_schema(self):
        """Initialize relational database tables and default admin user."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # 1. Users Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'operator', 'viewer')),
                created_at TEXT NOT NULL
            );
            """)

            # 2. Scans Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                owner_id INTEGER,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                config_json TEXT NOT NULL,
                summary_json TEXT,
                logs_json TEXT,
                duration_seconds REAL DEFAULT 0.0,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE SET NULL
            );
            """)

            # 3. Structured Findings Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER,
                service TEXT,
                vuln_id TEXT NOT NULL,
                title TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                remediation_sla TEXT,
                evidence TEXT,
                mitre_technique TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            );
            """)

            # 4. Forensic Audit Logs Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                target TEXT,
                ip TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
            );
            """)

            # Create Indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_owner ON scans(owner_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_risk ON findings(risk_level);")

            # Seed Default Admin Account if users table is empty
            cursor.execute("SELECT COUNT(*) FROM users;")
            if cursor.fetchone()[0] == 0:
                admin_hash, admin_salt = hash_password("pentrax1337")
                cursor.execute("""
                INSERT INTO users (username, password_hash, salt, role, created_at)
                VALUES (?, ?, ?, 'admin', datetime('now'));
                """, ("admin", admin_hash, admin_salt))
                
                # Seed a default demo operator
                op_hash, op_salt = hash_password("operator123")
                cursor.execute("""
                INSERT INTO users (username, password_hash, salt, role, created_at)
                VALUES (?, ?, ?, 'operator', datetime('now'));
                """, ("operator", op_hash, op_salt))

            conn.commit()

    # ─── User Management & Authentication ──────────────────────────────

    def create_user(self, username: str, password: str, role: str = "operator") -> Optional[Dict[str, Any]]:
        """Create a new user with hashed password and assigned role."""
        if role not in ("admin", "operator", "viewer"):
            raise ValueError(f"Invalid role: {role}")
        pw_hash, salt = hash_password(password)
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                INSERT INTO users (username, password_hash, salt, role, created_at)
                VALUES (?, ?, ?, ?, datetime('now'));
                """, (username.strip(), pw_hash, salt, role))
                conn.commit()
                return {"id": cursor.lastrowid, "username": username.strip(), "role": role}
        except sqlite3.IntegrityError:
            return None

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Fetch user by username."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, role, created_at FROM users WHERE username = ?;", (username.strip(),))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Verify user credentials and return user record if valid."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, password_hash, salt, role FROM users WHERE username = ?;", (username.strip(),))
            row = cursor.fetchone()
            if not row:
                return None
            if verify_password(password, row["password_hash"], row["salt"]):
                return {
                    "id": row["id"],
                    "username": row["username"],
                    "role": row["role"],
                }
            return None

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Fetch user by ID."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, role, created_at FROM users WHERE id = ?;", (user_id,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def list_users(self) -> List[Dict[str, Any]]:
        """List all registered users (admin utility)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, role, created_at FROM users ORDER BY id ASC;")
            return [dict(r) for r in cursor.fetchall()]

    # ─── Session Management ──────────────────────────────────────────

    def create_session(self, user: Union[int, Dict[str, Any]], duration_hours: int = 24) -> str:
        """Issue a cryptographically secure session token."""
        if isinstance(user, int):
            user_record = self.get_user_by_id(user)
            if not user_record:
                raise ValueError(f"User ID {user} not found")
            user = user_record

        token = secrets.token_urlsafe(32)
        self._active_sessions[token] = {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "created_at": time.time(),
        }
        return token

    def get_user_from_session(self, token: str) -> Optional[Dict[str, Any]]:
        """Retrieve user dictionary from active session token."""
        if not token:
            return None
        return self._active_sessions.get(token)

    def revoke_session(self, token: str) -> bool:
        """Revoke active session token."""
        return self._active_sessions.pop(token, None) is not None

    # ─── Scan Persistence & RBAC Queries ─────────────────────────────

    def save_scan(
        self,
        scan_id: str,
        owner_id: Optional[int],
        target: str,
        status: str,
        config: Dict[str, Any],
        summary: Optional[Dict[str, Any]] = None,
        logs: Optional[List[str]] = None,
        duration: float = 0.0,
        completed_at: Optional[str] = None
    ):
        """Save or update scan state in SQLite and index individual findings."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO scans (id, owner_id, target, status, config_json, summary_json, logs_json, duration_seconds, created_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)
            ON CONFLICT(id) DO UPDATE SET
                status = excluded.status,
                summary_json = excluded.summary_json,
                logs_json = excluded.logs_json,
                duration_seconds = excluded.duration_seconds,
                completed_at = excluded.completed_at;
            """, (
                scan_id,
                owner_id,
                target,
                status,
                json.dumps(config),
                json.dumps(summary or {}),
                json.dumps(logs or []),
                duration,
                completed_at
            ))

            # If scan summary has findings, index them in findings table
            if summary and "results" in summary:
                cursor.execute("DELETE FROM findings WHERE scan_id = ?;", (scan_id,))
                findings_to_insert = []
                for host_ip, host_info in summary["results"].items():
                    for port_info in host_info.get("ports", []):
                        port_num = port_info.get("port")
                        svc_name = port_info.get("service", "")
                        # Index CVEs
                        for cve in port_info.get("cves", []):
                            findings_to_insert.append((
                                scan_id, host_ip, port_num, svc_name,
                                cve.get("cve", "CVE"),
                                f"Known CVE on {svc_name}: {cve.get('cve')}",
                                port_info.get("risk_level", "HIGH"),
                                "14 Days",
                                f"CVSS Score: {cve.get('cvss_score', '')}",
                                "T1190"
                            ))
                        # Index dynamic vulns (DAST, etc)
                        for v in port_info.get("vulns", []):
                            v_id = v.get("id", "VULN") if isinstance(v, dict) else "VULN"
                            v_title = v.get("title", str(v)) if isinstance(v, dict) else str(v)
                            v_risk = v.get("risk_level", "MEDIUM") if isinstance(v, dict) else "MEDIUM"
                            v_sla = v.get("remediation_sla", "30 Days") if isinstance(v, dict) else "30 Days"
                            v_ev = v.get("evidence", "") if isinstance(v, dict) else ""
                            findings_to_insert.append((
                                scan_id, host_ip, port_num, svc_name,
                                v_id, v_title, v_risk, v_sla, v_ev, "T1190"
                            ))

                if findings_to_insert:
                    cursor.executemany("""
                    INSERT INTO findings (scan_id, host, port, service, vuln_id, title, risk_level, remediation_sla, evidence, mitre_technique)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, findings_to_insert)

            conn.commit()

    def list_scans(self, user: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """List scans filtered by user role (Admin sees all; Operator sees only own)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if not user or user.get("role") == "admin":
                query = """
                SELECT s.id, s.owner_id, s.target, s.status, s.duration_seconds, s.created_at, s.completed_at,
                       s.config_json, s.summary_json, u.username as owner_username
                FROM scans s
                LEFT JOIN users u ON s.owner_id = u.id
                ORDER BY s.created_at DESC;
                """
                cursor.execute(query)
            else:
                query = """
                SELECT s.id, s.owner_id, s.target, s.status, s.duration_seconds, s.created_at, s.completed_at,
                       s.config_json, s.summary_json, u.username as owner_username
                FROM scans s
                LEFT JOIN users u ON s.owner_id = u.id
                WHERE s.owner_id = ?
                ORDER BY s.created_at DESC;
                """
                cursor.execute(query, (user.get("id"),))

            rows = cursor.fetchall()
            scans_list = []
            for r in rows:
                item = dict(r)
                item["config"] = json.loads(item.pop("config_json") or "{}")
                summary = json.loads(item.pop("summary_json") or "{}")
                item["live_hosts_count"] = summary.get("hosts_alive", 0)
                item["open_ports_count"] = summary.get("total_open_ports", 0)
                scans_list.append(item)
            return scans_list

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Fetch complete scan record by ID."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT s.*, u.username as owner_username
            FROM scans s
            LEFT JOIN users u ON s.owner_id = u.id
            WHERE s.id = ?;
            """, (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            data["config"] = json.loads(data.pop("config_json") or "{}")
            data["result"] = json.loads(data.pop("summary_json") or "{}")
            data["logs"] = json.loads(data.pop("logs_json") or "[]")
            return data

    def delete_scan(self, scan_id: str, user: Optional[Dict[str, Any]] = None) -> bool:
        """Delete scan record respecting RBAC ownership."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if not user or user.get("role") == "admin":
                cursor.execute("DELETE FROM scans WHERE id = ?;", (scan_id,))
            else:
                cursor.execute("DELETE FROM scans WHERE id = ? AND owner_id = ?;", (scan_id, user.get("id")))
            conn.commit()
            return cursor.rowcount > 0

    def log_audit(self, user_id: Optional[int], action: str, target: Optional[str] = None, ip: Optional[str] = None):
        """Append an entry to the immutable audit_logs table."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO audit_logs (user_id, action, target, ip, created_at)
            VALUES (?, ?, ?, ?, datetime('now'));
            """, (user_id, action, target, ip))
            conn.commit()

    def get_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent immutable audit trail entries."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT a.*, u.username
            FROM audit_logs a
            LEFT JOIN users u ON a.user_id = u.id
            ORDER BY a.id DESC
            LIMIT ?;
            """, (limit,))
            return [dict(r) for r in cursor.fetchall()]


# Global Singleton Database Manager instance
db_manager = DatabaseManager()
