"""IP-based Rate Limiter backed by SQLite.

Protects authentication and sensitive endpoints from automated brute-force attacks.
"""

from typing import Optional
from web.db import db_manager

MAX_LOGIN_ATTEMPTS = 5
WINDOW_SECONDS = 300  # 5 minutes
LOCKOUT_SECONDS = 900  # 15 minutes lockout after threshold reached


class RateLimiter:
    """Manages failure tracking and temporary lockout by IP address."""

    def __init__(self, db=None):
        self.db = db or db_manager

    def is_allowed(self, ip: str, action: str = "login", max_attempts: int = MAX_LOGIN_ATTEMPTS, window_seconds: int = WINDOW_SECONDS) -> bool:
        """Check if IP is under rate limit threshold for given action."""
        if not ip:
            return True
        count = self.get_recent_failures(ip, action, window_seconds)
        return count < max_attempts

    def get_recent_failures(self, ip: str, action: str = "login", window_seconds: int = WINDOW_SECONDS) -> int:
        """Return the number of failed attempts within the window."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT COUNT(*) FROM rate_limits
            WHERE ip = ? AND action = ? AND datetime(created_at) > datetime('now', ?);
            """, (ip, action, f"-{int(window_seconds)} seconds"))
            row = cursor.fetchone()
            return row[0] if row else 0

    def record_failure(self, ip: str, action: str = "login"):
        """Record a failed attempt from the given IP address."""
        if not ip:
            return
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO rate_limits (ip, action, created_at)
            VALUES (?, ?, datetime('now'));
            """, (ip, action))
            conn.commit()

    def reset(self, ip: str, action: str = "login"):
        """Clear recorded failures for IP (called on successful authentication)."""
        if not ip:
            return
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM rate_limits WHERE ip = ? AND action = ?;", (ip, action))
            conn.commit()


rate_limiter = RateLimiter()

