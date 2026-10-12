"""FastAPI web dashboard for yerscan.

Serves a small single-page UI and a JSON API. A scan started in a terminal is recorded into the
shared SQLite database (see yerscan_store), so it shows up here live; a scan started from the
dashboard's new-scan form is launched as a yerscan.py worker subprocess (with --no-record, since
the dashboard already owns that scan row) and streamed back over SSE.

Run with:  python3 -m web   (reads YERSCAN_WEB_PASSWORD and friends from the environment)
"""

import asyncio
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import hmac
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from yerscan_store import (
    ACTIVE,
    CapacityError,
    Database,
    DB_NAME,
    default_data_dir,
    pid_alive,
)
from yerscan_policy import evaluate_scope, is_private_ip, load_scope_file

REPO_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"


@dataclass
class Settings:
    db_path: Path
    scans_dir: Path
    password: str
    session_ttl: int = 3600 * 8
    scope_file: Optional[Path] = None
    max_concurrent: int = 2
    max_hosts: int = 1024
    max_ports: int = 1000
    host: str = "127.0.0.1"
    port: int = 8000

    @staticmethod
    def from_env() -> "Settings":
        data_dir = default_data_dir()
        data_dir.mkdir(parents=True, exist_ok=True)
        scope = os.environ.get("YERSCAN_SCOPE_FILE")
        return Settings(
            db_path=data_dir / DB_NAME,
            scans_dir=data_dir / "scans",
            password=os.environ.get("YERSCAN_WEB_PASSWORD", ""),
            session_ttl=int(os.environ.get("YERSCAN_WEB_SESSION_TTL", str(3600 * 8))),
            scope_file=Path(scope) if scope else None,
            max_concurrent=int(os.environ.get("YERSCAN_MAX_CONCURRENT", "2")),
            max_hosts=int(os.environ.get("YERSCAN_MAX_HOSTS", "1024")),
            max_ports=int(os.environ.get("YERSCAN_MAX_PORTS", "1000")),
            host=os.environ.get("YERSCAN_WEB_HOST", "127.0.0.1"),
            port=int(os.environ.get("YERSCAN_WEB_PORT", "8000")),
        )


def _iso(ts):
    if not ts:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))


class Authenticator:
    """Password-gated sessions with a per-IP login rate limit and double-submit CSRF tokens."""

    def __init__(self, password: str, session_ttl: int = 3600 * 8):
        self.password = password
        self.session_ttl = session_ttl
        self._tokens: Dict[str, tuple] = {}  # token -> (expiry, csrf)
        self._lock = threading.Lock()
        self._fails: Dict[str, List[float]] = {}  # ip -> attempt timestamps

    def _allow_attempt(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            attempts = [t for t in self._fails.get(ip, []) if now - t < 60]
            if len(attempts) >= 8:
                return False
            attempts.append(now)
            self._fails[ip] = attempts
        return True

    def login(self, password: str, ip: str) -> Optional[dict]:
        if not self._allow_attempt(ip):
            return None
        if not self.password or len(self.password) < 12:
            return None
        if not hmac.compare_digest(password, self.password):
            return None
        token = secrets.token_hex(32)
        csrf = secrets.token_hex(16)
        with self._lock:
            self._tokens[token] = (time.time() + self.session_ttl, csrf)
        return {"token": token, "csrf": csrf}

    def check(self, token: Optional[str]):
        """Return the (token, csrf) for a valid session, else None."""
        if not token:
            return None
        with self._lock:
            entry = self._tokens.get(token)
            if not entry:
                return None
            expiry, csrf = entry
            if expiry < time.time():
                self._tokens.pop(token, None)
                return None
            return (token, csrf)

    def logout(self, token: Optional[str]):
        with self._lock:
            self._tokens.pop(token, None)


def _token_from_request(request: Request) -> Optional[str]:
    cookie = request.cookies.get("yerscan_session")
    if cookie:
        return cookie
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.query_params.get("token")


def require_auth(request: Request):
    token = _token_from_request(request)
    session = request.app.state.auth.check(token)
    if not session:
        raise HTTPException(status_code=401, detail="authentication required")
    # Single-page app: enforce CSRF only on state-changing requests.
    if request.method.upper() in ("POST", "PUT", "DELETE", "PATCH"):
        csrf = request.headers.get("X-CSRF-Token") or request.query_params.get("csrf")
        if not csrf or not hmac.compare_digest(csrf, session[1]):
            raise HTTPException(status_code=403, detail="csrf token missing or invalid")
    return session


def _scan_row(row: dict) -> dict:
    return {
        "id": row["id"],
        "target": row["target"],
        "ports": row["ports"],
        "verify": bool(row["verify"]),
        "authorized": bool(row["authorized"]),
        "status": row["status"],
        "source": row["source"],
        "created_at": _iso(row["created_at"]),
        "started_at": _iso(row["started_at"]),
        "finished_at": _iso(row["finished_at"]),
        "host_count": row["host_count"],
        "error": row["error"],
        "pid": row["pid"],
    }


def create_app(settings: Settings) -> FastAPI:
    app = FastAPI(title="yerscan dashboard", version="1.0")
    settings.scans_dir.mkdir(parents=True, exist_ok=True)

    db = Database(settings.db_path)
    db.reap_stale()  # only scans whose process is gone; live terminal scans are left alone
    auth = Authenticator(settings.password, settings.session_ttl)
    scope_networks = load_scope_file(str(settings.scope_file)) if settings.scope_file else None

    from web.jobs import JobManager
    jobs = JobManager(settings, db)

    app.state.db = db
    app.state.auth = auth
    app.state.settings = settings
    app.state.scope_networks = scope_networks
    app.state.jobs = jobs

    # Allow-embed handling for iframe previews (Arena, etc.).
    allow_embed = os.environ.get("YERSCAN_ALLOW_EMBED", "").lower() in ("1", "true", "yes", "on")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        if allow_embed:
            resp.headers["X-Frame-Options"] = "ALLOWALL"
            resp.headers["Content-Security-Policy"] = "frame-ancestors *"
        else:
            resp.headers["X-Frame-Options"] = "DENY"
            resp.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "same-origin"
        return resp

    @app.get("/api/config")
    def api_config(_=Depends(require_auth)):
        return {
            "max_hosts": settings.max_hosts,
            "max_ports": settings.max_ports,
            "max_concurrent": settings.max_concurrent,
            "scope_file": str(settings.scope_file) if settings.scope_file else None,
            "scan_types": ["connect"],
        }

    @app.post("/api/login")
    def api_login(request: Request, payload: dict):
        password = payload.get("password", "")
        ip = request.client.host if request.client else "unknown"
        result = auth.login(password, ip)
        if not result:
            raise HTTPException(status_code=401, detail="invalid password")
        resp = JSONResponse({"ok": True, "csrf": result["csrf"]})
        resp.set_cookie(
            "yerscan_session", result["token"], httponly=True, samesite="Lax",
            max_age=settings.session_ttl, secure=(os.environ.get("YERSCAN_WEB_SECURE_COOKIE") == "1"),
        )
        return resp

    @app.post("/api/logout")
    def api_logout(request: Request, _=Depends(require_auth)):
        auth.logout(_token_from_request(request))
        resp = JSONResponse({"ok": True})
        resp.delete_cookie("yerscan_session")
        return resp

    @app.get("/api/scans")
    def api_scans(_=Depends(require_auth)):
        rows = db.list_scans(limit=200)
        return {"scans": [_scan_row(r) for r in rows], "summary": db.summary()}

    @app.get("/api/scans/{scan_id}")
    def api_scan_detail(scan_id: str, _=Depends(require_auth)):
        row = db.get_scan(scan_id)
        if not row:
            raise HTTPException(status_code=404, detail="scan not found")
        hosts = db.scan_hosts(scan_id)
        events = db.events_after(scan_id, limit=1000)
        return {
            "scan": _scan_row(row),
            "hosts": hosts,
            "event_count": len(events),
            "events": [{"type": e["type"], "ts": e["ts"], "data": e["data"]} for e in events],
        }

    @app.get("/api/scans/{scan_id}/events")
    async def api_scan_events(scan_id: str, request: Request, _=Depends(require_auth)):
        row = db.get_scan(scan_id)
        if not row:
            raise HTTPException(status_code=404, detail="scan not found")
        source = row["source"]

        async def gen():
            after = 0
            last_size = 0
            stable_polls = 0
            while True:
                if await request.is_disconnected():
                    return
                if source == "cli":
                    rows = db.events_after(scan_id, after_seq=after, limit=500)
                    for r in rows:
                        after = r["seq"]
                        yield f"event: {r['type']}\ndata: {json.dumps(r['data'])}\n\n"
                    status = db.get_scan(scan_id)["status"]
                    if status not in ACTIVE and not rows:
                        yield "event: end\ndata: {}\n\n"
                        return
                else:
                    path = settings.scans_dir / scan_id / "events.jsonl"
                    grew = False
                    if path.exists():
                        size = path.stat().st_size
                        if size >= last_size:
                            with open(path, "r", encoding="utf-8") as fh:
                                fh.seek(last_size)
                                for line in fh:
                                    line = line.strip()
                                    if not line:
                                        continue
                                    try:
                                        obj = json.loads(line)
                                    except ValueError:
                                        continue
                                    etype = obj.get("type")
                                    data = {k: v for k, v in obj.items() if k not in ("type", "ts")}
                                    yield f"event: {etype}\ndata: {json.dumps(data)}\n\n"
                            if size > last_size:
                                grew = True
                            last_size = size
                    if not pid_alive(row["pid"]):
                        if not path.exists() or (not grew and stable_polls >= 1):
                            yield "event: end\ndata: {}\n\n"
                            return
                        stable_polls += 1
                    else:
                        stable_polls = 0
                await asyncio.sleep(0.5)

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.post("/api/scans")
    def api_start_scan(request: Request, payload: dict, _=Depends(require_auth)):
        target = (payload.get("target") or "").strip()
        ports = (payload.get("ports") or "").strip()
        verify = bool(payload.get("verify", False))
        authorized = bool(payload.get("authorized", False))
        if not target or not ports:
            raise HTTPException(status_code=400, detail="target and ports are required")

        decision = evaluate_scope(target, authorized=authorized, allow_networks=scope_networks)
        if not decision.allowed:
            raise HTTPException(status_code=400, detail=decision.reason)
        if decision.host_count > settings.max_hosts:
            raise HTTPException(
                status_code=400,
                detail=f"too many hosts ({decision.host_count}); limit is {settings.max_hosts}",
            )
        # Sanity-check the port specification without expanding huge ranges.
        try:
            parsed_ports = _count_ports(ports)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"invalid ports: {e}")
        if parsed_ports > settings.max_ports:
            raise HTTPException(
                status_code=400,
                detail=f"too many ports ({parsed_ports}); limit is {settings.max_ports}",
            )

        try:
            scan_id = request.app.state.jobs.start(target, ports, verify, authorized)
        except CapacityError as e:
            raise HTTPException(status_code=429, detail=str(e))
        return {"ok": True, "id": scan_id}

    @app.get("/")
    def index():
        index_path = STATIC_DIR / "index.html"
        if index_path.exists():
            return FileResponse(index_path)
        return HTMLResponse(
            "<!doctype html><meta charset=utf-8><title>yerscan</title>"
            "<p>Dashboard files missing. Run from the repository root.</p>"
        )

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    return app


def _count_ports(spec: str) -> int:
    """Count the number of ports in a spec like '22,80,8000-8100' without allocating them all."""
    total = 0
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo < 1 or hi > 65535 or lo > hi:
                raise ValueError(part)
            total += (hi - lo + 1)
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(part)
            total += 1
    if total == 0:
        raise ValueError("no ports")
    return total
