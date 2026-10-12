"""Scan Manager module for PENTRAX Web.

Handles scan orchestration, background task lifecycle, event dispatching,
and persistent scan storage.
"""

import asyncio
import io
import json
import logging
import os
import sys
import time
import uuid
from argparse import Namespace
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Any

# Ensure parent directory is in path so pentrax can be imported
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pentrax as ys
from web.db import db_manager

logger = logging.getLogger("pentrax.web.manager")

SCANS_DIR = ROOT_DIR / "scans"
SCANS_DIR.mkdir(parents=True, exist_ok=True)


class ScanInstance:
    """Represents a single scan job and its live lifecycle."""

    def __init__(self, scan_id: str, config: Dict[str, Any], owner_id: Optional[int] = None):
        self.id = scan_id
        self.config = config
        self.owner_id = owner_id
        self.status = "pending"  # pending, running, completed, failed, stopped
        self.created_at = datetime.now().isoformat()
        self.completed_at: Optional[str] = None
        self.duration_seconds: float = 0.0

        self.current_phase: Dict[str, Any] = {
            "phase": 0,
            "total_phases": 6 if config.get("verify", True) else 5,
            "name": "INITIALIZING",
            "detail": "Preparing scan engine...",
        }
        self.progress: Dict[str, Any] = {
            "done": 0,
            "total": 0,
            "percent": 0.0,
            "rate": 0.0,
            "found": 0,
            "filtered": 0,
            "closed": 0,
            "eta_seconds": 0,
        }
        self.logs: List[str] = []
        self.live_hosts: List[str] = []
        self.open_ports: List[Dict[str, Any]] = []
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None

        self._task: Optional[asyncio.Task] = None
        self._subscribers: Set[asyncio.Queue] = set()

    def add_log(self, text: str):
        """Append log line and broadcast to subscribers."""
        ts = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{ts}] {text}"
        self.logs.append(formatted)
        if len(self.logs) > 500:
            self.logs.pop(0)
        self.broadcast({"type": "log", "text": formatted})

    def broadcast(self, event: Dict[str, Any]):
        """Push an event to all connected WebSocket subscribers."""
        event_with_meta = {
            **event,
            "scan_id": self.id,
            "timestamp": time.time(),
        }
        dead = set()
        for q in self._subscribers:
            try:
                q.put_nowait(event_with_meta)
            except asyncio.QueueFull:
                pass
            except Exception:
                dead.add(q)
        self._subscribers.difference_update(dead)

    def to_dict(self, full: bool = False) -> Dict[str, Any]:
        """Convert scan state to dictionary representation."""
        data = {
            "id": self.id,
            "owner_id": self.owner_id,
            "target": self.config.get("target"),
            "status": self.status,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "config": self.config,
            "current_phase": self.current_phase,
            "progress": self.progress,
            "live_hosts_count": len(self.live_hosts),
            "open_ports_count": len(self.open_ports),
            "error": self.error,
        }
        if full:
            data.update({
                "logs": self.logs,
                "live_hosts": self.live_hosts,
                "open_ports": self.open_ports,
                "result": self.result,
            })
        return data


class ScanManager:
    """Manages all scans, concurrency, history, and persistence."""

    def __init__(self):
        self.scans: Dict[str, ScanInstance] = {}
        self._scan_lock = asyncio.Lock()
        self._load_persisted_scans()

    def is_busy(self) -> bool:
        """Check if another scan is currently running."""
        return self._scan_lock.locked() or any(s.status == "running" for s in self.scans.values())

    def _load_persisted_scans(self):
        """Load past scans from SQLite database pentrax.db."""
        try:
            db_scans = db_manager.list_scans(user=None)
            for item in db_scans:
                scan_id = item["id"]
                full_scan = db_manager.get_scan(scan_id)
                if not full_scan:
                    continue
                instance = ScanInstance(scan_id, full_scan.get("config", {}), owner_id=full_scan.get("owner_id"))
                instance.status = full_scan.get("status", "completed")
                instance.created_at = full_scan.get("created_at", instance.created_at)
                instance.completed_at = full_scan.get("completed_at")
                instance.duration_seconds = full_scan.get("duration_seconds", 0.0)
                instance.logs = full_scan.get("logs", [])
                instance.result = full_scan.get("result")
                self.scans[scan_id] = instance
        except Exception as e:
            logger.warning(f"Could not load scans from SQLite: {e}")

    def save_scan(self, instance: ScanInstance):
        """Persist scan state to SQLite database."""
        try:
            db_manager.save_scan(
                scan_id=instance.id,
                owner_id=instance.owner_id,
                target=instance.config.get("target", ""),
                status=instance.status,
                config=instance.config,
                summary=instance.result,
                logs=instance.logs,
                duration=instance.duration_seconds,
                completed_at=instance.completed_at,
            )
        except Exception as e:
            logger.error(f"Failed to persist scan {instance.id} to SQLite: {e}")

    def list_scans(self, user: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """List all scans respecting RBAC user ownership."""
        # Query SQLite for consistent RBAC filtering
        try:
            return db_manager.list_scans(user=user)
        except Exception as e:
            logger.error(f"Failed to list scans from DB: {e}")
            sorted_scans = sorted(
                self.scans.values(),
                key=lambda s: s.created_at,
                reverse=True,
            )
            return [s.to_dict(full=False) for s in sorted_scans]

    def get_scan(self, scan_id: str, full: bool = True) -> Optional[ScanInstance]:
        """Fetch a scan by its ID."""
        instance = self.scans.get(scan_id)
        if not instance:
            # Fallback load from SQLite
            data = db_manager.get_scan(scan_id)
            if data:
                instance = ScanInstance(scan_id, data.get("config", {}), owner_id=data.get("owner_id"))
                instance.status = data.get("status", "completed")
                instance.created_at = data.get("created_at", instance.created_at)
                instance.completed_at = data.get("completed_at")
                instance.duration_seconds = data.get("duration_seconds", 0.0)
                instance.logs = data.get("logs", [])
                instance.result = data.get("result")
                self.scans[scan_id] = instance
        return instance

    def delete_scan(self, scan_id: str, user: Optional[Dict[str, Any]] = None) -> bool:
        """Cancel if running and delete scan from memory and SQLite database."""
        instance = self.scans.get(scan_id)
        if instance and instance.status == "running":
            self.cancel_scan(scan_id)
        
        self.scans.pop(scan_id, None)
        return db_manager.delete_scan(scan_id, user=user)

    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel an in-progress scan."""
        instance = self.scans.get(scan_id)
        if not instance or instance.status != "running":
            return False
        
        instance.status = "stopped"
        ys.stop_flag = True
        instance.add_log("Scan cancellation requested by user.")
        if instance._task and not instance._task.done():
            instance._task.cancel()
        
        self.save_scan(instance)
        instance.broadcast({"type": "status_change", "status": "stopped"})
        return True

    def create_scan(self, config: Dict[str, Any], owner_id: Optional[int] = None) -> ScanInstance:
        """Create and queue a new scan instance with owner_id."""
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S_") + uuid.uuid4().hex[:6]
        instance = ScanInstance(scan_id, config, owner_id=owner_id)
        self.scans[scan_id] = instance
        self.save_scan(instance)
        return instance

    def start_scan(self, instance: ScanInstance) -> asyncio.Task:
        """Launch the scan in the background."""
        task = asyncio.create_task(self._run_scan(instance))
        instance._task = task
        return task

    async def _run_scan(self, instance: ScanInstance):
        """Background coroutine that invokes pentrax.amain with event callbacks."""
        config = instance.config
        target = config.get("target", "").strip()
        instance.status = "running"
        start_time = time.time()
        instance.add_log(f"Starting scan on target: {target}")
        instance.broadcast({"type": "status_change", "status": "running"})

        # Build Namespace matching pentrax CLI arguments
        scan_type = config.get("scan_type", "connect")
        if scan_type != "connect" and not ys.IS_ROOT:
            instance.add_log(f"Scan type '{scan_type}' requires root. Falling back to safe TCP connect.")
            scan_type = "connect"

        ports_arg = config.get("ports", "top100")
        top_n = 0
        if ports_arg == "top50":
            top_n = 50
            ports_val = "all"
        elif ports_arg == "top100":
            top_n = 100
            ports_val = "all"
        elif ports_arg == "all":
            top_n = 0
            ports_val = "all"
        elif ports_arg.startswith("top"):
            try:
                top_n = int(ports_arg[3:])
                ports_val = "all"
            except ValueError:
                top_n = 100
                ports_val = "all"
        else:
            ports_val = ports_arg

        args = Namespace(
            target=target,
            ports=ports_val,
            top=top_n,
            udp=bool(config.get("udp", False)),
            scan_type=scan_type,
            concurrency=int(config.get("concurrency", 2000)),
            timeout=float(config.get("timeout", 1.5)),
            timing=config.get("timing") or None,
            icmp=bool(config.get("icmp", False)),
            no_banner=not bool(config.get("banner", True)),
            no_mac=bool(config.get("no_mac", False)),
            deep=bool(config.get("deep", True)),
            shuffle=bool(config.get("shuffle", False)),
            evasive=bool(config.get("evasive", False)),
            max_delay=float(config.get("max_delay", 2.0)),
            decoy=config.get("decoy") or None,
            mtu=int(config.get("mtu", 0)),
            script=None,
            resume=None,
            checkpoint=None,
            config=None,
            save_profile=None,
            log=None,
            authorize=True,  # User explicitly authorizes via UI modal
            scope=None,
            exclude=config.get("exclude") or None,
            output=None,
            format="json",
            yes=True,
            self_test=False,
            fast=False,
            quick=False,
            stealth=False,
            thorough=False,
            full=False,
            vuln=False,
            verify=bool(config.get("verify", True)),
            dast=bool(config.get("dast", True)),
            ssl_audit=bool(config.get("ssl_audit", True)),
            target_ips=config.get("pinned_ips") or None,
        )

        async def event_callback(ev: Dict[str, Any]):
            ev_type = ev.get("type")
            if ev_type == "phase":
                instance.current_phase = {
                    "phase": ev.get("phase", 0),
                    "total_phases": ev.get("total_phases", 5),
                    "name": ev.get("name", ""),
                    "detail": ev.get("detail", ""),
                }
                instance.add_log(f"Phase {ev.get('phase')}: {ev.get('name')} - {ev.get('detail')}")
                instance.broadcast(ev)

            elif ev_type == "progress":
                instance.progress.update({
                    "done": ev.get("done", 0),
                    "total": ev.get("total", 0),
                    "percent": ev.get("percent", 0.0),
                    "rate": ev.get("rate", 0.0),
                    "found": ev.get("found", 0),
                    "filtered": ev.get("filtered", 0),
                    "closed": ev.get("closed", 0),
                    "eta_seconds": ev.get("eta_seconds", 0),
                })
                instance.broadcast(ev)

            elif ev_type == "host_alive" or (ev_type == "phase_complete" and "live_hosts" in ev):
                live = ev.get("live_hosts", [])
                for h in live:
                    if h not in instance.live_hosts:
                        instance.live_hosts.append(h)
                        instance.add_log(f"Host alive: {h}")
                instance.broadcast({"type": "hosts_update", "live_hosts": instance.live_hosts})

            elif ev_type == "port_found":
                port_data = {
                    "ip": ev.get("ip"),
                    "port": ev.get("port"),
                    "protocol": ev.get("protocol"),
                    "state": ev.get("state"),
                    "service": ev.get("service"),
                }
                instance.open_ports.append(port_data)
                instance.add_log(f"Open port found: {port_data['ip']}:{port_data['port']}/{port_data['protocol']} ({port_data['service']})")
                instance.broadcast(ev)

            elif ev_type == "vulnerability_found":
                instance.add_log(f"Vulnerability found [{ev.get('severity')}]: {ev.get('title')} on {ev.get('ip')}:{ev.get('port')} (SLA: {ev.get('remediation_sla')})")
                instance.broadcast(ev)

            elif ev_type == "scan_completed":
                instance.result = ev.get("export_data")
                instance.broadcast(ev)

            elif ev_type == "log":
                instance.add_log(ev.get("text", ""))

        # Execute scan with concurrency mutex protection
        try:
            async with self._scan_lock:
                export_result = await ys.amain(args, event_callback=event_callback)
            instance.result = export_result or instance.result
            instance.status = "completed"
            instance.duration_seconds = round(time.time() - start_time, 2)
            instance.completed_at = datetime.now().isoformat()
            instance.add_log(f"Scan finished successfully in {instance.duration_seconds}s.")
            instance.broadcast({
                "type": "status_change",
                "status": "completed",
                "duration_seconds": instance.duration_seconds,
            })
        except asyncio.CancelledError:
            instance.status = "stopped"
            instance.duration_seconds = round(time.time() - start_time, 2)
            instance.completed_at = datetime.now().isoformat()
            instance.add_log("Scan stopped by user request.")
            instance.broadcast({"type": "status_change", "status": "stopped"})
        except Exception as e:
            instance.status = "failed"
            instance.error = str(e)
            instance.duration_seconds = round(time.time() - start_time, 2)
            instance.completed_at = datetime.now().isoformat()
            instance.add_log(f"Scan error: {e}")
            logger.exception(f"Scan {instance.id} encountered an error: {e}")
            instance.broadcast({"type": "status_change", "status": "failed", "error": str(e)})
        finally:
            self.save_scan(instance)


# Global singleton instance
scan_manager = ScanManager()

