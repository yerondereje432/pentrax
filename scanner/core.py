"""Core data structures, enums, CVSS scoring, and runtime state for PENTRAX."""

import os
import sys
import platform
import logging
import resource
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any, Callable

# System detection
IS_ROOT = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
IS_LINUX = platform.system() == "Linux"
IS_WINDOWS = platform.system() == "Windows"

# File descriptor limit expansion
try:
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 65535), hard))
except Exception:
    pass

VERSION = "8.0"


class PortState(Enum):
    """Port states matching nmap semantics."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"


class ScanType(Enum):
    """Supported network scan probe types."""
    CONNECT = "connect"
    SYN = "syn"
    ACK = "ack"
    FIN = "fin"
    XMAS = "xmas"
    NULL = "null"
    WINDOW = "window"
    UDP = "udp"


class RiskLevel(Enum):
    """Vulnerability risk severity tiers."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CISLevel(Enum):
    """CIS security benchmark compliance tiers."""
    LEVEL1 = "Level 1"
    LEVEL2 = "Level 2"


def _roundup_cvss(x: float) -> float:
    """CVSS v3.1 Roundup: smallest one-decimal value >= x, computed without float drift."""
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000
    return (i // 10000 + 1) / 10


@dataclass
class CVSSScore:
    """Structured CVSS v3.1 scoring implementation compliant with FIRST specification."""
    base_score: float = 0.0
    vector: str = ""
    severity: str = "NONE"
    attack_vector: str = "N"  # Network
    attack_complexity: str = "L"  # Low
    privileges_required: str = "N"  # None
    user_interaction: str = "N"  # None
    scope: str = "U"  # Unchanged
    confidentiality: str = "N"  # None
    integrity: str = "N"  # None
    availability: str = "N"  # None

    def __post_init__(self):
        def _norm(val: str, default: str) -> str:
            v_str = str(val).upper().strip()
            return v_str[0] if v_str else default

        if len(str(self.attack_vector)) > 1:
            self.attack_vector = _norm(self.attack_vector, "N")
        if len(str(self.attack_complexity)) > 1:
            self.attack_complexity = _norm(self.attack_complexity, "L")
        if len(str(self.privileges_required)) > 1:
            self.privileges_required = _norm(self.privileges_required, "N")
        if len(str(self.user_interaction)) > 1:
            self.user_interaction = _norm(self.user_interaction, "N")
        if len(str(self.scope)) > 1:
            self.scope = _norm(self.scope, "U")
        if len(str(self.confidentiality)) > 1:
            self.confidentiality = _norm(self.confidentiality, "N")
        if len(str(self.integrity)) > 1:
            self.integrity = _norm(self.integrity, "N")
        if len(str(self.availability)) > 1:
            self.availability = _norm(self.availability, "N")

        if self.base_score == 0.0 and (self.confidentiality != "N" or self.integrity != "N" or self.availability != "N"):
            self.calculate()

    def calculate(self):
        """Compute the CVSS v3.1 base score from vector components (FIRST spec section 7.1)."""
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}.get(self.attack_vector, 0.85)
        ac = {"L": 0.77, "H": 0.44}.get(self.attack_complexity, 0.77)
        changed = self.scope == "C"
        if changed:
            pr = {"N": 0.85, "L": 0.68, "H": 0.50}.get(self.privileges_required, 0.85)
        else:
            pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(self.privileges_required, 0.85)
        ui = {"N": 0.85, "R": 0.62}.get(self.user_interaction, 0.85)
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        c = cia.get(self.confidentiality, 0.0)
        i = cia.get(self.integrity, 0.0)
        a = cia.get(self.availability, 0.0)

        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        if changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            self.base_score = 0.0
        elif changed:
            self.base_score = _roundup_cvss(min(1.08 * (impact + exploitability), 10.0))
        else:
            self.base_score = _roundup_cvss(min(impact + exploitability, 10.0))

        if self.base_score >= 9.0:
            self.severity = "CRITICAL"
        elif self.base_score >= 7.0:
            self.severity = "HIGH"
        elif self.base_score >= 4.0:
            self.severity = "MEDIUM"
        elif self.base_score > 0:
            self.severity = "LOW"
        else:
            self.severity = "NONE"

        self.vector = f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/PR:{self.privileges_required}/UI:{self.user_interaction}/S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/A:{self.availability}"
        return self


@dataclass
class CISBenchmark:
    """CIS benchmark reference."""
    id: str = ""
    title: str = ""
    level: str = "Level 1"
    description: str = ""
    remediation: str = ""


@dataclass
class Vulnerability:
    """Structured vulnerability finding with CVSS, CIS, and remediation SLA."""
    id: str = ""  # CVE or custom finding ID
    title: str = ""
    description: str = ""
    cvss: CVSSScore = field(default_factory=CVSSScore)
    cis: CISBenchmark = field(default_factory=CISBenchmark)
    risk_level: str = "INFO"
    affected_service: str = ""
    affected_port: int = 0
    evidence: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    remediation_sla: str = ""  # e.g. "48 Hours", "14 Days", "30 Days", "90 Days"
    category: str = ""  # e.g. "DAST", "SSL/TLS", "CVE", "MISCONFIG"

    def __post_init__(self):
        risk_str = self.risk_level.value if hasattr(self.risk_level, "value") else str(self.risk_level or "INFO")
        self.risk_level = risk_str.upper()

        if not self.remediation_sla:
            sla_map = {
                "CRITICAL": "48 Hours",
                "HIGH": "14 Days",
                "MEDIUM": "30 Days",
                "LOW": "90 Days",
                "INFO": "90 Days",
            }
            self.remediation_sla = sla_map.get(self.risk_level, "30 Days")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.risk_level,
            "risk_level": self.risk_level,
            "cvss": self.cvss.base_score if hasattr(self.cvss, "base_score") else 0.0,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "remediation_sla": self.remediation_sla,
            "affected_port": self.affected_port,
            "affected_service": self.affected_service,
            "references": self.references,
        }


@dataclass
class PortResult:
    """Structured port scan result."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = "unknown"
    version: str = ""
    banner: str = ""
    os_hint: str = ""
    ttl: int = 0
    window_size: int = 0
    risk_level: str = ""
    risk_reason: str = ""
    cves: List[Dict] = field(default_factory=list)
    vulns: List[Vulnerability] = field(default_factory=list)
    deep: Dict = field(default_factory=dict)
    extra: Dict = field(default_factory=dict)


@dataclass
class HostResult:
    """Structured host scan result."""
    ip: str
    hostname: str = ""
    mac: str = ""
    os_guess: str = ""
    os_confidence: float = 0.0
    ttl: int = 0
    risk_score: int = 0
    risk_level: str = "LOW"
    ports: List[PortResult] = field(default_factory=list)
    vulns: List[Vulnerability] = field(default_factory=list)
    discovery_method: str = ""


@dataclass
class ScanState:
    """Checkpoint state for scan resumption."""
    target: str = ""
    scan_type: str = "connect"
    ports: List[int] = field(default_factory=list)
    started: str = ""
    completed_hosts: List[str] = field(default_factory=list)
    pending_hosts: List[str] = field(default_factory=list)
    results: Dict = field(default_factory=dict)


class C:
    """ANSI color formatting helpers."""
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
    M = "\033[95m"; CY = "\033[96m"; W = "\033[97m"; D = "\033[2m"
    BOLD = "\033[1m"; E = "\033[0m"


audit_logger = logging.getLogger("pentrax.audit")
audit_logger.setLevel(logging.DEBUG)


def setup_logging(log_file=None):
    """Setup file-based audit logging."""
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        fh.setFormatter(formatter)
        audit_logger.addHandler(fh)

    sh = logging.StreamHandler()
    sh.setLevel(logging.WARNING)
    audit_logger.addHandler(sh)


def log_audit(level: str, message: str, **kwargs):
    """Write an entry to the audit log."""
    extra = " | ".join(f"{k}={v}" for k, v in kwargs.items()) if kwargs else ""
    full_msg = f"{message} {extra}".strip()
    getattr(audit_logger, level.lower(), audit_logger.info)(full_msg)


# Global Engine State Flags
stop_flag = False
progress_data = {
    "done": 0, "total": 0, "found": 0, "filtered": 0, "closed": 0,
    "current_host": "", "rate": 0, "eta": "", "phase": 0,
    "phase_name": "", "phase_detail": ""
}
event_callback: Optional[Callable] = None


def set_event_callback(cb: Optional[Callable]):
    """Register an asynchronous event listener for scan telemetry."""
    global event_callback
    event_callback = cb


async def emit_event(event_type: str, data: Optional[Dict] = None):
    """Emit telemetry event to connected observer."""
    if event_callback:
        try:
            payload = {"type": event_type}
            if data:
                payload.update(data)
            await event_callback(payload)
        except Exception:
            pass


def reset_scan_state():
    """Reset engine state variables between consecutive scans."""
    global stop_flag, progress_data
    stop_flag = False
    progress_data = {
        "done": 0, "total": 0, "found": 0, "filtered": 0, "closed": 0,
        "current_host": "", "rate": 0, "eta": "", "phase": 0,
        "phase_name": "", "phase_detail": ""
    }
