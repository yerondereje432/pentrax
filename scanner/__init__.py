"""PENTRAX Scanner Package — Elite Red Team & Vulnerability Assessment Engine."""

from .core import (
    CVSSScore,
    HostResult,
    IS_LINUX,
    IS_ROOT,
    IS_WINDOWS,
    PortResult,
    PortState,
    RiskLevel,
    ScanType,
    VERSION,
    Vulnerability,
)
from .notifier import Notifier, notifier
from .plugin_loader import PluginManager, YAMLTemplateEngine
from .recon import PassiveRecon, ReconResult
from .reporting import (
    export_csv,
    export_html,
    export_json,
    generate_executive_summary,
    generate_markdown,
)
from .threat_intel import ThreatIntel, ThreatProfile, threat_intel
from .tls_audit import CertReport, TLSAuditor, tls_auditor
from .vuln_feed import CVEFeedUpdater

__version__ = VERSION

__all__ = [
    "VERSION",
    "IS_ROOT",
    "IS_LINUX",
    "IS_WINDOWS",
    "ScanType",
    "PortState",
    "RiskLevel",
    "CVSSScore",
    "Vulnerability",
    "PortResult",
    "HostResult",
    "PluginManager",
    "YAMLTemplateEngine",
    "PassiveRecon",
    "ReconResult",
    "CVEFeedUpdater",
    "Notifier",
    "notifier",
    "TLSAuditor",
    "CertReport",
    "tls_auditor",
    "ThreatIntel",
    "ThreatProfile",
    "threat_intel",
    "generate_executive_summary",
    "generate_markdown",
    "export_json",
    "export_csv",
    "export_html",
]

