"""TLS / SSL Certificate Chain & Cryptographic Security Auditor for PENTRAX."""
import datetime
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CertReport:
    host: str
    port: int
    subject: str = "Unknown"
    issuer: str = "Unknown"
    sans: List[str] = field(default_factory=list)
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    expires_in_days: int = 0
    is_expired: bool = False
    expiry_warning: bool = False
    is_self_signed: bool = False
    key_bits: int = 2048
    key_type: str = "RSA"
    weak_key: bool = False
    tls_version: str = "Unknown"
    cipher_suite: str = "Unknown"
    ocsp_stapling: bool = False
    grade: str = "A"
    vulnerabilities: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "subject": self.subject,
            "issuer": self.issuer,
            "sans": self.sans,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "expires_in_days": self.expires_in_days,
            "is_expired": self.is_expired,
            "expiry_warning": self.expiry_warning,
            "is_self_signed": self.is_self_signed,
            "key_bits": self.key_bits,
            "key_type": self.key_type,
            "weak_key": self.weak_key,
            "tls_version": self.tls_version,
            "cipher_suite": self.cipher_suite,
            "ocsp_stapling": self.ocsp_stapling,
            "grade": self.grade,
            "vulnerabilities": self.vulnerabilities,
        }


class TLSAuditor:
    """Deep TLS / SSL cryptographic auditor using Python standard library ssl."""

    def audit(self, host: str, port: int = 443, timeout: float = 5.0) -> CertReport:
        report = CertReport(host=host, port=port)

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    report.tls_version = ssock.version() or "TLSv1.2"
                    if cipher:
                        report.cipher_suite = cipher[0]
                        report.key_bits = cipher[2] or 2048

                    if cert:
                        self._parse_cert_dict(cert, report)

        except Exception as e:
            report.vulnerabilities.append(f"TLS handshake failure: {str(e)}")
            report.grade = "F"
            return report

        # Security evaluation & grading
        vulns: List[str] = []
        if report.is_expired:
            vulns.append("Certificate is EXPIRED")
        elif report.expiry_warning:
            vulns.append(f"Certificate expires soon ({report.expires_in_days} days)")

        if report.is_self_signed:
            vulns.append("Self-signed or untrusted CA certificate")

        if report.key_bits < 2048:
            report.weak_key = True
            vulns.append(f"Weak cryptographic key size ({report.key_bits} bits < 2048)")

        if report.tls_version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            vulns.append(f"Insecure protocol version {report.tls_version} in use")

        if any(weak in report.cipher_suite.upper() for weak in ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"]):
            vulns.append(f"Weak / obsolete cipher suite {report.cipher_suite}")

        report.vulnerabilities = vulns

        # Assign letter grade
        if report.is_expired or report.weak_key or report.tls_version in ("SSLv2", "SSLv3"):
            report.grade = "F"
        elif report.is_self_signed or report.tls_version in ("TLSv1", "TLSv1.1"):
            report.grade = "C"
        elif report.expiry_warning or "CBC" in report.cipher_suite:
            report.grade = "B"
        elif report.tls_version == "TLSv1.3":
            report.grade = "A+"
        else:
            report.grade = "A"

        return report

    def _parse_cert_dict(self, cert: Dict[str, Any], report: CertReport):
        # Subject & Issuer
        subj_parts = [val[0][1] for val in cert.get("subject", []) if val and len(val[0]) > 1]
        iss_parts = [val[0][1] for val in cert.get("issuer", []) if val and len(val[0]) > 1]
        report.subject = ", ".join(subj_parts) if subj_parts else "Unknown"
        report.issuer = ", ".join(iss_parts) if iss_parts else "Unknown"

        # Check self-signed
        if report.subject and report.issuer and report.subject == report.issuer:
            report.is_self_signed = True

        # SANs
        sans = [item[1] for item in cert.get("subjectAltName", []) if item[0] == "DNS"]
        report.sans = sans

        # Dates
        not_after = cert.get("notAfter")
        not_before = cert.get("notBefore")
        report.valid_from = not_before
        report.valid_until = not_after

        if not_after:
            try:
                # SSL standard date format: 'May 23 12:00:00 2026 GMT'
                dt_after = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                diff = dt_after - now
                report.expires_in_days = diff.days
                if report.expires_in_days < 0:
                    report.is_expired = True
                elif report.expires_in_days < 30:
                    report.expiry_warning = True
            except Exception:
                pass


tls_auditor = TLSAuditor()
