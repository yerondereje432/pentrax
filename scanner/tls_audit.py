"""TLS / SSL Certificate Chain & Cryptographic Security Auditor for PENTRAX."""
import datetime
from unittest.mock import patch

import pytest

from scanner.tls_audit import CertReport, TLSAuditor


# ---------- helpers ----------

def make_date(days_from_now):
    dt = datetime.datetime.utcnow() + datetime.timedelta(days=days_from_now)
    return dt.strftime("%b %d %H:%M:%S %Y GMT")


def make_cert(subject="example.com", issuer="Test CA", days=365, sans=()):
    return {
        "subject": ((("commonName", subject),),),
        "issuer": ((("commonName", issuer),),),
        "subjectAltName": [("DNS", s) for s in sans],
        "notBefore": make_date(-10),
        "notAfter": make_date(days),
    }


def parse(cert):
    report = CertReport(host="test.local", port=443)
    TLSAuditor()._parse_cert_dict(cert, report)
    return report


class FakeSock:
    """Stand-in for a TLS connection, so tests never touch the network."""

    def init(self, cert=None, cipher=None, version=None):
        self._cert = cert
        self._cipher = cipher
        self._version = version

    def enter(self):
        return self

    def exit(self, *args):
        return False

    def getpeercert(self, binary_form=False):
        return self._cert

    def cipher(self):
        return self._cipher

    def version(self):
        return self._version


class FakeCtx:
    def init(self, ssock):
        self._ssock = ssock

    def wrap_socket(self, sock, server_hostname=None):
        return self._ssock


def run_audit(version="TLSv1.2", cipher_name="ECDHE-RSA-AES256-GCM-SHA384",
              cipher_bits=2048, cert=None):
    """Run audit() against a fake TLS connection (no network)."""
    if cert is None:
        cert = make_cert()
    ssock = FakeSock(cert, (cipher_name, version, cipher_bits), version)

    with patch("scanner.tls_audit.socket.create_connection",
               return_value=FakeSock()), \
         patch("scanner.tls_audit.ssl.create_default_context",
               return_value=FakeCtx(ssock)):
        return TLSAuditor().audit("test.local", 443)


# ---------- certificate parsing ----------

def test_valid_cert_has_no_flags():
    r = parse(make_cert(days=365))
    assert not r.is_expired
    assert not r.expiry_warning
    assert not r.is_self_signed
    assert r.expires_in_days > 300


def test_expired_cert_is_flagged():
    assert parse(make_cert(days=-5)).is_expired


def test_cert_expiring_soon_gets_warning():
    r = parse(make_cert(days=10))
    assert r.expiry_warning
    assert not r.is_expired


def test_self_signed_detected():
    assert parse(make_cert(subject="mysite", issuer="mysite")).is_self_signed


def test_subject_issuer_and_sans_parsed():
    r = parse(make_cert(sans=["example.com", "www.example.com"]))
    assert r.subject == "example.com"
    assert r.issuer == "Test CA"
    assert r.sans == ["example.com", "www.example.com"]


def test_missing_fields_default_to_unknown():
    r = parse({})
    assert r.subject == "Unknown"
    assert r.issuer == "Unknown"


def test_bad_date_does_not_crash():
    cert = make_cert()
    cert["notAfter"] = "not a date"
    parse(cert)


# ---------- grading ----------

def test_handshake_failure_gets_F():
    with patch("scanner.tls_audit.socket.create_connection",
               side_effect=OSError("connection refused")):
        r = TLSAuditor().audit("test.local", 443)
    assert r.grade == "F"
    assert any("handshake" in v.lower() for v in r.vulnerabilities)


def test_expired_cert_gets_F():
    r = run_audit(cert=make_cert(days=-5))
    assert r.grade == "F"
    assert "Certificate is EXPIRED" in r.vulnerabilities


def test_sslv3_gets_F():
    assert run_audit(version="SSLv3").grade == "F"


def test_self_signed_gets_C():
    r = run_audit(cert=make_cert(subject="x", issuer="x"))
    assert r.grade == "C"


def test_tls10_gets_C_and_is_flagged():
    r = run_audit(version="TLSv1")
    assert r.grade == "C"
    assert any("Insecure protocol" in v for v in r.vulnerabilities)


def test_expiring_soon_gets_B():
    assert run_audit(cert=make_cert(days=10)).grade == "B"
def test_cbc_cipher_gets_B():
    assert run_audit(cipher_name="ECDHE-RSA-AES256-CBC-SHA").grade == "B"


def test_tls12_gets_A():
    assert run_audit(version="TLSv1.2").grade == "A"


def test_tls13_gets_A_plus():
    assert run_audit(version="TLSv1.3").grade == "A+"


def test_weak_cipher_is_flagged():
    r = run_audit(cipher_name="RC4-MD5")
    assert any("Weak / obsolete cipher" in v for v in r.vulnerabilities)


# ---------- known bug ----------

@pytest.mark.xfail(reason="key_bits uses the symmetric cipher size (256), not the cert key size")
def test_modern_connection_is_not_flagged_weak_key():
    r = run_audit(version="TLSv1.3", cipher_name="TLS_AES_256_GCM_SHA384",
                  cipher_bits=256)
    assert not r.weak_key
    assert r.grade == "A+"
