"""Unit tests for the TLS certificate & grading auditor.

These tests never touch the network: the TLS connection is replaced
with an in-memory fake socket/context pair. They run under the stdlib
unittest runner used by CI (``python -m unittest discover -s tests``),
so they must not depend on pytest.
"""

import datetime
import unittest
from unittest.mock import patch

from scanner.tls_audit import CertReport, TLSAuditor


# ---------- helpers ----------

def make_date(days_from_now):
    dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_from_now)
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

    def __init__(self, cert=None, cipher=None, version=None):
        self._cert = cert
        self._cipher = cipher
        self._version = version

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def getpeercert(self, binary_form=False):
        # No fake DER bytes available, so binary form yields nothing.
        if binary_form:
            return None
        return self._cert

    def cipher(self):
        return self._cipher

    def version(self):
        return self._version


class FakeCtx:
    def __init__(self, ssock):
        self._ssock = ssock

    def wrap_socket(self, sock, server_hostname=None):
        return self._ssock


def run_audit(version="TLSv1.2", cipher_name="ECDHE-RSA-AES256-GCM-SHA384",
              cipher_bits=256, cert=None):
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

class TestCertParsing(unittest.TestCase):

    def test_valid_cert_has_no_flags(self):
        r = parse(make_cert(days=365))
        self.assertFalse(r.is_expired)
        self.assertFalse(r.expiry_warning)
        self.assertFalse(r.is_self_signed)
        self.assertGreater(r.expires_in_days, 300)

    def test_expired_cert_is_flagged(self):
        self.assertTrue(parse(make_cert(days=-5)).is_expired)

    def test_cert_expiring_soon_gets_warning(self):
        r = parse(make_cert(days=10))
        self.assertTrue(r.expiry_warning)
        self.assertFalse(r.is_expired)

    def test_self_signed_detected(self):
        self.assertTrue(parse(make_cert(subject="mysite", issuer="mysite")).is_self_signed)

    def test_subject_issuer_and_sans_parsed(self):
        r = parse(make_cert(sans=["example.com", "www.example.com"]))
        self.assertEqual(r.subject, "example.com")
        self.assertEqual(r.issuer, "Test CA")
        self.assertEqual(r.sans, ["example.com", "www.example.com"])

    def test_missing_fields_default_to_unknown(self):
        r = parse({})
        self.assertEqual(r.subject, "Unknown")
        self.assertEqual(r.issuer, "Unknown")

    def test_bad_date_does_not_crash(self):
        cert = make_cert()
        cert["notAfter"] = "not a date"
        parse(cert)  # should not raise


# ---------- grading ----------

class TestTLSGrading(unittest.TestCase):

    def test_handshake_failure_gets_F(self):
        with patch("scanner.tls_audit.socket.create_connection",
                   side_effect=OSError("connection refused")):
            r = TLSAuditor().audit("test.local", 443)
        self.assertEqual(r.grade, "F")
        self.assertTrue(any("handshake" in v.lower() for v in r.vulnerabilities))

    def test_expired_cert_gets_F(self):
        r = run_audit(cert=make_cert(days=-5))
        self.assertEqual(r.grade, "F")
        self.assertIn("Certificate is EXPIRED", r.vulnerabilities)

    def test_sslv3_gets_F(self):
        self.assertEqual(run_audit(version="SSLv3").grade, "F")

    def test_self_signed_gets_C(self):
        r = run_audit(cert=make_cert(subject="x", issuer="x"))
        self.assertEqual(r.grade, "C")

    def test_tls10_gets_C_and_is_flagged(self):
        r = run_audit(version="TLSv1")
        self.assertEqual(r.grade, "C")
        self.assertTrue(any("Insecure protocol" in v for v in r.vulnerabilities))

    def test_expiring_soon_gets_B(self):
        self.assertEqual(run_audit(cert=make_cert(days=10)).grade, "B")

    def test_cbc_cipher_gets_B(self):
        self.assertEqual(run_audit(cipher_name="ECDHE-RSA-AES256-CBC-SHA").grade, "B")

    def test_tls12_gets_A(self):
        self.assertEqual(run_audit(version="TLSv1.2").grade, "A")

    def test_tls13_gets_A_plus(self):
        self.assertEqual(run_audit(version="TLSv1.3").grade, "A+")

    def test_weak_cipher_is_flagged(self):
        r = run_audit(cipher_name="RC4-MD5")
        self.assertTrue(any("Weak / obsolete cipher" in v for v in r.vulnerabilities))


# ---------- regression: symmetric cipher bits are not the cert key size ----------

class TestCipherBitsRegression(unittest.TestCase):

    def test_modern_tls13_connection_is_not_flagged_weak_key(self):
        """TLS 1.3 AES-256 reports 256 *symmetric* bits.

        That value must be stored as cipher_bits and must not be
        compared against the 2048-bit certificate key threshold.
        """
        r = run_audit(version="TLSv1.3", cipher_name="TLS_AES_256_GCM_SHA384",
                      cipher_bits=256)
        self.assertFalse(r.weak_key)
        self.assertEqual(r.grade, "A+")
        self.assertEqual(r.cipher_bits, 256)
        self.assertEqual(r.key_bits, 2048)

    def test_to_dict_includes_cipher_bits(self):
        r = run_audit(version="TLSv1.3", cipher_name="TLS_AES_256_GCM_SHA384",
                      cipher_bits=256)
        self.assertEqual(r.to_dict()["cipher_bits"], 256)


if __name__ == "__main__":
    unittest.main()
