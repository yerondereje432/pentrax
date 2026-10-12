"""Regression tests for pentrax.py.

Run without privileges (raw-socket tests are skipped):
    python3 -m unittest discover -s tests -v

Run everything, including raw SYN/ACK/FIN/NULL/XMAS/WINDOW tests on loopback:
    sudo python3 -m unittest discover -s tests -v
(sudo may need -E if the environment matters; the tests do not need any network access)
"""

import asyncio
import contextlib
import importlib.util
import ipaddress
import io
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("pentrax", os.path.join(ROOT, "pentrax.py"))
ys = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ys)


def _free_port(family=socket.AF_INET, host="127.0.0.1"):
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def listener(host="127.0.0.1", family=socket.AF_INET):
    """Open a TCP listener on an ephemeral port and yield the port."""
    srv = socket.socket(family, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, 0))
    srv.listen(16)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def accept_loop():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
            except OSError:
                pass

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()
    try:
        yield port
    finally:
        stop.set()
        t.join(timeout=2)
        srv.close()


def _run(coro):
    """Run a coroutine on a fresh loop and always release the shared raw engine."""
    async def wrapper():
        try:
            return await coro
        finally:
            ys.close_raw_engine()
    return asyncio.run(wrapper())


# ═══════════════════════════════════════════════════════════════════
#  Bug 3: TCP checksum must include the pseudo-header (RFC 793)
# ═══════════════════════════════════════════════════════════════════

class TestPacketChecksums(unittest.TestCase):

    def _segment(self, pkt):
        ihl = (pkt[0] & 0x0F) * 4
        return pkt[ihl:]

    def test_tcp_checksum_verifies_with_pseudo_header(self):
        pkt = ys.create_tcp_packet("10.0.0.1", "10.0.0.2", 40000, 80, ys.TCP_SYN, 1234)[0]
        seg = self._segment(pkt)
        pseudo = (socket.inet_aton("10.0.0.1") + socket.inet_aton("10.0.0.2")
                  + struct.pack("!BBH", 0, 6, len(seg)))
        # A segment with a correct checksum sums to 0 over pseudo-header + segment
        self.assertEqual(ys.checksum(pseudo + seg), 0)

    def test_ip_header_checksum_valid(self):
        pkt = ys.create_tcp_packet("10.0.0.1", "10.0.0.2", 40000, 80, ys.TCP_SYN, 1)[0]
        self.assertEqual(ys.checksum(pkt[:20]), 0)

    def test_fragments_are_8_byte_aligned_and_reassemble(self):
        options = b"\x02\x04\x05\xb4\x01\x03\x03\x07\x01\x01\x04\x02"  # MSS, WS, SACK-permitted
        segment_pkt = ys.create_tcp_packet("10.0.0.1", "10.0.0.2", 40000, 80, ys.TCP_SYN, 99,
                                           options=options)[0]
        original_segment = segment_pkt[20:]
        frags = ys.create_tcp_packet("10.0.0.1", "10.0.0.2", 40000, 80, ys.TCP_SYN, 99,
                                     options=options, mtu=24)
        self.assertGreater(len(frags), 1)
        payloads = []
        for i, f in enumerate(frags):
            flags_frag = struct.unpack("!H", f[6:8])[0]
            offset = (flags_frag & 0x1FFF) * 8
            more = bool(flags_frag & 0x2000)
            data = f[20:]
            if more:
                self.assertEqual(len(data) % 8, 0, "non-final fragment must be a multiple of 8 bytes")
            self.assertEqual(ys.checksum(f[:20]), 0)
            payloads.append((offset, data))
        reassembled = b"".join(d for _, d in sorted(payloads))
        self.assertEqual(reassembled, original_segment)


# ═══════════════════════════════════════════════════════════════════
#  Bugs 4, 5 and CVSS: CVE matching and scoring
# ═══════════════════════════════════════════════════════════════════

class TestCVSS(unittest.TestCase):

    def _score(self, **kw):
        base = dict(attack_vector="N", attack_complexity="L", privileges_required="N",
                    user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="H")
        base.update(kw)
        return ys.CVSSScore(**base).calculate()

    def test_critical_network_unauthenticated(self):
        c = self._score()
        self.assertEqual(c.base_score, 9.8)
        self.assertEqual(c.severity, "CRITICAL")

    def test_scope_changed_full_impact_is_10(self):
        self.assertEqual(self._score(scope="C").base_score, 10.0)

    def test_high_example(self):
        c = self._score(attack_complexity="H", privileges_required="L")
        self.assertEqual(c.base_score, 7.5)
        self.assertEqual(c.severity, "HIGH")

    def test_no_impact_is_zero(self):
        self.assertEqual(self._score(confidentiality="N", integrity="N", availability="N").base_score, 0.0)


class TestCVEMatching(unittest.TestCase):

    def cves(self, banner, service="HTTP"):
        return {v["cve"] for v in ys.check_cve(banner, service)}

    def test_apache_patched_version_not_flagged(self):
        # Bug 5: 2.4.52 is fixed for CVE-2021-44790 (affects <= 2.4.51)
        self.assertNotIn("CVE-2021-44790", self.cves("Apache/2.4.52 (Ubuntu)"))

    def test_apache_vulnerable_version_flagged(self):
        self.assertIn("CVE-2021-44790", self.cves("Apache/2.4.50 (Ubuntu)"))
        self.assertIn("CVE-2022-22720", self.cves("Apache/2.4.50 (Ubuntu)"))

    def test_openssh_ranges(self):
        self.assertIn("CVE-2018-15473", self.cves("OpenSSH_7.4p1", "SSH"))
        self.assertIn("CVE-2023-38408", self.cves("OpenSSH_9.2p1 Debian-2", "SSH"))  # 9.0-9.2 were missed before
        self.assertNotIn("CVE-2023-38408", self.cves("OpenSSH_9.3p2", "SSH"))
        self.assertNotIn("CVE-2021-28041", self.cves("OpenSSH_8.9p1", "SSH"))

    def test_redis_two_ranges(self):
        self.assertIn("CVE-2021-32625", self.cves("redis_version:6.2.3", "Redis"))
        self.assertIn("CVE-2021-32625", self.cves("redis_version:6.0.9", "Redis"))
        self.assertNotIn("CVE-2021-32625", self.cves("redis_version:6.2.4", "Redis"))
        self.assertNotIn("CVE-2021-32625", self.cves("redis_version:5.0.7", "Redis"))

    def test_iis_only_6(self):
        # Bug 5: CVE-2017-7269 affects IIS 6.0 only
        self.assertIn("CVE-2017-7269", self.cves("Microsoft-IIS/6.0", "HTTP"))
        self.assertNotIn("CVE-2017-7269", self.cves("Microsoft-IIS/10.0", "HTTP"))

    def test_nginx_range(self):
        self.assertIn("CVE-2021-23017", self.cves("nginx/1.18.0"))
        self.assertNotIn("CVE-2021-23017", self.cves("nginx/1.20.1"))

    def test_ms17_010_not_matched_by_build_numbers(self):
        # Bug 4: build numbers such as 17763 or 20348 contain '7' or '8' but are not OS versions
        self.assertNotIn("MS17-010", self.cves("Windows Server 2019 10.0.17763", "SMB"))
        self.assertNotIn("MS17-010", self.cves("Windows Server 2022 Standard 10.0.20348", "SMB"))
        self.assertNotIn("MS17-010", self.cves("Windows 10 Pro 10.0.19045", "SMB"))

    def test_ms17_010_matches_old_products(self):
        self.assertIn("MS17-010", self.cves("Windows Server 2012 R2 6.3.9600", "SMB"))
        self.assertIn("MS17-010", self.cves("Windows 7 Professional", "SMB"))
        self.assertIn("MS17-010", self.cves("Windows 8.1 Pro", "SMB"))

    def test_ms17_010_is_marked_inferred(self):
        match = [v for v in ys.check_cve("Windows 7 Professional", "SMB") if v["cve"] == "MS17-010"][0]
        self.assertLess(match["confidence"], 0.9)

    def test_parse_version(self):
        self.assertEqual(ys.parse_version("9.2p1"), (9, 2, 0, 1))
        self.assertEqual(ys.parse_version("2.4.52"), (2, 4, 52, 0))

    def test_backport_detection_and_sla(self):
        # Plain vulnerable version without distribution markers
        plain_cves = ys.check_cve("OpenSSH_7.4p1", "SSH")
        self.assertTrue(len(plain_cves) > 0)
        self.assertFalse(plain_cves[0]["is_backport"])
        self.assertEqual(plain_cves[0]["severity"], "MEDIUM")
        self.assertEqual(plain_cves[0]["remediation_sla"], "30 Days")

        # Debian backported version with +deb9u7
        backport_cves = ys.check_cve("OpenSSH_7.4p1-10+deb9u7", "SSH")
        self.assertTrue(len(backport_cves) > 0)
        self.assertTrue(backport_cves[0]["is_backport"])
        self.assertLess(backport_cves[0]["confidence"], 0.5)
        self.assertIn("backport", backport_cves[0]["description"].lower())


# ═══════════════════════════════════════════════════════════════════
#  Bug 6: SMB check must not claim verification
# ═══════════════════════════════════════════════════════════════════

class TestSMBVerification(unittest.TestCase):

    def _serve_once(self, reply):
        """Start a one-shot TCP server on localhost that answers with `reply`."""
        port = _free_port()
        ready = threading.Event()

        async def handle(reader, writer):
            await reader.read(1024)
            writer.write(reply)
            await writer.drain()
            writer.close()

        async def main():
            server = await asyncio.start_server(handle, "127.0.0.1", port)
            ready.set()
            async with server:
                await asyncio.sleep(3)

        t = threading.Thread(target=lambda: asyncio.run(main()), daemon=True)
        t.start()
        ready.wait(2)
        time.sleep(0.1)
        return port

    def test_smbv1_offered_is_possible_not_verified(self):
        port = self._serve_once(b"\x00\x00\x00\x20" + b"NT LM 0.12" + b"\x00" * 10)
        res = _run(ys.verify_smb_eternalblue("127.0.0.1", port, 2.0))
        self.assertFalse(res.verified)
        self.assertEqual(res.exploitability, "POSSIBLE")
        self.assertIn("not tested", res.evidence)

    def test_no_smbv1_is_not_verified(self):
        port = self._serve_once(b"\x00\x00\x00\x04junk")
        res = _run(ys.verify_smb_eternalblue("127.0.0.1", port, 2.0))
        self.assertFalse(res.verified)


# ═══════════════════════════════════════════════════════════════════
#  Bug 7: attack paths need evidence before they are CONFIRMED
# ═══════════════════════════════════════════════════════════════════

class TestAttackPathEvidence(unittest.TestCase):

    def test_open_port_alone_is_potential(self):
        paths, _ = ys.analyze_attack_paths([ys.PortResult(port=6379, service="Redis")])
        self.assertTrue(paths)
        self.assertEqual(paths[0]["status"], "POTENTIAL")
        self.assertFalse(paths[0]["verified"])

    def test_passing_verification_is_confirmed(self):
        vr = ys.VerificationResult(vulnerability="Redis", verified=True, confidence=0.95,
                                   evidence="INFO succeeded without auth", exploitability="CONFIRMED",
                                   safe_test=True)
        paths, _ = ys.analyze_attack_paths([ys.PortResult(port=6379, service="Redis")],
                                           verifications={6379: vr})
        self.assertEqual(paths[0]["status"], "CONFIRMED")
        self.assertIn("INFO succeeded", paths[0]["evidence"])

    def test_failed_verification_stays_potential(self):
        vr = ys.VerificationResult(vulnerability="Redis", verified=False, confidence=0.1,
                                   evidence="auth required", exploitability="UNLIKELY", safe_test=True)
        paths, _ = ys.analyze_attack_paths([ys.PortResult(port=6379, service="Redis")],
                                           verifications={6379: vr})
        self.assertEqual(paths[0]["status"], "POTENTIAL")


# ═══════════════════════════════════════════════════════════════════
#  Bug 8: scope gate checks every host, enforces the allowlist, fails closed
# ═══════════════════════════════════════════════════════════════════

class TestScopeGate(unittest.TestCase):

    def _quiet(self):
        return contextlib.redirect_stdout(io.StringIO())

    def test_private_targets_pass_without_prompt(self):
        hosts = ["10.1.2.3", "192.168.1.1"]
        with mock.patch("builtins.input", side_effect=AssertionError("must not prompt")), self._quiet():
            self.assertTrue(ys.check_scope("10.0.0.0/30", hosts=hosts))

    def test_public_host_later_in_list_is_detected(self):
        # The old check sampled the first 5 hosts only.
        hosts = [f"10.0.0.{i}" for i in range(1, 20)] + ["8.8.8.8"]
        with mock.patch("builtins.input", return_value="n"), self._quiet():
            self.assertFalse(ys.check_scope("mixed", hosts=hosts))

    def test_public_host_with_authorize_passes(self):
        with self._quiet():
            self.assertTrue(ys.check_scope("8.8.8.8", authorized=True, hosts=["8.8.8.8"]))

    def test_allowlist_blocks_hosts_outside_scope(self):
        nets = [ipaddress.ip_network("10.0.0.0/24")]
        with self._quiet():
            self.assertFalse(ys.check_scope("10.9.9.9", hosts=["10.9.9.9"], allow_networks=nets))
            self.assertTrue(ys.check_scope("10.0.0.5", hosts=["10.0.0.5"], allow_networks=nets))

    def test_fails_closed_on_error(self):
        with mock.patch("builtins.input", side_effect=RuntimeError("boom")), self._quiet():
            self.assertFalse(ys.check_scope("8.8.8.8", hosts=["8.8.8.8"]))

    def test_no_hosts_aborts(self):
        with self._quiet():
            self.assertFalse(ys.check_scope("nothing", hosts=[]))

    def test_cloud_metadata_ssrf_blocked(self):
        with self._quiet():
            # Even if authorized=True, cloud metadata endpoints must always fail closed
            self.assertFalse(ys.check_scope("169.254.169.254", authorized=True, hosts=["169.254.169.254"]))
            self.assertTrue(ys.is_cloud_metadata_ip("169.254.169.254"))
            self.assertTrue(ys.is_cloud_metadata_ip("fd00:ec2::254"))
            self.assertFalse(ys.is_cloud_metadata_ip("192.168.1.1"))


# ═══════════════════════════════════════════════════════════════════
#  Bug 9: HTML report escapes remote-controlled data
# ═══════════════════════════════════════════════════════════════════

class TestHTMLEscaping(unittest.TestCase):

    def test_banner_and_server_are_escaped(self):
        payload = "<script>alert(1)</script>"
        data = {
            "target": "10.0.0.5", "scan_time": "now", "duration_seconds": 1, "scan_type": "connect",
            "hosts_alive": 1, "hosts_with_ports": 1, "total_open_ports": 1,
            "results": {"10.0.0.5": {
                "mac": "", "risk_score": 10, "risk_level": "LOW",
                "ports": [{
                    "port": 80, "protocol": "tcp", "state": "open", "service": "HTTP",
                    "version": payload, "os_hint": "",
                    "deep": {"server": "<img src=x onerror=alert(2)>"},
                    "risk_level": "LOW", "cves": [{"cve": "X", "cvss_score": 1, "description": payload}],
                    "vulns": [],
                }],
            }},
        }
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "r.html")
            ys.export_html(data, out)
            with open(out, encoding="utf-8") as fh:
                html_text = fh.read()
        self.assertNotIn("<script>alert(1)", html_text)
        self.assertNotIn("<img src=x", html_text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_text)


# ═══════════════════════════════════════════════════════════════════
#  Bug 10: IPv6 (connect scan and the TCP connect path)
# ═══════════════════════════════════════════════════════════════════

@unittest.skipUnless(socket.has_ipv6, "IPv6 not available")
class TestIPv6(unittest.TestCase):

    def test_connect_scan_ipv6_open_and_closed(self):
        try:
            with listener("::1", socket.AF_INET6) as port:
                self.assertEqual(_run(ys.scan_connect("::1", port, 1.0))[0], ys.PortState.OPEN)
                self.assertEqual(_run(ys.scan_connect("::1", _free_port(socket.AF_INET6, "::1"), 1.0))[0],
                                 ys.PortState.CLOSED)
        except OSError as e:
            self.skipTest(f"IPv6 loopback not usable: {e}")

    def test_local_ip_follows_destination_family(self):
        self.assertEqual(ys.get_local_ip("::1"), "::1")
        self.assertEqual(ys.get_local_ip("127.0.0.1"), "127.0.0.1")


# ═══════════════════════════════════════════════════════════════════
#  Bugs 1 and 2: raw-socket scans (need root; skipped otherwise)
# ═══════════════════════════════════════════════════════════════════

RAW_OK = ys.IS_ROOT and hasattr(socket, "SOCK_RAW")


@unittest.skipUnless(RAW_OK, "raw sockets need root")
class TestRawScansOnLoopback(unittest.TestCase):

    def test_syn_open_and_closed(self):
        # Bug 1: a SYN scan used to read its own outgoing SYN and report FILTERED
        with listener() as port:
            closed = _free_port()
            self.assertEqual(_run(ys.scan_syn("127.0.0.1", port, 1.0, src_ip="127.0.0.1"))[0],
                             ys.PortState.OPEN)
            self.assertEqual(_run(ys.scan_syn("127.0.0.1", closed, 1.0, src_ip="127.0.0.1"))[0],
                             ys.PortState.CLOSED)

    def test_ack_is_unfiltered_for_open_and_closed(self):
        with listener() as port:
            closed = _free_port()
            self.assertEqual(_run(ys.scan_ack("127.0.0.1", port, 1.0, src_ip="127.0.0.1"))[0],
                             ys.PortState.UNFILTERED)
            self.assertEqual(_run(ys.scan_ack("127.0.0.1", closed, 1.0, src_ip="127.0.0.1"))[0],
                             ys.PortState.UNFILTERED)

    def test_fin_null_xmas_closed_gives_rst(self):
        with listener() as port:
            closed = _free_port()
            for fn in (ys.scan_fin, ys.scan_null, ys.scan_xmas):
                self.assertEqual(_run(fn("127.0.0.1", closed, 1.0, src_ip="127.0.0.1"))[0],
                                 ys.PortState.CLOSED, fn.__name__)
                # Open ports stay silent on Linux, so the result is open|filtered
                self.assertEqual(_run(fn("127.0.0.1", port, 1.0, src_ip="127.0.0.1"))[0],
                                 ys.PortState.OPEN_FILTERED, fn.__name__)

    def test_concurrent_syn_probes_do_not_block_event_loop(self):
        # Bug 2: blocking recvfrom used to stall the loop for the whole timeout.
        if not shutil.which("iptables"):
            self.skipTest("iptables not available to create a silent (filtered) port")
        port = 39999
        rule = ["-p", "tcp", "--dport", str(port), "-j", "DROP"]
        subprocess.run(["iptables", "-A", "INPUT", *rule], check=True)
        try:
            async def scenario():
                gaps = []
                last = [time.monotonic()]
                stop = asyncio.Event()

                async def heartbeat():
                    while not stop.is_set():
                        now = time.monotonic()
                        gaps.append(now - last[0])
                        last[0] = now
                        await asyncio.sleep(0.02)

                hb = asyncio.create_task(heartbeat())
                await asyncio.sleep(0.1)
                start = time.monotonic()
                results = await asyncio.gather(*[
                    ys.scan_syn("127.0.0.1", port, 1.0, src_ip="127.0.0.1") for _ in range(3)])
                elapsed = time.monotonic() - start
                stop.set()
                await hb
                return results, elapsed, max(gaps)

            results, elapsed, max_gap = _run(scenario())
            self.assertEqual([r[0] for r in results], [ys.PortState.FILTERED] * 3)
            self.assertLess(elapsed, 2.0, "three 1s probes should run in parallel")
            self.assertLess(max_gap, 0.5, "event loop should keep ticking during probes")
        finally:
            subprocess.run(["iptables", "-D", "INPUT", *rule], check=False)


# ═══════════════════════════════════════════════════════════════════
#  Smoke test: connect scan through the public API
# ═══════════════════════════════════════════════════════════════════

class TestConnectScan(unittest.TestCase):

    def test_open_and_closed_ipv4(self):
        with listener() as port:
            self.assertEqual(_run(ys.scan_connect("127.0.0.1", port, 1.0))[0], ys.PortState.OPEN)
            self.assertEqual(_run(ys.scan_connect("127.0.0.1", _free_port(), 1.0))[0], ys.PortState.CLOSED)


class TestCSVHardening(unittest.TestCase):
    """Test CSV formula injection / DDE prevention."""

    def test_sanitize_csv_cell(self):
        self.assertEqual(ys.sanitize_csv_cell("normal"), "normal")
        self.assertEqual(ys.sanitize_csv_cell("=1+1"), "'=1+1")
        self.assertEqual(ys.sanitize_csv_cell("+cmd|' /C calc'!A0"), "'+cmd|' /C calc'!A0")
        self.assertEqual(ys.sanitize_csv_cell("-2+3"), "'-2+3")
        self.assertEqual(ys.sanitize_csv_cell("@SUM(1,2)"), "'@SUM(1,2)")
        self.assertEqual(ys.sanitize_csv_cell("\talert"), "'\talert")
        self.assertEqual(ys.sanitize_csv_cell(None), "")

    def test_export_csv_escapes_malicious_banners(self):
        with tempfile.NamedTemporaryFile("r+", delete=False) as tf:
            temp_path = tf.name
        try:
            fake_data = {
                "results": {
                    "127.0.0.1": {
                        "mac": "=cmd",
                        "ports": [
                            {
                                "port": 80,
                                "protocol": "tcp",
                                "state": "open",
                                "service": "+malicious_service",
                                "version": "@v1.0",
                                "cves": [],
                                "vulns": [{"title": "-vuln_trigger"}],
                            }
                        ]
                    }
                }
            }
            ys.export_csv(fake_data, temp_path)
            with open(temp_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("'+malicious_service", content)
            self.assertIn("'@v1.0", content)
            self.assertIn("'-vuln_trigger", content)
            self.assertIn("'=cmd", content)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


if __name__ == "__main__":
    unittest.main()
