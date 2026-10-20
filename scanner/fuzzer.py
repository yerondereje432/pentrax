"""Safe Active Parameter Fuzzing Engine for PENTRAX.

Audits web query parameters and form fields for Reflected Cross-Site Scripting (XSS)
and Error-Based SQL Injection using non-destructive canary and syntax error oracles.
"""

import asyncio
import html
import logging
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger("pentrax.fuzzer")

# Known database error regex signatures
SQL_ERROR_PATTERNS = [
    # MySQL
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysql_", re.I),
    re.compile(r"valid MySQL result", re.I),
    # PostgreSQL
    re.compile(r"syntax error at or near", re.I),
    re.compile(r"pg_query\(\): query failed", re.I),
    re.compile(r"unterminated quoted string at or near", re.I),
    # Microsoft SQL Server
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"microsoft ole db provider for sql server", re.I),
    re.compile(r"driver\]\[sql server\]", re.I),
    # SQLite
    re.compile(r"sqlite3::sqlexception", re.I),
    re.compile(r"unrecognized token:", re.I),
    re.compile(r"near \".*\": syntax error", re.I),
    # Oracle
    re.compile(r"ora-01756", re.I),
    re.compile(r"ora-00933", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
]

XSS_CANARY_TAG = "<pentrax_xss_probe>"
XSS_CANARY_FULL = f"px1337{XSS_CANARY_TAG}"


class ParameterFuzzer:
    """Non-destructive fuzzer for query parameters and form endpoints."""

    def __init__(
        self,
        timeout: float = 3.0,
        cookie: Optional[str] = None,
        custom_header: Optional[str] = None,
    ):
        self.timeout = timeout
        self.cookie = cookie
        self.custom_header = custom_header

    async def fuzz_endpoints(
        self,
        parameterized_endpoints: List[Dict[str, Any]],
        forms: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Audits all discovered parameterized endpoints and forms."""
        findings = []

        headers = {
            "User-Agent": "PENTRAX-Fuzzer/8.0 (Authorized Security Audit; +https://pentrax.sec)",
            "Accept": "*/*",
        }
        if self.cookie:
            headers["Cookie"] = self.cookie
        if self.custom_header:
            if ":" in self.custom_header:
                hk, hv = self.custom_header.split(":", 1)
                headers[hk.strip()] = hv.strip()
            else:
                headers["Authorization"] = self.custom_header

        # 1. Fuzz GET Query Parameters
        for endpoint in parameterized_endpoints:
            raw_url = endpoint.get("url")
            params = endpoint.get("params", [])
            if not raw_url or not params:
                continue

            parsed = urllib.parse.urlparse(raw_url)
            qs = urllib.parse.parse_qs(parsed.query)

            for param in params:
                # A. Reflected XSS Canary Check
                xss_finding = await self._check_reflected_xss(parsed, qs, param, headers)
                if xss_finding:
                    findings.append(xss_finding)

                # B. Error-Based SQLi Syntax Check
                sqli_finding = await self._check_error_sqli(parsed, qs, param, headers)
                if sqli_finding:
                    findings.append(sqli_finding)

        # 2. Fuzz Form Action Endpoints (if GET forms with named inputs)
        if forms:
            for form in forms:
                action = form.get("action")
                method = form.get("method", "GET").upper()
                inputs = form.get("inputs", [])
                if method != "GET" or not action or not inputs:
                    continue

                input_names = [i["name"] for i in inputs if i.get("name")]
                if not input_names:
                    continue

                parsed = urllib.parse.urlparse(action)
                base_qs = {i["name"]: [i.get("value", "test")] for i in inputs if i.get("name")}

                for param in input_names:
                    xss_finding = await self._check_reflected_xss(parsed, base_qs, param, headers)
                    if xss_finding:
                        findings.append(xss_finding)

                    sqli_finding = await self._check_error_sqli(parsed, base_qs, param, headers)
                    if sqli_finding:
                        findings.append(sqli_finding)

        return findings

    async def _check_reflected_xss(
        self,
        parsed_url: urllib.parse.ParseResult,
        base_qs: Dict[str, List[str]],
        target_param: str,
        headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """Tests whether an unescaped canary tag reflects in the response."""
        fuzzed_qs = {k: list(v) for k, v in base_qs.items()}
        fuzzed_qs[target_param] = [XSS_CANARY_FULL]
        new_query = urllib.parse.urlencode(fuzzed_qs, doseq=True)
        probe_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))

        body = await self._http_get(probe_url, headers)
        if not body:
            return None

        # Confirm unescaped reflection
        if XSS_CANARY_TAG in body and html.escape(XSS_CANARY_TAG) not in body:
            return {
                "id": "DAST-REFLECTED-XSS",
                "title": f"Reflected Cross-Site Scripting (XSS) in Parameter '{target_param}'",
                "severity": "HIGH",
                "category": "DAST: XSS",
                "url": probe_url,
                "parameter": target_param,
                "evidence": f"Parameter '{target_param}' reflected raw canary tag: {XSS_CANARY_FULL}",
                "remediation": f"Contextually HTML-encode user input for parameter '{target_param}' and implement a strong Content-Security-Policy.",
                "remediation_sla": "14 Days",
            }
        return None

    async def _check_error_sqli(
        self,
        parsed_url: urllib.parse.ParseResult,
        base_qs: Dict[str, List[str]],
        target_param: str,
        headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """Tests whether single/double quotes elicit explicit database syntax errors."""
        for quote in ("'", "\""):
            fuzzed_qs = {k: list(v) for k, v in base_qs.items()}
            current_val = base_qs.get(target_param, ["1"])[0]
            fuzzed_qs[target_param] = [f"{current_val}{quote}"]
            new_query = urllib.parse.urlencode(fuzzed_qs, doseq=True)
            probe_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))

            body = await self._http_get(probe_url, headers)
            if not body:
                continue

            for pattern in SQL_ERROR_PATTERNS:
                match = pattern.search(body)
                if match:
                    error_snippet = match.group(0)
                    return {
                        "id": "DAST-SQLI-ERROR",
                        "title": f"Error-Based SQL Injection in Parameter '{target_param}'",
                        "severity": "CRITICAL",
                        "category": "DAST: INJECTION",
                        "url": probe_url,
                        "parameter": target_param,
                        "evidence": f"Injected quote '{quote}' triggered database syntax error: '{error_snippet}'",
                        "remediation": f"Use parameterized prepared statements (ORMs or parameterized queries) for parameter '{target_param}'. Never concatenate unsanitized user input into SQL commands.",
                        "remediation_sla": "48 Hours",
                    }
        return None

    async def _http_get(self, url: str, headers: Dict[str, str]) -> Optional[str]:
        """Performs non-blocking HTTP GET."""
        loop = asyncio.get_event_loop()

        def _get():
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:
                    return r.read(65536).decode("utf-8", errors="ignore")
            except urllib.error.HTTPError as e:
                # Error-based SQLi often returns HTTP 500 while leaking database errors!
                if hasattr(e, "read"):
                    return e.read(65536).decode("utf-8", errors="ignore")
                return None
            except Exception:
                return None

        return await loop.run_in_executor(None, _get)

