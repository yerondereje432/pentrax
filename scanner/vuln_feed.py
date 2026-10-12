"""Live & Offline Vulnerability Catalog Feed for PENTRAX (NVD 2.0 + EPSS Sync)."""
import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger("pentrax.vuln_feed")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"

# High-impact curated CVE baseline for instant offline / air-gapped matching
HIGH_IMPACT_BASELINE_CVES = [
    {
        "cve_id": "CVE-2021-44228",
        "description": "Apache Log4j2 JNDI remote code execution (Log4Shell).",
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "epss_score": 0.975,
        "cpe_uris": ["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"],
        "published": "2021-12-10T10:15:00Z",
    },
    {
        "cve_id": "CVE-2017-0144",
        "description": "Microsoft SMBv1 Remote Code Execution (EternalBlue / MS17-010).",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "epss_score": 0.974,
        "cpe_uris": ["cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"],
        "published": "2017-03-16T00:00:00Z",
    },
    {
        "cve_id": "CVE-2014-0160",
        "description": "OpenSSL TLS heartbeat read overrun information disclosure (Heartbleed).",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "epss_score": 0.952,
        "cpe_uris": ["cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*"],
        "published": "2014-04-07T22:55:00Z",
    },
    {
        "cve_id": "CVE-2021-41773",
        "description": "Apache HTTP Server 2.4.49 path traversal and remote code execution.",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "epss_score": 0.971,
        "cpe_uris": ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
        "published": "2021-10-05T11:15:00Z",
    },
    {
        "cve_id": "CVE-2022-22965",
        "description": "Spring Framework Remote Code Execution via Data Binding (Spring4Shell).",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "epss_score": 0.958,
        "cpe_uris": ["cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*"],
        "published": "2022-04-01T23:15:00Z",
    },
    {
        "cve_id": "CVE-2023-38606",
        "description": "Apple WebKit / Kernel privilege escalation memory corruption.",
        "severity": "HIGH",
        "cvss_score": 7.8,
        "epss_score": 0.812,
        "cpe_uris": ["cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*"],
        "published": "2023-07-24T18:15:00Z",
    },
    {
        "cve_id": "CVE-2024-3094",
        "description": "Malicious code injection in XZ Utils / liblzma leading to SSH authentication bypass.",
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "epss_score": 0.963,
        "cpe_uris": ["cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*", "cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*"],
        "published": "2024-03-29T19:15:00Z",
    },
    {
        "cve_id": "CVE-2023-44487",
        "description": "HTTP/2 Rapid Reset distributed denial of service vulnerability.",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "epss_score": 0.934,
        "cpe_uris": ["cpe:2.3:a:*:http2:*:*:*:*:*:*:*:*"],
        "published": "2023-10-10T14:15:00Z",
    },
]


class CVEFeedUpdater:
    """Manages syncing and querying of CVE vulnerability intelligence."""

    def __init__(self, db_manager=None, nvd_api_key: Optional[str] = None):
        if db_manager is None:
            from web.db import db_manager as default_db
            self.db = default_db
        else:
            self.db = db_manager
        self.nvd_api_key = nvd_api_key or os.getenv("NVD_API_KEY")
        self.seed_baseline_catalog()

    def seed_baseline_catalog(self):
        """Seeds curated critical baseline CVEs into SQLite if table is currently empty."""
        try:
            with self.db.get_connection() as conn:
                row = conn.execute("SELECT COUNT(*) FROM cve_catalog").fetchone()
                count = row[0] if row else 0
                if count == 0:
                    for item in HIGH_IMPACT_BASELINE_CVES:
                        conn.execute("""
                        INSERT OR REPLACE INTO cve_catalog 
                        (cve_id, description, severity, cvss_score, epss_score, cpe_uris, published, modified)
                        VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
                        """, (
                            item["cve_id"],
                            item["description"],
                            item["severity"],
                            item["cvss_score"],
                            item["epss_score"],
                            json.dumps(item["cpe_uris"]),
                            item["published"],
                        ))
                    conn.commit()
        except Exception as e:
            logger.warning("Could not seed baseline CVEs: %s", e)

    def sync(self, days_back: int = 7, limit: int = 100) -> int:
        """Fetches newly published or modified CVEs from NVD API 2.0 and EPSS."""
        start_date = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00.000")
        end_date = datetime.utcnow().strftime("%Y-%m-%dT23:59:59.999")

        query_params = {
            "pubStartDate": start_date,
            "pubEndDate": end_date,
            "resultsPerPage": str(min(limit, 2000)),
        }
        url = f"{NVD_API_BASE}?{urllib.parse.urlencode(query_params)}"

        headers = {
            "User-Agent": "PENTRAX-Vulnerability-Engine/10.0",
            "Accept": "application/json",
        }
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        count_stored = 0
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=12.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read())
                    vulns = data.get("vulnerabilities", [])
                    cve_ids_to_epss: List[str] = []

                    with self.db.get_connection() as conn:
                        for entry in vulns:
                            cve_obj = entry.get("cve", {})
                            cve_id = cve_obj.get("id")
                            if not cve_id:
                                continue

                            # Descriptions
                            descs = cve_obj.get("descriptions", [])
                            en_desc = next((d.get("value") for d in descs if d.get("lang") == "en"), "")

                            # CVSS metrics
                            metrics = cve_obj.get("metrics", {})
                            cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                            cvss_v30 = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                            cvss_data = cvss_v31 or cvss_v30
                            cvss_score = cvss_data.get("baseScore", 0.0)
                            severity = cvss_data.get("baseSeverity", "MEDIUM").upper()

                            # CPEs
                            cpes = []
                            for config in cve_obj.get("configurations", []):
                                for node in config.get("nodes", []):
                                    for cpe_match in node.get("cpeMatch", []):
                                        criteria = cpe_match.get("criteria")
                                        if criteria:
                                            cpes.append(criteria)

                            published = cve_obj.get("published", "")

                            conn.execute("""
                            INSERT OR REPLACE INTO cve_catalog
                            (cve_id, description, severity, cvss_score, epss_score, cpe_uris, published, modified)
                            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
                            """, (
                                cve_id,
                                en_desc,
                                severity,
                                float(cvss_score),
                                0.0,
                                json.dumps(cpes),
                                published,
                            ))
                            count_stored += 1
                            cve_ids_to_epss.append(cve_id)

                        conn.commit()

                    # Query EPSS scores for batch
                    if cve_ids_to_epss:
                        self._sync_epss_scores(cve_ids_to_epss[:100])

        except Exception as e:
            logger.warning("NVD sync warning (offline or rate limited): %s", e)

        return count_stored

    def _sync_epss_scores(self, cve_ids: List[str]):
        """Queries FIRST EPSS API for real-world exploit probability scores."""
        try:
            ids_param = ",".join(cve_ids)
            url = f"{EPSS_API_BASE}?cve={urllib.parse.quote(ids_param)}"
            req = urllib.request.Request(url, headers={"User-Agent": "PENTRAX-Vulnerability-Engine/10.0"})
            with urllib.request.urlopen(req, timeout=6.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read()).get("data", [])
                    with self.db.get_connection() as conn:
                        for row in data:
                            cid = row.get("cve")
                            epss = float(row.get("epss", 0.0))
                            if cid and epss:
                                conn.execute("UPDATE cve_catalog SET epss_score = ? WHERE cve_id = ?", (epss, cid))
                        conn.commit()
        except Exception:
            pass

    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves single CVE record from SQLite catalog."""
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT * FROM cve_catalog WHERE cve_id = ?", (cve_id,)).fetchone()
            if row:
                res = dict(row)
                if isinstance(res.get("cpe_uris"), str):
                    try:
                        res["cpe_uris"] = json.loads(res["cpe_uris"])
                    except Exception:
                        res["cpe_uris"] = []
                return res
        return None

    def match_service(self, product: str, version: Optional[str] = None) -> List[Dict[str, Any]]:
        """Matches a discovered service/product against the vulnerability database."""
        product_clean = product.lower().strip()
        results = []
        with self.db.get_connection() as conn:
            # Match either in description or in CPEs
            cursor = conn.execute("""
            SELECT * FROM cve_catalog 
            WHERE lower(description) LIKE ? OR lower(cpe_uris) LIKE ?
            ORDER BY cvss_score DESC LIMIT 20
            """, (f"%{product_clean}%", f"%{product_clean}%"))
            for row in cursor.fetchall():
                d = dict(row)
                if isinstance(d.get("cpe_uris"), str):
                    try:
                        d["cpe_uris"] = json.loads(d["cpe_uris"])
                    except Exception:
                        d["cpe_uris"] = []
                results.append(d)
        return results

    def get_stats(self) -> Dict[str, Any]:
        """Returns statistics of the local CVE catalog."""
        with self.db.get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM cve_catalog").fetchone()[0]
            critical = conn.execute("SELECT COUNT(*) FROM cve_catalog WHERE severity = 'CRITICAL'").fetchone()[0]
            high = conn.execute("SELECT COUNT(*) FROM cve_catalog WHERE severity = 'HIGH'").fetchone()[0]
            last_sync = conn.execute("SELECT MAX(modified) FROM cve_catalog").fetchone()[0]
            return {
                "total_cves": total,
                "critical_cves": critical,
                "high_cves": high,
                "last_sync": last_sync or "Never",
            }

