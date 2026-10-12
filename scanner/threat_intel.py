"""Threat Intelligence Correlation module for PENTRAX (Tor Exit Nodes & IP Reputation)."""
import asyncio
import ipaddress
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("pentrax.threat_intel")

TOR_BULK_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


@dataclass
class ThreatProfile:
    ip: str
    is_tor_exit: bool = False
    is_bogon_or_private: bool = False
    abuseipdb_score: int = 0
    threat_level: str = "CLEAN"  # CLEAN | SUSPICIOUS | MALICIOUS | BOGON
    listed_feeds: List[str] = field(default_factory=list)
    country_code: Optional[str] = None
    isp: Optional[str] = None
    total_reports: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "is_tor_exit": self.is_tor_exit,
            "is_bogon_or_private": self.is_bogon_or_private,
            "abuseipdb_score": self.abuseipdb_score,
            "threat_level": self.threat_level,
            "listed_feeds": self.listed_feeds,
            "country_code": self.country_code,
            "isp": self.isp,
            "total_reports": self.total_reports,
        }


class ThreatIntel:
    """Correlates target IP addresses against open threat intelligence and anonymity networks."""

    def __init__(self, abuseipdb_key: Optional[str] = None):
        self.abuseipdb_key = abuseipdb_key or os.getenv("ABUSEIPDB_API_KEY")
        self._tor_exit_nodes: Set[str] = set()
        self._last_tor_refresh: float = 0.0
        self._cache_duration_seconds: float = 3600.0  # 1 hour

    async def check(self, ip_str: str) -> ThreatProfile:
        ip_str = ip_str.strip()
        profile = ThreatProfile(ip=ip_str)

        # Check bogon / private / loopback
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                profile.is_bogon_or_private = True
                profile.threat_level = "BOGON"
                profile.listed_feeds.append("RFC1918 / Reserved Space")
                return profile
        except ValueError:
            # Domain provided instead of raw IP
            pass

        tasks = [
            self._check_tor(ip_str, profile),
        ]
        if self.abuseipdb_key:
            tasks.append(self._check_abuseipdb(ip_str, profile))

        await asyncio.gather(*tasks, return_exceptions=True)

        # Final threat calculation
        if profile.is_tor_exit:
            profile.listed_feeds.append("Tor Onion Router Bulk Exit List")
            if profile.threat_level == "CLEAN":
                profile.threat_level = "SUSPICIOUS"

        if profile.abuseipdb_score > 75:
            profile.threat_level = "MALICIOUS"
        elif profile.abuseipdb_score > 25 and profile.threat_level == "CLEAN":
            profile.threat_level = "SUSPICIOUS"

        return profile

    async def _check_tor(self, ip_str: str, profile: ThreatProfile):
        loop = asyncio.get_running_loop()
        now = time.time()

        if now - self._last_tor_refresh > self._cache_duration_seconds or not self._tor_exit_nodes:
            def _fetch_tor():
                try:
                    req = urllib.request.Request(
                        TOR_BULK_EXIT_LIST_URL,
                        headers={"User-Agent": "PENTRAX-ThreatIntel/10.0"},
                    )
                    with urllib.request.urlopen(req, timeout=5.0) as resp:
                        if resp.status == 200:
                            content = resp.read().decode("utf-8", errors="ignore")
                            ips = {line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")}
                            return ips
                except Exception as e:
                    logger.debug("Tor exit list fetch timed out or offline: %s", e)
                return None

            fetched = await loop.run_in_executor(None, _fetch_tor)
            if fetched is not None:
                self._tor_exit_nodes = fetched
                self._last_tor_refresh = now

        if ip_str in self._tor_exit_nodes:
            profile.is_tor_exit = True

    async def _check_abuseipdb(self, ip_str: str, profile: ThreatProfile):
        if not self.abuseipdb_key:
            return

        loop = asyncio.get_running_loop()
        url = f"{ABUSEIPDB_CHECK_URL}?ipAddress={urllib.parse.quote(ip_str)}&maxAgeInDays=90"

        def _fetch():
            import json
            req = urllib.request.Request(
                url,
                headers={
                    "Key": self.abuseipdb_key,
                    "Accept": "application/json",
                    "User-Agent": "PENTRAX-ThreatIntel/10.0",
                },
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status == 200:
                    return json.loads(resp.read())
            return None

        try:
            res = await loop.run_in_executor(None, _fetch)
            if res and "data" in res:
                data = res["data"]
                profile.abuseipdb_score = int(data.get("abuseConfidenceScore", 0))
                profile.total_reports = int(data.get("totalReports", 0))
                profile.country_code = data.get("countryCode")
                profile.isp = data.get("isp")
                if profile.abuseipdb_score > 0:
                    profile.listed_feeds.append(f"AbuseIPDB (Confidence: {profile.abuseipdb_score}%)")
        except Exception:
            pass


threat_intel = ThreatIntel()

