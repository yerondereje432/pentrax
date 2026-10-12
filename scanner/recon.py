"""Passive OSINT reconnaissance module for PENTRAX — zero direct packets to target."""
import asyncio
import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set


@dataclass
class ReconResult:
    domain: str
    target_ip: Optional[str] = None
    subdomains: List[str] = field(default_factory=list)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    whois_info: Dict[str, Any] = field(default_factory=dict)
    cert_sans: List[str] = field(default_factory=list)
    shodan_info: Optional[Dict[str, Any]] = None
    virustotal_info: Optional[Dict[str, Any]] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "target_ip": self.target_ip,
            "subdomains": self.subdomains,
            "dns_records": self.dns_records,
            "whois_info": self.whois_info,
            "cert_sans": self.cert_sans,
            "shodan_info": self.shodan_info,
            "virustotal_info": self.virustotal_info,
            "timestamp": self.timestamp,
        }


class PassiveRecon:
    """Performs non-intrusive, passive OSINT reconnaissance on domains and IP addresses."""

    def __init__(self, shodan_key: Optional[str] = None, vt_key: Optional[str] = None):
        self.shodan_key = shodan_key or os.getenv("SHODAN_API_KEY")
        self.vt_key = vt_key or os.getenv("VT_API_KEY")

    async def run(self, domain_or_ip: str) -> ReconResult:
        domain_or_ip = domain_or_ip.strip().lower()
        # Strip protocols and paths if accidentally provided
        if "://" in domain_or_ip:
            domain_or_ip = urllib.parse.urlparse(domain_or_ip).netloc or domain_or_ip
        if ":" in domain_or_ip and not domain_or_ip.count(":") > 1:  # strip port if host:port
            domain_or_ip = domain_or_ip.split(":")[0]

        result = ReconResult(domain=domain_or_ip)

        tasks = [
            self._dns_enum(domain_or_ip, result),
            self._cert_transparency(domain_or_ip, result),
            self._rdap_lookup(domain_or_ip, result),
        ]

        if self.shodan_key:
            tasks.append(self._shodan_lookup(domain_or_ip, result))
        if self.vt_key:
            tasks.append(self._virustotal_lookup(domain_or_ip, result))

        await asyncio.gather(*tasks, return_exceptions=True)

        # Deduplicate and sort discovered subdomains and cert SANs
        all_subs = set(result.subdomains) | set(result.cert_sans)
        # Filter valid domain names
        valid_subs = sorted({s.lower() for s in all_subs if s and not s.startswith("*.") and domain_or_ip in s})
        result.subdomains = valid_subs

        return result

    async def _dns_enum(self, domain: str, result: ReconResult):
        """Resolves basic DNS addresses and IP information using stdlib getaddrinfo."""
        loop = asyncio.get_running_loop()

        def _resolve():
            records: Dict[str, List[str]] = {}
            # Resolve A / IPv4
            try:
                ip_list = socket.gethostbyname_ex(domain)[2]
                records["A"] = sorted(list(set(ip_list)))
                if records["A"]:
                    result.target_ip = records["A"][0]
            except Exception:
                records["A"] = []

            # Resolve IPv6 if available
            try:
                addr_info = socket.getaddrinfo(domain, None, socket.AF_INET6)
                records["AAAA"] = sorted(list({info[4][0] for info in addr_info}))
            except Exception:
                records["AAAA"] = []

            # Canonical name
            try:
                cname = socket.getfqdn(domain)
                if cname and cname != domain:
                    records["CNAME"] = [cname]
            except Exception:
                pass

            return records

        try:
            dns_recs = await loop.run_in_executor(None, _resolve)
            result.dns_records.update(dns_recs)
        except Exception:
            pass

    async def _cert_transparency(self, domain: str, result: ReconResult):
        """Queries crt.sh Certificate Transparency logs for subdomains and SANs."""
        # crt.sh supports wildcard matching
        query_url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
        loop = asyncio.get_running_loop()

        def _fetch():
            req = urllib.request.Request(
                query_url,
                headers={"User-Agent": "PENTRAX-OSINT/10.0 (Security Research Scanner)"},
            )
            with urllib.request.urlopen(req, timeout=7.0) as resp:
                if resp.status == 200:
                    data = resp.read()
                    return json.loads(data)
            return []

        try:
            records = await loop.run_in_executor(None, _fetch)
            sans: Set[str] = set()
            for entry in records:
                name_value = entry.get("name_value", "")
                for sub in name_value.split("\n"):
                    clean = sub.strip().lower()
                    if clean:
                        sans.add(clean)
            result.cert_sans = sorted(list(sans))
        except Exception:
            # Passive OSINT ignores network timeouts from 3rd party services gracefully
            pass

    async def _rdap_lookup(self, domain: str, result: ReconResult):
        """Performs WHOIS/RDAP lookup via standard open RDAP gateway."""
        url = f"https://rdap.org/domain/{urllib.parse.quote(domain)}"
        loop = asyncio.get_running_loop()

        def _fetch():
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "PENTRAX-OSINT/10.0",
                    "Accept": "application/rdap+json, application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status == 200:
                    return json.loads(resp.read())
            return {}

        try:
            data = await loop.run_in_executor(None, _fetch)
            if data:
                whois: Dict[str, Any] = {
                    "handle": data.get("handle"),
                    "name": data.get("ldhName"),
                    "status": data.get("status", []),
                }
                # Extract event dates
                for event in data.get("events", []):
                    action = event.get("eventAction")
                    date = event.get("eventDate")
                    if action and date:
                        whois[f"date_{action}"] = date

                # Extract entities / registrar
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        whois["registrar"] = entity.get("handle") or entity.get("vcardArray", [None, [None, ["fn", {}, "text", "Unknown"]]])[1][0][3]

                result.whois_info = whois
        except Exception:
            pass

    async def _shodan_lookup(self, domain: str, result: ReconResult):
        """Queries Shodan REST API if API key is configured."""
        if not self.shodan_key:
            return
        ip = result.target_ip or domain
        url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}"
        loop = asyncio.get_running_loop()

        def _fetch():
            req = urllib.request.Request(url, headers={"User-Agent": "PENTRAX-OSINT/10.0"})
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status == 200:
                    return json.loads(resp.read())
            return None

        try:
            data = await loop.run_in_executor(None, _fetch)
            if data:
                result.shodan_info = {
                    "os": data.get("os"),
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", []),
                    "hostnames": data.get("hostnames", []),
                    "tags": data.get("tags", []),
                    "isp": data.get("isp"),
                    "asn": data.get("asn"),
                }
        except Exception:
            pass

    async def _virustotal_lookup(self, domain: str, result: ReconResult):
        """Queries VirusTotal v3 domain/ip reports if API key is configured."""
        if not self.vt_key:
            return
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        loop = asyncio.get_running_loop()

        def _fetch():
            req = urllib.request.Request(
                url,
                headers={
                    "x-apikey": self.vt_key,
                    "User-Agent": "PENTRAX-OSINT/10.0",
                },
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status == 200:
                    return json.loads(resp.read())
            return None

        try:
            data = await loop.run_in_executor(None, _fetch)
            if data and "data" in data:
                attrs = data["data"].get("attributes", {})
                last_stats = attrs.get("last_analysis_stats", {})
                result.virustotal_info = {
                    "malicious": last_stats.get("malicious", 0),
                    "suspicious": last_stats.get("suspicious", 0),
                    "harmless": last_stats.get("harmless", 0),
                    "reputation": attrs.get("reputation", 0),
                    "categories": attrs.get("categories", {}),
                }
        except Exception:
            pass

