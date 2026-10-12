"""Shared scope / authorization policy for yerscan.

Both the CLI scope gate and the web dashboard's new-scan form rely on the same idea: a target is
out of scope unless it is private (RFC1918 / loopback / link-local) or the operator has explicitly
authorized it, and everything must fall inside an optional allow-list. Keeping that logic in one
module stops the two front-ends from drifting apart.
"""

import ipaddress
from dataclasses import dataclass, field
from typing import List, Optional


def is_private_ip(ip_str: str) -> bool:
    """True for RFC1918 / loopback / link-local addresses. Unknown strings are treated as public."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _split_targets(spec: str) -> List[str]:
    return [t.strip() for t in spec.replace("\n", ",").split(",") if t.strip()]


def _token_networks(token: str):
    """Yield ip_network objects for a single target token (an IP becomes a /32-/128 host net)."""
    token = token.strip()
    try:
        # Accept CIDR, plain IP, and ranges like 10.0.0.1-10.
        if "-" in token and "/" not in token:
            low, high = token.split("-", 1)
            return [ipaddress.ip_network(f"{low}/{ipaddress.ip_address(low).max_prefixlen}", strict=False)]
        return [ipaddress.ip_network(token, strict=False)]
    except ValueError:
        return []


def in_networks(token: str, allow_networks) -> bool:
    if not allow_networks:
        return True
    for net in _token_networks(token):
        if any(net.subnet_of(allow) for allow in allow_networks):
            return True
    return False


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    public_hosts: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    host_count: int = 0


def evaluate_scope(spec: str, authorized: bool = False,
                   allow_networks=None) -> ScopeDecision:
    """Decide whether the web dashboard may scan `spec`.

    - Tokens that are public (non-private) require `authorized`.
    - When `allow_networks` is given, every token must sit inside one of them.
    - Host count is the number of distinct IPs implied (hosts inside CIDR ranges are not expanded;
      a CIDR counts as one target for the limit check).
    """
    public: List[str] = []
    out_of_scope: List[str] = []
    count = 0
    for token in _split_targets(spec):
        nets = _token_networks(token)
        if not nets:
            return ScopeDecision(False, f"Cannot parse target: {token!r}", token)
        count += 1
        if not is_private_ip(str(nets[0].network_address)):
            public.append(token)
        if not in_networks(token, allow_networks):
            out_of_scope.append(token)

    if out_of_scope:
        return ScopeDecision(
            False,
            f"{len(out_of_scope)} target(s) outside the scope allow-list (e.g. {out_of_scope[0]})",
            public, out_of_scope, count,
        )
    if public and not authorized:
        return ScopeDecision(
            False,
            f"{len(public)} public target(s) need authorization (e.g. {public[0]})",
            public, out_of_scope, count,
        )
    return ScopeDecision(True, "in scope", public, out_of_scope, count)


def load_scope_file(path: str):
    """Read an allow-list file (one CIDR/IP per line, # comments) into a list of networks."""
    networks = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for net in _token_networks(line):
                    networks.append(net)
    except OSError:
        return None
    return networks or None
