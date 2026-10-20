"""YAML Template Vulnerability Probe Engine for PENTRAX.

Allows writing declarative DAST and network vulnerability probes in YAML (Nuclei-style)
without modifying core scanner source code.
"""

import asyncio
import re
import socket
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    import yaml
except ImportError:
    yaml = None


def parse_simple_yaml(text: str) -> Dict[str, Any]:
    """Lightweight fallback YAML parser for environments without PyYAML."""
    data: Dict[str, Any] = {}
    current_key = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            parts = line.split(":", 1)
            k = parts[0].strip()
            v = parts[1].strip()
            if v.startswith("[") and v.endswith("]"):
                items = [i.strip().strip("'\"") for i in v[1:-1].split(",") if i.strip()]
                data[k] = items
            elif v:
                data[k] = v.strip("'\"")
            else:
                current_key = k
                data[k] = []
        elif line.startswith("- ") and current_key:
            data[current_key].append(line[2:].strip().strip("'\""))
    return data


class YAMLTemplateEngine:
    """Discovers, validates, and executes declarative YAML vulnerability checks."""

    def __init__(self, templates_dir: Optional[Path] = None):
        self.templates_dir = templates_dir or (Path(__file__).resolve().parent.parent / "templates")
        self.templates: List[Dict[str, Any]] = []
        self.load_templates()

    def load_templates(self) -> int:
        """Scan directory and load all *.yaml / *.yml templates."""
        self.templates.clear()
        if not self.templates_dir.exists():
            return 0

        for path in self.templates_dir.rglob("*.yaml"):
            try:
                content = path.read_text(encoding="utf-8")
                if yaml:
                    parsed = yaml.safe_load(content)
                else:
                    parsed = parse_simple_yaml(content)
                if isinstance(parsed, dict) and "id" in parsed:
                    parsed["_file"] = str(path)
                    self.templates.append(parsed)
            except Exception:
                pass
        return len(self.templates)

    async def run_http_probes(
        self,
        host: str,
        port: int = 80,
        use_ssl: bool = False,
        timeout: float = 3.0,
        cookie: Optional[str] = None,
        custom_header: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Run all matching HTTP probes against target host and port."""
        findings = []
        scheme = "https" if use_ssl or port in (443, 8443) else "http"
        base_url = f"{scheme}://{host}:{port}"

        extra_headers = {}
        if cookie:
            extra_headers["Cookie"] = cookie
        if custom_header:
            if ":" in custom_header:
                hk, hv = custom_header.split(":", 1)
                extra_headers[hk.strip()] = hv.strip()
            else:
                extra_headers["Authorization"] = custom_header

        for tmpl in self.templates:
            http_config = tmpl.get("http")
            if not http_config:
                continue

            # Support both list of requests or single dict
            probe_list = http_config if isinstance(http_config, list) else [http_config]
            for probe in probe_list:
                paths = probe.get("paths", ["/"])
                if isinstance(paths, str):
                    paths = [paths]
                method = probe.get("method", "GET").upper()
                matchers = probe.get("matchers", [])

                for p in paths:
                    req_url = f"{base_url}{p if p.startswith('/') else '/' + p}"
                    res = await self._execute_http(req_url, method, timeout, extra_headers)
                    if not res:
                        continue

                    if self._eval_matchers(res, matchers):
                        findings.append({
                            "template_id": tmpl.get("id"),
                            "title": tmpl.get("name", tmpl.get("id")),
                            "severity": tmpl.get("severity", "MEDIUM").upper(),
                            "category": tmpl.get("category", "DAST"),
                            "host": host,
                            "port": port,
                            "path": p,
                            "evidence": f"HTTP {res['status']} response at {p} matched template pattern",
                            "remediation": tmpl.get("remediation", "Review and restrict public access to this path."),
                            "remediation_sla": tmpl.get("sla", "14 Days"),
                        })
                        break
        return findings

    async def _execute_http(
        self,
        url: str,
        method: str = "GET",
        timeout: float = 3.0,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Execute non-blocking HTTP probe using asyncio loop executor."""
        loop = asyncio.get_event_loop()

        def _do_req():
            try:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                headers = {"User-Agent": "PENTRAX-Vulnerability-Scanner/8.0 (Authorized Security Audit)"}
                if extra_headers:
                    headers.update(extra_headers)

                req = urllib.request.Request(
                    url,
                    headers=headers,
                    method=method
                )
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                    body = r.read(8192).decode("utf-8", errors="ignore")
                    headers = dict(r.headers)
                    return {"status": r.status, "body": body, "headers": headers}
            except urllib.error.HTTPError as e:
                body = e.read(4096).decode("utf-8", errors="ignore") if hasattr(e, "read") else ""
                headers = dict(e.headers) if hasattr(e, "headers") else {}
                return {"status": e.code, "body": body, "headers": headers}
            except Exception:
                return None

        return await loop.run_in_executor(None, _do_req)

    def _eval_matchers(self, response: Dict[str, Any], matchers: List[Dict[str, Any]]) -> bool:
        """Evaluate matcher conditions against HTTP response status, body, and headers."""
        if not matchers:
            return response.get("status") == 200

        for m in matchers:
            m_type = m.get("type", "status")
            part = str(m.get("part", "body")).lower()
            if part in ("header", "headers"):
                target_text = "\n".join(f"{k}: {v}" for k, v in response.get("headers", {}).items())
            else:
                target_text = response.get("body", "")

            if m_type == "status":
                expected_statuses = m.get("values", [200])
                if response.get("status") not in expected_statuses:
                    return False
            elif m_type == "word":
                words = m.get("words", [])
                if isinstance(words, str):
                    words = [words]
                condition = m.get("condition", "and")
                if condition == "and":
                    if not all(w in target_text for w in words):
                        return False
                else:
                    if not any(w in target_text for w in words):
                        return False
            elif m_type == "regex":
                patterns = m.get("patterns") or m.get("regex") or []
                if isinstance(patterns, str):
                    patterns = [patterns]
                if not any(re.search(p, target_text, re.IGNORECASE) for p in patterns):
                    return False
        return True


class PluginManager:
    """Plugin and script management system for Python extension modules."""

    def __init__(self):
        self.plugins = []
        self.hooks = {
            "pre_scan": [],
            "post_scan": [],
            "per_host": [],
            "per_service": [],
            "per_vuln": [],
        }

    def load_plugin(self, path: str) -> bool:
        """Load a plugin from file path."""
        import importlib.util
        try:
            spec = importlib.util.spec_from_file_location("plugin", path)
            if not spec or not spec.loader:
                return False
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Register hooks
            for hook in ["pre_scan", "post_scan", "per_host", "per_service", "per_vuln"]:
                if hasattr(module, hook):
                    self.hooks[hook].append(getattr(module, hook))

            self.plugins.append(path)
            return True
        except Exception:
            return False

    def run_hook(self, hook_name: str, *args, **kwargs) -> List[Any]:
        """Run all registered hooks for a given event."""
        results = []
        for hook in self.hooks.get(hook_name, []):
            try:
                res = hook(*args, **kwargs)
                if res is not None:
                    results.append(res)
            except Exception:
                pass
        return results


plugin_manager = PluginManager()

