"""Asynchronous Web Link and Form Crawler (Web Spider) for PENTRAX.

Recursively maps web application attack surface by discovering internal links,
forms, query parameters, and endpoints for targeted DAST and fuzzing.
"""

import asyncio
import logging
import ssl
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("pentrax.crawler")


class _HTMLRouteExtractor(HTMLParser):
    """Parses HTML DOM to extract hyperlinks, forms, and script sources."""

    def __init__(self, current_url: str):
        super().__init__()
        self.current_url = current_url
        self.links: Set[str] = set()
        self.scripts: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): v for k, v in attrs if v is not None}

        # 1. Hyperlinks
        if tag == "a" and "href" in attr_dict:
            href = attr_dict["href"].strip()
            if self._is_valid_route(href):
                resolved = urllib.parse.urljoin(self.current_url, href)
                self.links.add(resolved)

        # 2. Scripts
        elif tag == "script" and "src" in attr_dict:
            src = attr_dict["src"].strip()
            if self._is_valid_route(src):
                resolved = urllib.parse.urljoin(self.current_url, src)
                self.scripts.add(resolved)

        # 3. Form initiation
        elif tag == "form":
            action = attr_dict.get("action", "").strip() or self.current_url
            resolved_action = urllib.parse.urljoin(self.current_url, action)
            method = attr_dict.get("method", "GET").upper()
            self._current_form = {
                "action": resolved_action,
                "method": method,
                "inputs": [],
            }

        # 4. Form inputs
        elif tag in ("input", "textarea", "select") and self._current_form:
            input_name = attr_dict.get("name")
            if input_name:
                self._current_form["inputs"].append({
                    "name": input_name,
                    "type": attr_dict.get("type", "text").lower(),
                    "value": attr_dict.get("value", ""),
                })

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form:
            self.forms.append(self._current_form)
            self._current_form = None

    @staticmethod
    def _is_valid_route(href: str) -> bool:
        """Filter out non-HTTP schemes and void anchors."""
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return False
        return True


class AsyncWebCrawler:
    """Non-blocking web crawler bounded by depth and page limits."""

    def __init__(
        self,
        base_url: str,
        max_depth: int = 2,
        max_pages: int = 30,
        timeout: float = 3.0,
        cookie: Optional[str] = None,
        custom_header: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        parsed = urllib.parse.urlparse(self.base_url)
        self.target_host = parsed.netloc.lower()
        self.scheme = parsed.scheme.lower() or "http"
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.cookie = cookie
        self.custom_header = custom_header

        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.parameterized_endpoints: List[Dict[str, Any]] = []
        self.discovered_forms: List[Dict[str, Any]] = []
        self.discovered_scripts: Set[str] = set()

    async def crawl(self) -> Dict[str, Any]:
        """Executes asynchronous breadth-first web crawling."""
        # Queue item: (url, depth)
        queue: List[Tuple[str, int]] = [(self.base_url, 0)]
        self.discovered_urls.add(self.base_url)

        headers = {
            "User-Agent": "PENTRAX-Spider/8.0 (Authorized Security Audit; +https://pentrax.sec)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        if self.cookie:
            headers["Cookie"] = self.cookie
        if self.custom_header:
            if ":" in self.custom_header:
                hk, hv = self.custom_header.split(":", 1)
                headers[hk.strip()] = hv.strip()
            else:
                headers["Authorization"] = self.custom_header

        while queue and len(self.visited_urls) < self.max_pages:
            current_url, depth = queue.pop(0)
            if current_url in self.visited_urls:
                continue

            self.visited_urls.add(current_url)
            self._extract_params_if_any(current_url)

            if depth >= self.max_depth:
                continue

            html_body = await self._fetch_html(current_url, headers)
            if not html_body:
                continue

            # Parse DOM
            extractor = _HTMLRouteExtractor(current_url)
            try:
                extractor.feed(html_body)
            except Exception as e:
                logger.debug(f"HTML parse error on {current_url}: {e}")

            # Collect scripts & forms
            self.discovered_scripts.update(extractor.scripts)
            for form in extractor.forms:
                if form not in self.discovered_forms:
                    self.discovered_forms.append(form)

            # Enqueue valid internal links
            for link in extractor.links:
                parsed_link = urllib.parse.urlparse(link)
                # Ensure link belongs to same host (avoid external crawling)
                if parsed_link.netloc.lower() == self.target_host:
                    clean_link = urllib.parse.urldefrag(link)[0]
                    if clean_link not in self.discovered_urls:
                        self.discovered_urls.add(clean_link)
                        queue.append((clean_link, depth + 1))

        return {
            "target": self.base_url,
            "pages_crawled": len(self.visited_urls),
            "urls_discovered": sorted(list(self.discovered_urls)),
            "parameterized_endpoints": self.parameterized_endpoints,
            "forms_discovered": self.discovered_forms,
            "scripts_discovered": sorted(list(self.discovered_scripts)),
        }

    def _extract_params_if_any(self, url: str):
        """Extract and catalog query parameters for downstream fuzzing."""
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            qs = urllib.parse.parse_qs(parsed.query)
            params = list(qs.keys())
            base_endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            entry = {
                "url": url,
                "base_endpoint": base_endpoint,
                "params": params,
                "sample_query": parsed.query,
            }
            if not any(e["url"] == url for e in self.parameterized_endpoints):
                self.parameterized_endpoints.append(entry)

    async def _fetch_html(self, url: str, headers: Dict[str, str]) -> Optional[str]:
        """Fetch page content asynchronously via threadpool."""
        loop = asyncio.get_event_loop()

        def _get():
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:
                    content_type = r.headers.get("Content-Type", "").lower()
                    if "text/html" not in content_type and "application/xhtml" not in content_type:
                        return None
                    return r.read(131072).decode("utf-8", errors="ignore")
            except Exception:
                return None

        return await loop.run_in_executor(None, _get)

