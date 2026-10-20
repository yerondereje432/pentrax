"""Unit tests for PENTRAX Web Spider / Crawler and Active Parameter Fuzzer."""

import unittest
from unittest.mock import AsyncMock, patch
from scanner.crawler import AsyncWebCrawler, _HTMLRouteExtractor
from scanner.fuzzer import ParameterFuzzer, XSS_CANARY_TAG
from scanner.plugin_loader import YAMLTemplateEngine


class TestWebCrawler(unittest.TestCase):
    """Test suite for AsyncWebCrawler and DOM parsing."""

    def test_route_extractor_filters_and_extracts(self):
        extractor = _HTMLRouteExtractor("http://target.local/base/")
        sample_html = """
        <html>
          <head>
            <script src="/static/app.js"></script>
            <script src="https://cdn.external.com/lib.js"></script>
          </head>
          <body>
            <a href="/login">Login</a>
            <a href="dashboard?user=1">Dashboard</a>
            <a href="mailto:admin@target.local">Email</a>
            <a href="javascript:void(0)">Click</a>
            <a href="#section2">Anchor</a>
            <form action="/search" method="GET">
              <input name="q" type="text" value="default">
              <input name="category" type="hidden" value="sec">
            </form>
          </body>
        </html>
        """
        extractor.feed(sample_html)

        # Verify links normalized
        self.assertIn("http://target.local/login", extractor.links)
        self.assertIn("http://target.local/base/dashboard?user=1", extractor.links)
        # Verify void links filtered
        for link in extractor.links:
            self.assertFalse(link.startswith(("mailto:", "javascript:", "#")))

        # Verify scripts
        self.assertIn("http://target.local/static/app.js", extractor.scripts)

        # Verify form extraction
        self.assertEqual(len(extractor.forms), 1)
        form = extractor.forms[0]
        self.assertEqual(form["action"], "http://target.local/search")
        self.assertEqual(form["method"], "GET")
        input_names = [i["name"] for i in form["inputs"]]
        self.assertIn("q", input_names)
        self.assertIn("category", input_names)

    def test_crawler_parameter_cataloging(self):
        crawler = AsyncWebCrawler("http://example.com")
        crawler._extract_params_if_any("http://example.com/search?q=test&lang=en")
        self.assertEqual(len(crawler.parameterized_endpoints), 1)
        entry = crawler.parameterized_endpoints[0]
        self.assertEqual(entry["params"], ["q", "lang"])
        self.assertEqual(entry["base_endpoint"], "http://example.com/search")


class TestParameterFuzzer(unittest.IsolatedAsyncioTestCase):
    """Test suite for safe parameter fuzzing (XSS & SQLi)."""

    async def test_reflected_xss_detection(self):
        fuzzer = ParameterFuzzer()
        # Mock HTTP GET returning the reflected canary
        fuzzer._http_get = AsyncMock(return_value=f"<html><body>Hello {XSS_CANARY_TAG}</body></html>")

        endpoints = [{
            "url": "http://target.local/profile?name=john",
            "base_endpoint": "http://target.local/profile",
            "params": ["name"],
        }]

        findings = await fuzzer.fuzz_endpoints(endpoints)
        xss_findings = [f for f in findings if f["id"] == "DAST-REFLECTED-XSS"]
        self.assertEqual(len(xss_findings), 1)
        self.assertEqual(xss_findings[0]["severity"], "HIGH")
        self.assertEqual(xss_findings[0]["parameter"], "name")
        self.assertIn("DAST: XSS", xss_findings[0]["category"])

    async def test_error_sqli_detection(self):
        fuzzer = ParameterFuzzer()
        # Mock HTTP GET returning a MySQL syntax error
        fuzzer._http_get = AsyncMock(return_value="Fatal Error: You have an error in your SQL syntax near '1''")

        endpoints = [{
            "url": "http://target.local/item?id=10",
            "base_endpoint": "http://target.local/item",
            "params": ["id"],
        }]

        findings = await fuzzer.fuzz_endpoints(endpoints)
        sqli_findings = [f for f in findings if f["id"] == "DAST-SQLI-ERROR"]
        self.assertEqual(len(sqli_findings), 1)
        self.assertEqual(sqli_findings[0]["severity"], "CRITICAL")
        self.assertEqual(sqli_findings[0]["parameter"], "id")
        self.assertEqual(sqli_findings[0]["remediation_sla"], "48 Hours")


class TestYAMLTemplatesExpanded(unittest.IsolatedAsyncioTestCase):
    """Verify new templates are successfully loaded and matched."""

    def test_new_templates_loaded(self):
        engine = YAMLTemplateEngine()
        template_ids = [t.get("id") for t in engine.templates]
        self.assertIn("PENTRAX-HTTP-LFI", template_ids)
        self.assertIn("PENTRAX-HTTP-REDIRECT", template_ids)
        self.assertIn("PENTRAX-CVE-2021-41773", template_ids)
        self.assertIn("PENTRAX-CVE-2022-22965", template_ids)
        self.assertIn("PENTRAX-API-GRAPHQL", template_ids)
        self.assertIn("PENTRAX-NET-DOCKER", template_ids)
        self.assertIn("PENTRAX-NET-KUBELET", template_ids)


if __name__ == "__main__":
    unittest.main()

