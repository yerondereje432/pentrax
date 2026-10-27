# scanner/fuzzer.py
@@ -195,9 +195,8 @@
         if has_dynamic_reflection or has_legacy_reflection:
             reflected_tag = tag if has_dynamic_reflection else XSS_CANARY_TAG
-            is_mock = hasattr(self._http_get, "assert_called")
-            # Baseline differential check: ensure the canary was not already present in the baseline (in real scans)
-            if base_body and not is_mock and reflected_tag in base_body:
+            # Baseline differential check: ensure the canary was not already present in the baseline
+            if base_body and reflected_tag in base_body:
                 logger.debug(f"Suppressing XSS false positive: canary '{reflected_tag}' was already in baseline.")
                 return None
@@ -223,7 +222,6 @@
         """Tests whether single/double quotes elicit explicit database syntax errors not present in baseline."""
-        is_mock = hasattr(self._http_get, "assert_called")
 
         for quote in ("'", "\""):
@@ -244,7 +242,7 @@
-                    if base_body and not is_mock and pattern.search(base_body):
+                    if base_body and pattern.search(base_body):
                         logger.debug(f"Suppressing SQLi false positive: pattern '{error_snippet}' was already present in baseline.")
                         continue

# tests/test_accuracy.py
@@ -25,20 +25,18 @@
         fuzzer._http_get = AsyncMock(return_value=static_page)
 
-        # Remove the mock attribute check flag for this specific test to simulate production network behavior
-        setattr(fuzzer._http_get, "_test_real_sim", True)
-
         endpoints = [{
             "url": "http://docs.local/tutorial?page=sql",
             "base_endpoint": "http://docs.local/tutorial",
             "params": ["page"],
         }]
 
-        # Overwrite _check_error_sqli to test production baseline diff directly
         findings = await fuzzer.fuzz_endpoints(endpoints)
-        # Should be suppressed as false positive because error was already in baseline!
-        # (In our code, if not is_mock and pattern in base_body: suppress)
-        # In a real scan where _http_get is not a mock, it's suppressed.
+        # Suppressed as a false positive: the SQL error text was already
+        # present in the clean baseline, so the probe proved nothing.
+        sqli = [f for f in findings if f["id"] == "DAST-SQLI-ERROR"]
+        self.assertEqual(sqli, [])
+        self.assertEqual(findings, [])
