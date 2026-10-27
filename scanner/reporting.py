@@ -218,10 +218,30 @@
     return content
 
 
+def sanitize_csv_cell(value: Any) -> str:
+    """Sanitize a cell value to prevent CSV Formula Injection / DDE attacks in Excel/Sheets.
+
+    Mirrors pentrax.sanitize_csv_cell: any cell whose text starts with
+    =, +, -, @, a tab, or a carriage return is prefixed with a single
+    quote so spreadsheet applications treat it as text, not a formula.
+    Service banners and version strings are attacker-controlled, so a
+    scanned host must not be able to weaponize the analyst's report.
+    """
+    if value is None:
+        return ""
+    cell = str(value)
+    if cell and cell[0] in ("=", "+", "-", "@", "\t", "\r"):
+        return "'" + cell
+    return cell
+
+
 def export_csv(data: Dict[str, Any], path: Optional[str] = None) -> str:
     """Exports scan findings and open ports to CSV string or file."""
     output = io.StringIO()
     writer = csv.writer(output)
+
+    def _write_row(row):
+        writer.writerow([sanitize_csv_cell(cell) for cell in row])
     writer.writerow([
         "Host", "Port", "Protocol", "State", "Service", "Version", "Vulnerability", "CVE", "Severity", "CVSS", "Remediation", "SLA"
     ])
@@ -232,21 +252,21 @@
             if not vulns and not cves:
-                writer.writerow([
+                _write_row([
                     ip, p.get("port"), p.get("protocol", "tcp"), p.get("state", "open"),
                     p.get("service", "unknown"), p.get("version", ""), "", "", "INFO", "0.0", "", ""
                 ])
             else:
                 for v in vulns:
                     v_dict = v if isinstance(v, dict) else {"title": str(v), "severity": "MEDIUM", "cvss": 5.0}
-                    writer.writerow([
+                    _write_row([
                         ip, p.get("port"), p.get("protocol", "tcp"), p.get("state", "open"),
                         p.get("service", "unknown"), p.get("version", ""), v_dict.get("title", ""),
                         "", v_dict.get("severity", "MEDIUM"), v_dict.get("cvss", 5.0),
                         v_dict.get("remediation", ""), v_dict.get("remediation_sla", "")
                     ])
                 for c in cves:
-                    writer.writerow([
+                    _write_row([
                         ip, p.get("port"), p.get("protocol", "tcp"), p.get("state", "open"),
                         p.get("service", "unknown"), p.get("version", ""), c.get("description", ""),
                         c.get("cve", ""), "CRITICAL" if float(c.get("cvss_score", 0)) >= 9 else "HIGH",
