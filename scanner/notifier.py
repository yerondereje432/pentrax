"""Critical finding alerting via Webhook (Slack / Discord) and SMTP email for PENTRAX."""
import json
import logging
import os
import smtplib
import urllib.error
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, Optional

logger = logging.getLogger("pentrax.notifier")


class Notifier:
    """Dispatches real-time security alerts when high or critical vulnerabilities are discovered."""

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        smtp_host: Optional[str] = None,
        smtp_port: Optional[int] = None,
        smtp_user: Optional[str] = None,
        smtp_pass: Optional[str] = None,
        alert_email: Optional[str] = None,
    ):
        self.webhook_url = webhook_url or os.getenv("PENTRAX_WEBHOOK_URL")
        self.smtp_host = smtp_host or os.getenv("PENTRAX_SMTP_HOST")
        self.smtp_port = smtp_port or int(os.getenv("PENTRAX_SMTP_PORT", "587"))
        self.smtp_user = smtp_user or os.getenv("PENTRAX_SMTP_USER")
        self.smtp_pass = smtp_pass or os.getenv("PENTRAX_SMTP_PASS")
        self.alert_email = alert_email or os.getenv("PENTRAX_ALERT_EMAIL")

    def notify_critical(self, finding: Dict[str, Any], scan_id: str, host: str = "Unknown") -> bool:
        """Sends an urgent alert for a CRITICAL or HIGH finding."""
        webhook_sent = False
        email_sent = False

        if self.webhook_url:
            webhook_sent = self._send_webhook_alert(finding, scan_id, host)
        if self.smtp_host and self.alert_email:
            email_sent = self._send_email_alert(finding, scan_id, host)

        return webhook_sent or email_sent

    def notify_scan_complete(self, scan_summary: Dict[str, Any]) -> bool:
        """Dispatches notification when a full assessment scan completes."""
        if not self.webhook_url:
            return False

        scan_id = scan_summary.get("id", "Unknown")
        target = scan_summary.get("target", "Unknown")
        crit_count = scan_summary.get("critical_count", 0)
        high_count = scan_summary.get("high_count", 0)
        open_ports = scan_summary.get("open_ports_count", 0)

        color = "#ef4444" if crit_count > 0 else ("#f97316" if high_count > 0 else "#10b981")
        title = f"🛡️ PENTRAX Scan Completed: {target}"

        # Slack / Discord dual payload structure
        payload = {
            "text": f"*{title}* (`{scan_id}`)\nOpen Ports: {open_ports} | Critical: {crit_count} | High: {high_count}",
            "attachments": [
                {
                    "color": color,
                    "title": f"Scan Dossier — {target}",
                    "fields": [
                        {"title": "Scan ID", "value": scan_id, "short": True},
                        {"title": "Open Ports", "value": str(open_ports), "short": True},
                        {"title": "Critical Vulns", "value": str(crit_count), "short": True},
                        {"title": "High Vulns", "value": str(high_count), "short": True},
                    ],
                }
            ],
        }
        return self._post_json(self.webhook_url, payload)

    def _send_webhook_alert(self, finding: Dict[str, Any], scan_id: str, host: str) -> bool:
        title = finding.get("title", finding.get("id", "Vulnerability Detected"))
        severity = finding.get("severity", "CRITICAL").upper()
        cvss = finding.get("cvss", 9.0)
        remediation = finding.get("remediation", "Review host configuration immediately.")
        evidence = finding.get("evidence", "")

        is_discord = "discord.com" in self.webhook_url

        if is_discord:
            color_int = 0xFF0000 if severity == "CRITICAL" else 0xFF8800
            payload = {
                "content": f"🚨 **PENTRAX SECURITY ALERT** — {severity} finding on `{host}`",
                "embeds": [
                    {
                        "title": title,
                        "description": evidence[:500] if evidence else "Severe security exposure detected.",
                        "color": color_int,
                        "fields": [
                            {"name": "Host", "value": host, "inline": True},
                            {"name": "CVSS v3.1", "value": str(cvss), "inline": True},
                            {"name": "Scan ID", "value": scan_id, "inline": True},
                            {"name": "Remediation", "value": remediation, "inline": False},
                        ],
                    }
                ],
            }
        else:
            payload = {
                "text": f"🚨 *PENTRAX ALERT* — {severity} on `{host}`: *{title}* (CVSS {cvss})",
                "attachments": [
                    {
                        "color": "danger" if severity == "CRITICAL" else "warning",
                        "text": f"*Remediation*: {remediation}\n*Scan ID*: `{scan_id}`",
                    }
                ],
            }

        return self._post_json(self.webhook_url, payload)

    def _send_email_alert(self, finding: Dict[str, Any], scan_id: str, host: str) -> bool:
        try:
            msg = MIMEMultipart("alternative")
            severity = finding.get("severity", "CRITICAL").upper()
            title = finding.get("title", "Security Finding")
            msg["Subject"] = f"[{severity}] PENTRAX Alert: {title} on {host}"
            msg["From"] = self.smtp_user or "scanner@pentrax.local"
            msg["To"] = self.alert_email

            body_text = f"""
PENTRAX Automated Security Notification
Severity: {severity}
Host: {host}
Finding: {title}
CVSS Score: {finding.get('cvss', 'N/A')}
Remediation: {finding.get('remediation', 'N/A')}
Scan ID: {scan_id}
            """
            msg.attach(MIMEText(body_text, "plain"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=5.0) as server:
                server.starttls()
                if self.smtp_user and self.smtp_pass:
                    server.login(self.smtp_user, self.smtp_pass)
                server.send_message(msg)
            return True
        except Exception as e:
            logger.warning("SMTP email dispatch failed: %s", e)
            return False

    def _post_json(self, url: str, data: Dict[str, Any]) -> bool:
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "PENTRAX-Notifier/10.0",
                },
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return resp.status in (200, 204)
        except Exception as e:
            logger.warning("Webhook dispatch failed: %s", e)
            return False


notifier = Notifier()

