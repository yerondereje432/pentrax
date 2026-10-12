"""Opt-in notifications for newly introduced high-risk scan findings."""

from __future__ import annotations

import logging
import json
import os
import urllib.parse
import urllib.request
from typing import Any


WEBHOOK_ENV = "YERSCAN_ALERT_WEBHOOK_URL"
ALERT_LEVELS = {"CRITICAL", "HIGH"}


def notify_new_findings(
    *,
    target: str,
    report_name: str,
    diff: dict[str, Any],
    webhook_url: str | None = None,
    logger: logging.Logger | None = None,
) -> bool:
    """Send a webhook alert for new CRITICAL/HIGH findings, if configured.

    Delivery is deliberately best-effort: an absent or failing webhook must not
    make a scan or report upload fail.
    """
    logger = logger or logging.getLogger(__name__)
    findings = [
        row for row in diff.get("new_findings", [])
        if str(row.get("risk_level", "")).upper() in ALERT_LEVELS
    ]
    if not findings:
        return False

    webhook_url = (webhook_url or os.environ.get(WEBHOOK_ENV, "")).strip()
    if not webhook_url:
        return False

    parsed_url = urllib.parse.urlparse(webhook_url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        logger.warning("Skipping scan alert because %s is not a valid HTTP webhook URL", WEBHOOK_ENV)
        return False

    lines = [f"New CRITICAL/HIGH findings detected for {target}", f"Report: {report_name}"]
    for row in findings[:20]:
        identifier = row.get("cve_id") or row.get("description") or "Unnamed finding"
        location = f"{row.get('host_ip', 'unknown')}:{row.get('port', 'unknown')}"
        lines.append(f"[{str(row.get('risk_level', '')).upper()}] {identifier} on {location}")
    if len(findings) > 20:
        lines.append(f"...and {len(findings) - 20} more")
    message = "\n".join(lines)

    host = parsed_url.netloc.lower()
    payload = {"content": message} if "discord.com" in host or "discordapp.com" in host else {"text": message}
    request = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
    except Exception as exc:  # Notification must never break scan processing.
        logger.warning("Could not deliver scan alert webhook: %s", exc)
        return False
    return True
