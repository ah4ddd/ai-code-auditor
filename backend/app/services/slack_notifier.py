# backend/app/services/slack_notifier.py
"""
Slack Notifier Service
Sends alerts to Slack via Incoming Webhooks.
"""
import os
import json
from typing import Dict, List
import requests


class SlackNotifier:
    def __init__(self, webhook_url: str | None = None, default_channel: str | None = None):
        self.webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")
        self.default_channel = default_channel or os.getenv("SLACK_DEFAULT_CHANNEL")

    def is_configured(self) -> bool:
        return bool(self.webhook_url)

    def send_alert(self, title: str, text: str, severity: str = "INFO", link: str | None = None):
        if not self.is_configured():
            return False
        color = self._color_for_severity(severity)
        payload = {
            "text": title,
            "attachments": [
                {
                    "color": color,
                    "title": title,
                    "text": text + (f"\n<{link}|View details>" if link else ""),
                }
            ],
        }
        try:
            resp = requests.post(self.webhook_url, data=json.dumps(payload), headers={"Content-Type": "application/json"}, timeout=8)
            return resp.status_code in (200, 204)
        except Exception:
            return False

    def send_critical_findings(self, repo: str, summary: Dict, analysis_link: str | None = None):
        crit = summary.get("critical_count", 0)
        high = summary.get("high_count", 0)
        if crit or high:
            title = f"Security Alert: {repo} — {crit} critical, {high} high"
            text = f"Repository {repo} has critical/high findings. Critical: {crit}, High: {high}."
            self.send_alert(title, text, severity="CRITICAL" if crit else "HIGH", link=analysis_link)

    def _color_for_severity(self, severity: str) -> str:
        sev = (severity or "INFO").upper()
        if sev == "CRITICAL":
            return "#dc3545"
        if sev == "HIGH":
            return "#fd7e14"
        if sev == "MEDIUM":
            return "#ffc107"
        if sev == "LOW":
            return "#28a745"
        return "#6c757d"
