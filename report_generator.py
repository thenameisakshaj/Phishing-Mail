"""Safe plain-text report generation for completed analyses."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Mapping

from utils import sanitise_filename, sanitise_report_value


def create_report(
    email_data: Mapping[str, object],
    result: Mapping[str, object],
) -> tuple[str, str]:
    """Return a sanitised filename and a non-executable plain-text report."""
    timestamp = datetime.now(timezone.utc)
    filename = sanitise_filename(
        f"phishguard-analysis-{timestamp:%Y%m%d-%H%M%S}.txt"
    )

    lines = [
        "PHISHGUARD - PHISHING EMAIL EDUCATIONAL ANALYSIS",
        "=" * 56,
        f"Generated (UTC): {timestamp:%Y-%m-%d %H:%M:%S}",
        "",
        "EMAIL METADATA",
        "-" * 14,
        f"Sender name: {sanitise_report_value(email_data.get('sender_name'))}",
        f"Sender email: {sanitise_report_value(email_data.get('sender_email'))}",
        f"Recipient: {sanitise_report_value(email_data.get('recipient'))}",
        f"Subject: {sanitise_report_value(email_data.get('subject'))}",
        "Displayed link: "
        f"{sanitise_report_value(email_data.get('displayed_link'))}",
        f"Actual URL: {sanitise_report_value(email_data.get('actual_url'))}",
        "Attachment filename: "
        f"{sanitise_report_value(email_data.get('attachment_filename'))}",
        "",
        "EMAIL BODY",
        "-" * 10,
        sanitise_report_value(email_data.get("body")),
        "",
        "RISK ASSESSMENT",
        "-" * 15,
        f"Risk score: {int(result.get('score', 0))}/100",
        f"Risk category: {sanitise_report_value(result.get('risk_category'))}",
        f"Indicators detected: {int(result.get('indicator_count', 0))}",
        "",
        "TRIGGERED INDICATORS",
        "-" * 20,
    ]

    indicators = list(result.get("indicators", []))
    if not indicators:
        lines.append("No rule-based warning indicators were detected.")
    for number, indicator in enumerate(indicators, start=1):
        lines.extend(
            [
                f"{number}. {sanitise_report_value(indicator.get('title'))} "
                f"(+{int(indicator.get('points', 0))} points)",
                "   Explanation: "
                f"{sanitise_report_value(indicator.get('explanation'))}",
                "   Recommended action: "
                f"{sanitise_report_value(indicator.get('action'))}",
            ]
        )

    lines.extend(
        [
            "",
            "SAFE BEHAVIOUR RECOMMENDATIONS",
            "-" * 30,
            "- Verify the complete sender address.",
            "- Open the organisation's official site independently.",
            "- Never share passwords, OTPs, PINs, recovery codes, or card data.",
            "- Verify payment and attachment requests through another channel.",
            "- Report suspicious messages to the appropriate administrator.",
            "",
            "EDUCATIONAL DISCLAIMER",
            "-" * 22,
            "This report is produced by a transparent heuristic tool for "
            "phishing-awareness education. It is not a definitive security "
            "verdict and does not guarantee that an email is safe or malicious. "
            "No URL or attachment was opened, resolved, downloaded, or executed.",
            "",
        ]
    )
    return filename, "\n".join(lines)
