"""Shared validation, sanitisation, and safe highlighting helpers."""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Mapping


FIELD_LIMITS: dict[str, int] = {
    "sender_name": 120,
    "sender_email": 254,
    "recipient": 254,
    "subject": 300,
    "body": 10_000,
    "displayed_link": 1_000,
    "actual_url": 2_048,
    "attachment_filename": 255,
}

HIGHLIGHT_PHRASES: tuple[str, ...] = (
    "verify immediately",
    "account suspended",
    "banking details",
    "claim your prize",
    "reset your password now",
    "click here",
    "password",
    "urgent",
    "otp",
    "pin",
    "cvv",
)


def normalise_form_data(form: Mapping[str, object]) -> dict[str, str]:
    """Return known fields as trimmed, length-limited strings."""
    cleaned: dict[str, str] = {}
    for field, limit in FIELD_LIMITS.items():
        value = str(form.get(field, "") or "").strip()
        cleaned[field] = value[:limit]
    return cleaned


def validate_email_input(
    form: Mapping[str, object],
) -> tuple[dict[str, str], list[str]]:
    """Validate a submitted educational sample without retaining its values."""
    cleaned = normalise_form_data(form)
    errors: list[str] = []

    for field, limit in FIELD_LIMITS.items():
        original = str(form.get(field, "") or "")
        if len(original) > limit:
            label = field.replace("_", " ").title()
            errors.append(f"{label} must be {limit} characters or fewer.")

    if not any(
        cleaned[field]
        for field in (
            "sender_email",
            "subject",
            "body",
            "actual_url",
            "attachment_filename",
        )
    ):
        errors.append("Enter at least one email detail to analyse.")

    authorised = str(form.get("authorised", "")).lower() in {
        "on",
        "true",
        "1",
        "yes",
    }
    if not authorised:
        errors.append(
            "Confirm that the sample is fictional, harmless, or authorised."
        )

    return cleaned, errors


def find_phrases(text: str, phrases: tuple[str, ...] | list[str]) -> list[str]:
    """Find phrases case-insensitively and return each phrase once."""
    lowered = text.casefold()
    return [phrase for phrase in phrases if phrase.casefold() in lowered]


def safe_highlight(
    text: str,
    phrases: tuple[str, ...] = HIGHLIGHT_PHRASES,
) -> str:
    """Escape untrusted text, then add markup only around known phrases."""
    if not text:
        return ""

    unique_phrases = sorted(set(phrases), key=len, reverse=True)
    if not unique_phrases:
        return html.escape(text).replace("\n", "<br>")
    pattern = re.compile(
        "(" + "|".join(re.escape(item) for item in unique_phrases) + ")",
        re.IGNORECASE,
    )
    output: list[str] = []
    cursor = 0

    for match in pattern.finditer(text):
        output.append(html.escape(text[cursor : match.start()]))
        output.append(
            '<mark class="suspicious-phrase">'
            + html.escape(match.group(0))
            + "</mark>"
        )
        cursor = match.end()

    output.append(html.escape(text[cursor:]))
    return "".join(output).replace("\n", "<br>")


def sanitise_report_value(value: object, limit: int = 10_000) -> str:
    """Remove unsafe control characters from a plain-text report value."""
    text = str(value or "")[:limit]
    return "".join(
        character
        for character in text
        if character in "\n\t" or ord(character) >= 32
    )


def sanitise_filename(name: str, default: str = "phishguard-report.txt") -> str:
    """Create a conservative basename that cannot expose a local path."""
    basename = Path(name).name
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", basename).strip(".-_")
    if not safe:
        return default
    return safe[:100]
