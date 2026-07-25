"""Filename-only attachment risk checks."""

from __future__ import annotations

from pathlib import PurePath


ATTACHMENT_WEIGHTS: dict[str, int] = {
    "executable_attachment": 25,
    "macro_enabled_attachment": 15,
    "double_extension_attachment": 25,
    "archive_attachment": 10,
}

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".js",
    ".vbs",
    ".ps1",
    ".jar",
    ".msi",
    ".hta",
    ".iso",
    ".img",
    ".lnk",
}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
COMMON_DECOY_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".jpg",
    ".jpeg",
    ".png",
    ".txt",
}


def _indicator(
    rule_id: str,
    title: str,
    explanation: str,
    action: str,
    matches: list[str],
) -> dict[str, object]:
    return {
        "id": rule_id,
        "category": "attachment",
        "title": title,
        "points": ATTACHMENT_WEIGHTS[rule_id],
        "explanation": explanation,
        "action": action,
        "matches": matches,
    }


def analyse_attachment(filename: str) -> dict[str, object]:
    """Classify a filename without uploading, opening, or executing a file."""
    cleaned = PurePath(filename.strip()).name
    if not cleaned:
        return {
            "filename": "",
            "extension": "",
            "points": 0,
            "risk_level": "Low",
            "indicators": [],
        }

    lowered = cleaned.casefold()
    suffixes = [suffix.casefold() for suffix in PurePath(lowered).suffixes]
    extension = suffixes[-1] if suffixes else ""
    indicators: list[dict[str, object]] = []

    if extension in EXECUTABLE_EXTENSIONS:
        indicators.append(
            _indicator(
                "executable_attachment",
                "Executable or active attachment type",
                f"The filename ends in {extension}, a type that may run code or "
                "mount active content.",
                "Do not open it. Confirm the file through a trusted channel.",
                [extension],
            )
        )

    if extension in MACRO_EXTENSIONS:
        indicators.append(
            _indicator(
                "macro_enabled_attachment",
                "Macro-enabled Office document",
                f"The {extension} format can contain executable Office macros.",
                "Do not enable macros; verify the document with the sender.",
                [extension],
            )
        )

    if extension in ARCHIVE_EXTENSIONS:
        indicators.append(
            _indicator(
                "archive_attachment",
                "Compressed archive attachment",
                f"The {extension} archive can conceal risky files inside it.",
                "Inspect it only with approved security controls after verification.",
                [extension],
            )
        )

    if (
        len(suffixes) >= 2
        and suffixes[-2] in COMMON_DECOY_EXTENSIONS
        and suffixes[-1] in EXECUTABLE_EXTENSIONS
    ):
        indicators.append(
            _indicator(
                "double_extension_attachment",
                "Deceptive double extension",
                "The filename combines a familiar document or image extension "
                "with an active final extension.",
                "Treat the final extension as authoritative and do not open it.",
                suffixes[-2:],
            )
        )

    points = sum(int(item["points"]) for item in indicators)
    if any(item["id"] == "double_extension_attachment" for item in indicators):
        risk_level = "Critical"
    elif extension in EXECUTABLE_EXTENSIONS:
        risk_level = "High"
    elif extension in MACRO_EXTENSIONS or extension in ARCHIVE_EXTENSIONS:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "filename": cleaned,
        "extension": extension,
        "points": points,
        "risk_level": risk_level,
        "indicators": indicators,
    }
