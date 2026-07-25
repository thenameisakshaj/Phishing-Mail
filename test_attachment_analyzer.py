"""Tests for filename-only attachment analysis."""

from attachment_analyzer import analyse_attachment


def _ids(filename: str) -> set[str]:
    result = analyse_attachment(filename)
    return {str(item["id"]) for item in result["indicators"]}


def test_executable_attachment_detection() -> None:
    assert "executable_attachment" in _ids("installer.exe")


def test_double_extension_detection() -> None:
    ids = _ids("invoice.pdf.exe")
    assert {"executable_attachment", "double_extension_attachment"} <= ids


def test_macro_enabled_document_detection() -> None:
    result = analyse_attachment("quarterly_report.xlsm")
    assert "macro_enabled_attachment" in {
        item["id"] for item in result["indicators"]
    }
    assert result["risk_level"] == "Medium"


def test_archive_is_medium_risk() -> None:
    result = analyse_attachment("documents.7z")
    assert "archive_attachment" in {
        item["id"] for item in result["indicators"]
    }
    assert result["risk_level"] == "Medium"


def test_safe_document_is_low_risk() -> None:
    result = analyse_attachment("schedule.pdf")
    assert result["risk_level"] == "Low"
    assert result["points"] == 0


def test_empty_attachment_filename_is_low_risk() -> None:
    result = analyse_attachment("")
    assert result["risk_level"] == "Low"
    assert result["indicators"] == []
