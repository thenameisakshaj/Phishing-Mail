"""Tests for sender and content rules."""

from analyzer import analyse_email
from utils import find_phrases, safe_highlight


def test_keyword_detection_finds_urgent_phrase() -> None:
    result = analyse_email(
        {
            "sender_email": "notice@portal.example.org",
            "subject": "Urgent action required",
        }
    )
    assert any(item["id"] == "urgent_language" for item in result["indicators"])


def test_keyword_matching_is_case_insensitive() -> None:
    matches = find_phrases("vErIfY ImMeDiAtElY", ["verify immediately"])
    assert matches == ["verify immediately"]


def test_generic_greeting_detection() -> None:
    result = analyse_email(
        {
            "sender_email": "notice@portal.example.org",
            "body": "Dear Account Holder,\nPlease review this message.",
        }
    )
    assert any(
        item["id"] == "generic_greeting" for item in result["indicators"]
    )


def test_password_and_otp_requests_are_separate_high_risk_rules() -> None:
    result = analyse_email(
        {
            "sender_email": "notice@portal.example.org",
            "body": "Reply with your PASSWORD and otp.",
        }
    )
    ids = {item["id"] for item in result["indicators"]}
    assert {"password_request", "otp_pin_request"} <= ids


def test_missing_sender_is_handled_without_error() -> None:
    result = analyse_email({})
    assert result["score"] >= 0
    assert any(item["id"] == "missing_sender" for item in result["indicators"])


def test_personalised_greeting_reduces_score_slightly() -> None:
    base = {
        "sender_email": "notice@portal.example.org",
        "recipient": "Ava Student",
        "subject": "Urgent action required",
    }
    generic = analyse_email({**base, "body": "Please act now."})
    personalised = analyse_email({**base, "body": "Hello Ava,\nPlease act now."})
    assert personalised["score"] == generic["score"] - 3


def test_safe_highlight_escapes_html_before_markup() -> None:
    rendered = safe_highlight("<script>alert(1)</script> urgent")
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert '<mark class="suspicious-phrase">urgent</mark>' in rendered


def test_excessive_formatting_detection() -> None:
    result = analyse_email(
        {
            "sender_email": "notice@portal.example.org",
            "body": "ACT NOW AND VERIFY YOUR ACCOUNT!!!!",
        }
    )
    assert any(
        item["id"] == "excessive_formatting"
        for item in result["indicators"]
    )
