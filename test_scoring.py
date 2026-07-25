"""Tests for score calculation and category mapping."""

from analyzer import analyse_email, classify_risk


def test_risk_category_boundaries() -> None:
    assert classify_risk(0) == "Low Risk"
    assert classify_risk(24) == "Low Risk"
    assert classify_risk(25) == "Suspicious"
    assert classify_risk(49) == "Suspicious"
    assert classify_risk(50) == "High Risk"
    assert classify_risk(74) == "High Risk"
    assert classify_risk(75) == "Critical Phishing Risk"
    assert classify_risk(100) == "Critical Phishing Risk"


def test_score_is_capped_at_100() -> None:
    result = analyse_email(
        {
            "sender_name": "Security Team",
            "sender_email": "support@security-login-check.example.net",
            "subject": "URGENT ACTION REQUIRED - ACCOUNT SUSPENDED",
            "body": (
                "Dear User, ACT NOW!!!! Send your password, OTP, PIN, card "
                "number, CVV, Aadhaar number and bank details. Click here, "
                "open the attachment, keep this secret, and disable antivirus."
            ),
            "displayed_link": "https://portal.example.org",
            "actual_url": "http://198.51.100.42/login.exe?redirect=x",
            "attachment_filename": "invoice.pdf.exe",
        }
    )
    assert result["raw_score"] > 100
    assert result["score"] == 100


def test_single_password_request_contributes_configured_points() -> None:
    result = analyse_email(
        {
            "sender_email": "notice@portal.example.org",
            "body": "Please send your password.",
        }
    )
    password_item = next(
        item for item in result["indicators"] if item["id"] == "password_request"
    )
    assert password_item["points"] == 25


def test_component_scores_equal_indicator_points_by_category() -> None:
    result = analyse_email(
        {
            "sender_email": "notice@portal.example.org",
            "body": "Dear Customer, please send your OTP.",
            "attachment_filename": "notice.docm",
        }
    )
    for category, component in result["components"].items():
        expected = sum(
            item["points"]
            for item in result["indicators"]
            if item["category"] == category
        )
        assert component["points"] == expected
