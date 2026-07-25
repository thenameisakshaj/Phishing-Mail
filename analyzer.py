"""Transparent rule-based phishing risk analysis."""

from __future__ import annotations

import re
from email.utils import parseaddr
from typing import Mapping

from attachment_analyzer import analyse_attachment
from url_analyzer import analyse_url
from utils import find_phrases, normalise_form_data, safe_highlight


RISK_WEIGHTS: dict[str, int] = {
    "urgent_language": 10,
    "generic_greeting": 5,
    "password_request": 25,
    "otp_pin_request": 25,
    "banking_card_request": 25,
    "personal_information_request": 15,
    "suspicious_sender_domain": 15,
    "free_provider_company_sender": 10,
    "displayed_link_mismatch": 20,
    "http_url": 5,
    "ip_based_url": 15,
    "url_shortener": 10,
    "punycode_domain": 15,
    "excessive_subdomains": 10,
    "executable_attachment": 25,
    "macro_enabled_attachment": 15,
    "double_extension_attachment": 25,
    "prize_lottery_claim": 15,
    "account_suspension_threat": 15,
    "excessive_formatting": 5,
    "missing_sender": 15,
    "sender_identity_inconsistent": 8,
    "attachment_prompt": 8,
    "unrealistic_financial_offer": 15,
    "security_bypass_request": 15,
    "secrecy_pressure": 10,
    "emotional_manipulation": 8,
    "grammar_warning_patterns": 5,
    "click_prompt": 5,
    "artificial_deadline": 8,
}

SUBJECT_URGENCY_PHRASES = (
    "urgent action required",
    "verify immediately",
    "account suspended",
    "unusual login detected",
    "claim your reward",
    "payment failed",
    "security alert",
    "final warning",
    "limited-time offer",
    "confirm your identity",
    "reset your password now",
)
URGENT_BODY_PHRASES = (
    "urgent",
    "immediately",
    "act now",
    "final warning",
    "without delay",
    "failure to comply",
    "within 24 hours",
)
GENERIC_GREETINGS = (
    "dear customer",
    "dear user",
    "dear account holder",
    "valued member",
    "sir/madam",
    "attention user",
)
PASSWORD_PHRASES = (
    "password",
    "login credentials",
    "security answer",
    "security-answer",
    "recovery code",
)
OTP_PIN_PHRASES = ("otp", "one-time password", "pin")
BANKING_CARD_PHRASES = (
    "card details",
    "card number",
    "cvv",
    "bank details",
    "bank account",
    "banking details",
)
PERSONAL_INFORMATION_PHRASES = (
    "personal information",
    "aadhaar",
    "pan number",
    "date of birth",
    "identity document",
)

FREE_EMAIL_PROVIDERS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "mail.example",
}
SENDER_DOMAIN_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "security",
    "secure",
    "account",
    "support",
    "update",
    "check",
}
ORGANISATION_STOP_WORDS = {
    "team",
    "support",
    "security",
    "service",
    "services",
    "department",
    "office",
    "notification",
    "example",
    "student",
    "portal",
    "bank",
}


def _indicator(
    rule_id: str,
    category: str,
    title: str,
    explanation: str,
    action: str,
    matches: list[str] | None = None,
) -> dict[str, object]:
    return {
        "id": rule_id,
        "category": category,
        "title": title,
        "points": RISK_WEIGHTS[rule_id],
        "explanation": explanation,
        "action": action,
        "matches": matches or [],
    }


def classify_risk(score: int) -> str:
    """Map a capped score to the project's four risk categories."""
    if score >= 75:
        return "Critical Phishing Risk"
    if score >= 50:
        return "High Risk"
    if score >= 25:
        return "Suspicious"
    return "Low Risk"


def _component_level(points: int) -> str:
    if points >= 35:
        return "Critical"
    if points >= 20:
        return "High"
    if points > 0:
        return "Medium"
    return "Low"


def _sender_indicators(
    sender_name: str,
    sender_email: str,
) -> list[dict[str, object]]:
    indicators: list[dict[str, object]] = []
    parsed_email = parseaddr(sender_email)[1].casefold()

    if not parsed_email:
        indicators.append(
            _indicator(
                "missing_sender",
                "sender",
                "Missing sender address",
                "A message without a complete sender address cannot be reliably "
                "attributed.",
                "Ask for the message through a known, verified channel.",
            )
        )
        return indicators

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", parsed_email):
        indicators.append(
            _indicator(
                "suspicious_sender_domain",
                "sender",
                "Malformed sender address",
                "The sender address does not follow a normal email-address format.",
                "Do not reply; verify the sender independently.",
                [sender_email],
            )
        )
        return indicators

    local_part, domain = parsed_email.rsplit("@", 1)
    domain_labels = [label for label in domain.split(".") if label]
    prefix_labels = domain_labels[:-2] if len(domain_labels) >= 2 else domain_labels
    suspicious_words = sorted(
        word for word in SENDER_DOMAIN_KEYWORDS if word in domain
    )
    digit_substitution = bool(
        re.search(r"[A-Za-z][01][A-Za-z]|[01][A-Za-z]{2,}", domain)
    )
    hyphen_heavy = domain.count("-") >= 2
    suspicious_subdomains = len(prefix_labels) >= 3 and bool(suspicious_words)

    name_tokens = [
        token.casefold()
        for token in re.findall(r"[A-Za-z0-9]+", sender_name)
        if len(token) >= 4 and token.casefold() not in ORGANISATION_STOP_WORDS
    ]
    claimed_domain_mismatch = bool(
        name_tokens and not any(token in domain for token in name_tokens)
    )

    if (
        digit_substitution
        or hyphen_heavy
        or suspicious_subdomains
        or len(suspicious_words) >= 3
        or claimed_domain_mismatch
    ):
        reasons: list[str] = []
        if claimed_domain_mismatch:
            reasons.append("claimed organisation is not reflected in the domain")
        if digit_substitution:
            reasons.append("letter-like numeric substitution")
        if hyphen_heavy:
            reasons.append("multiple hyphens")
        if suspicious_subdomains:
            reasons.append("deep security-themed subdomains")
        if len(suspicious_words) >= 3:
            reasons.append("many trust-related words")
        indicators.append(
            _indicator(
                "suspicious_sender_domain",
                "sender",
                "Suspicious sender domain",
                "The domain shows warning patterns: " + ", ".join(reasons) + ".",
                "Compare the complete address with a known official address.",
                [domain],
            )
        )

    company_style_name = bool(
        re.search(
            r"\b(team|support|security|billing|service|services|bank|portal|"
            r"office|learning|school|company|community)\b",
            sender_name,
            re.IGNORECASE,
        )
    )
    if domain in FREE_EMAIL_PROVIDERS and company_style_name:
        indicators.append(
            _indicator(
                "free_provider_company_sender",
                "sender",
                "Company-style sender uses a free email provider",
                "The sender name sounds organisational, but the address uses a "
                "general-purpose mailbox provider.",
                "Verify the organisation's published contact domain.",
                [domain],
            )
        )

    personal_name_tokens = [
        token.casefold()
        for token in re.findall(r"[A-Za-z]+", sender_name)
        if len(token) >= 3
    ]
    if (
        len(personal_name_tokens) == 2
        and not company_style_name
        and not any(token in local_part for token in personal_name_tokens)
    ):
        indicators.append(
            _indicator(
                "sender_identity_inconsistent",
                "sender",
                "Sender name and mailbox appear inconsistent",
                "The personal display name is not reflected in the mailbox name.",
                "Confirm the sender using a known phone number or address.",
                [sender_name, local_part],
            )
        )

    return indicators


def _content_indicators(
    subject: str,
    body: str,
) -> list[dict[str, object]]:
    indicators: list[dict[str, object]] = []
    combined = f"{subject}\n{body}"

    urgent_hits = find_phrases(
        combined,
        SUBJECT_URGENCY_PHRASES + URGENT_BODY_PHRASES,
    )
    if urgent_hits:
        indicators.append(
            _indicator(
                "urgent_language",
                "content",
                "Urgent or threatening language",
                "The message pressures the reader to act before thinking or "
                "verifying.",
                "Pause and confirm the request through an independent channel.",
                urgent_hits,
            )
        )

    greeting_hits = find_phrases(body[:160], GENERIC_GREETINGS)
    if greeting_hits:
        indicators.append(
            _indicator(
                "generic_greeting",
                "content",
                "Generic greeting",
                "The message uses a broad greeting instead of identifying the "
                "recipient.",
                "Check whether the sender would normally know your name.",
                greeting_hits,
            )
        )

    password_hits = find_phrases(combined, PASSWORD_PHRASES)
    if password_hits:
        indicators.append(
            _indicator(
                "password_request",
                "content",
                "Password or recovery-secret request",
                "The message mentions credentials or recovery secrets that should "
                "never be shared by email.",
                "Do not provide credentials. Visit the service independently.",
                password_hits,
            )
        )

    otp_hits = find_phrases(combined, OTP_PIN_PHRASES)
    if otp_hits:
        indicators.append(
            _indicator(
                "otp_pin_request",
                "content",
                "OTP or PIN request",
                "One-time passwords and PINs can authorise access or transactions.",
                "Never share an OTP or PIN; contact the service directly.",
                otp_hits,
            )
        )

    banking_hits = find_phrases(combined, BANKING_CARD_PHRASES)
    if banking_hits:
        indicators.append(
            _indicator(
                "banking_card_request",
                "content",
                "Banking or card-information request",
                "The message asks about financial account or payment-card data.",
                "Do not reply. Contact the institution using its official number.",
                banking_hits,
            )
        )

    personal_hits = find_phrases(combined, PERSONAL_INFORMATION_PHRASES)
    if personal_hits:
        indicators.append(
            _indicator(
                "personal_information_request",
                "content",
                "Personal-information request",
                "Identity information can be abused for fraud or account recovery.",
                "Share personal data only through a verified, necessary process.",
                personal_hits,
            )
        )

    attachment_hits = find_phrases(
        body,
        (
            "open the attachment",
            "open attached",
            "see attachment",
            "download the attachment",
            "enable macros",
        ),
    )
    if attachment_hits:
        indicators.append(
            _indicator(
                "attachment_prompt",
                "content",
                "Prompt to open an attachment",
                "Unexpected attachment prompts are a common malware-delivery tactic.",
                "Verify the sender and file purpose before opening anything.",
                attachment_hits,
            )
        )

    suspension_hits = find_phrases(
        combined,
        (
            "account suspended",
            "account will be suspended",
            "account will be closed",
            "access will be blocked",
        ),
    )
    if suspension_hits:
        indicators.append(
            _indicator(
                "account_suspension_threat",
                "content",
                "Account-suspension threat",
                "The message threatens loss of access to force a rushed response.",
                "Check account status by opening the official service yourself.",
                suspension_hits,
            )
        )

    prize_hits = find_phrases(
        combined,
        ("claim your prize", "lottery winner", "you have won", "claim your reward"),
    )
    if prize_hits:
        indicators.append(
            _indicator(
                "prize_lottery_claim",
                "content",
                "Prize or lottery claim",
                "Unexpected rewards are frequently used to trigger curiosity and "
                "collect information.",
                "Do not pay fees or submit data for an unexpected prize.",
                prize_hits,
            )
        )

    financial_hits = find_phrases(
        combined,
        (
            "guaranteed return",
            "double your money",
            "risk-free investment",
            "instant profit",
            "transfer fee to receive",
        ),
    )
    if financial_hits:
        indicators.append(
            _indicator(
                "unrealistic_financial_offer",
                "content",
                "Unrealistic financial offer",
                "Guaranteed or extraordinary returns are a common fraud signal.",
                "Do not transfer money; seek independent financial verification.",
                financial_hits,
            )
        )

    letters = [character for character in body if character.isalpha()]
    uppercase_ratio = (
        sum(character.isupper() for character in letters) / len(letters)
        if letters
        else 0
    )
    if body.count("!") >= 4 or (len(letters) >= 20 and uppercase_ratio > 0.45):
        indicators.append(
            _indicator(
                "excessive_formatting",
                "content",
                "Excessive capitalisation or punctuation",
                "Heavy visual emphasis can be used to heighten panic or excitement.",
                "Ignore the pressure and evaluate the request calmly.",
            )
        )

    bypass_hits = find_phrases(
        body,
        (
            "disable antivirus",
            "bypass security",
            "ignore the warning",
            "approve the login",
            "turn off security",
        ),
    )
    if bypass_hits:
        indicators.append(
            _indicator(
                "security_bypass_request",
                "content",
                "Request to bypass security controls",
                "Legitimate support should not ask users to disable protections.",
                "Stop and report the request to your security contact.",
                bypass_hits,
            )
        )

    secrecy_hits = find_phrases(
        body,
        ("keep this secret", "do not tell anyone", "confidential between us"),
    )
    if secrecy_hits:
        indicators.append(
            _indicator(
                "secrecy_pressure",
                "content",
                "Pressure to act secretly",
                "Secrecy discourages the independent checks that could expose fraud.",
                "Discuss the request with a trusted colleague or authority.",
                secrecy_hits,
            )
        )

    emotional_hits = find_phrases(
        body,
        (
            "i need your help",
            "emergency",
            "your family",
            "disappointed in you",
            "trust me",
        ),
    )
    if emotional_hits:
        indicators.append(
            _indicator(
                "emotional_manipulation",
                "content",
                "Emotional manipulation",
                "The message uses fear, obligation, or sympathy to reduce scrutiny.",
                "Pause and verify the situation with another trusted person.",
                emotional_hits,
            )
        )

    grammar_hits = find_phrases(
        body,
        ("kindly do the needful", "your account have", "we has detected"),
    )
    if len(grammar_hits) >= 2:
        indicators.append(
            _indicator(
                "grammar_warning_patterns",
                "content",
                "Multiple grammar warning patterns",
                "Several unusual constructions may indicate an unauthentic message.",
                "Compare the writing style with previous verified messages.",
                grammar_hits,
            )
        )

    click_hits = find_phrases(body, ("click here", "click below", "use this link"))
    if click_hits:
        indicators.append(
            _indicator(
                "click_prompt",
                "content",
                "Unsolicited click prompt",
                "The message directs the reader toward a link instead of a known "
                "official route.",
                "Open the organisation's official site manually.",
                click_hits,
            )
        )

    deadline_hits = re.findall(
        r"\b(?:within|in the next)\s+\d{1,2}\s+"
        r"(?:minutes?|hours?|days?)\b|\bbefore midnight\b",
        combined,
        flags=re.IGNORECASE,
    )
    if deadline_hits:
        indicators.append(
            _indicator(
                "artificial_deadline",
                "content",
                "Artificial deadline",
                "A short deadline creates time pressure that discourages checking.",
                "Do not let the stated deadline replace independent verification.",
                deadline_hits,
            )
        )

    return indicators


def _personalised_greeting(body: str, recipient: str) -> bool:
    if not body or not recipient:
        return False
    recipient_name = recipient.split("@", 1)[0].strip()
    first_token_match = re.search(r"[A-Za-z]{2,}", recipient_name)
    if not first_token_match:
        return False
    first_name = re.escape(first_token_match.group(0))
    return bool(
        re.search(
            rf"^\s*(?:dear|hello|hi)\s+{first_name}\b",
            body,
            re.IGNORECASE,
        )
    )


def analyse_email(data: Mapping[str, object]) -> dict[str, object]:
    """Analyse a fictional email sample and return an explainable risk result."""
    cleaned = normalise_form_data(data)
    sender_items = _sender_indicators(
        cleaned["sender_name"],
        cleaned["sender_email"],
    )
    content_items = _content_indicators(cleaned["subject"], cleaned["body"])
    url_result = analyse_url(
        cleaned["actual_url"],
        cleaned["displayed_link"],
    )
    attachment_result = analyse_attachment(cleaned["attachment_filename"])

    indicators = (
        sender_items
        + content_items
        + list(url_result["indicators"])
        + list(attachment_result["indicators"])
    )
    raw_score = sum(int(item["points"]) for item in indicators)

    mitigations: list[dict[str, object]] = []
    mitigation_points = 0
    if _personalised_greeting(cleaned["body"], cleaned["recipient"]):
        mitigation_points = 3
        mitigations.append(
            {
                "title": "Personalised greeting",
                "points": -3,
                "explanation": "The greeting matches the entered recipient. This "
                "slightly lowers risk but does not prove legitimacy.",
            }
        )

    score = min(100, max(0, raw_score - mitigation_points))
    component_points = {
        category: sum(
            int(item["points"])
            for item in indicators
            if item["category"] == category
        )
        for category in ("sender", "content", "url", "attachment")
    }
    component_risks = {
        category: {
            "points": points,
            "level": (
                attachment_result["risk_level"]
                if category == "attachment"
                else _component_level(points)
            ),
        }
        for category, points in component_points.items()
    }

    matched_phrases = tuple(
        str(match)
        for item in content_items
        for match in item.get("matches", [])
        if match
    )

    return {
        "score": score,
        "raw_score": raw_score,
        "risk_category": classify_risk(score),
        "indicator_count": len(indicators),
        "indicators": indicators,
        "mitigations": mitigations,
        "components": component_risks,
        "highlighted_body": safe_highlight(
            cleaned["body"],
            matched_phrases or (),
        ),
        "url": url_result,
        "attachment": attachment_result,
        "input": cleaned,
        "confidence_note": (
            "This score is a transparent heuristic for education. It is not a "
            "definitive verdict and cannot guarantee that an email is safe or "
            "malicious."
        ),
    }
