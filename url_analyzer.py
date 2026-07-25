"""Offline URL inspection for the PhishGuard educational application."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qs, urlparse


URL_WEIGHTS: dict[str, int] = {
    "displayed_link_mismatch": 20,
    "http_url": 5,
    "ip_based_url": 15,
    "long_url": 5,
    "url_shortener": 10,
    "excessive_subdomains": 10,
    "at_symbol": 10,
    "encoded_characters": 5,
    "numeric_substitution": 5,
    "hyphen_heavy_domain": 8,
    "suspicious_extension": 15,
    "punycode_domain": 15,
    "non_standard_port": 10,
    "redirect_parameter": 8,
    "suspicious_url_keyword": 5,
    "malformed_url": 5,
}

SHORTENER_HOSTS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "ow.ly",
    "short.example",
}
SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "banking",
    "password",
    "authentication",
    "confirm",
}
SUSPICIOUS_FILE_EXTENSIONS = {
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
REDIRECT_PARAMETERS = {
    "redirect",
    "redirect_url",
    "return",
    "return_url",
    "next",
    "continue",
    "destination",
    "dest",
    "url",
}


def _indicator(
    rule_id: str,
    title: str,
    explanation: str,
    action: str,
    matches: list[str] | None = None,
) -> dict[str, object]:
    return {
        "id": rule_id,
        "category": "url",
        "title": title,
        "points": URL_WEIGHTS[rule_id],
        "explanation": explanation,
        "action": action,
        "matches": matches or [],
    }


def _normalise_url_for_parsing(value: str) -> tuple[str, bool]:
    value = value.strip()
    if not value:
        return "", False
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value):
        return value, True
    return "https://" + value, False


def _extract_displayed_hostname(displayed_link: str) -> str:
    candidate = displayed_link.strip()
    if not candidate:
        return ""
    match = re.search(
        r"(?:https?://)?([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d+)?",
        candidate,
        re.IGNORECASE,
    )
    return match.group(1).lower().strip(".") if match else ""


def _hosts_are_related(first: str, second: str) -> bool:
    return (
        first == second
        or first.endswith("." + second)
        or second.endswith("." + first)
    )


def analyse_url(actual_url: str, displayed_link: str = "") -> dict[str, object]:
    """Inspect URL text without opening, resolving, or requesting it."""
    if not actual_url.strip():
        return {
            "indicators": [],
            "points": 0,
            "hostname": "",
            "risk_level": "Low",
        }

    parse_target, had_scheme = _normalise_url_for_parsing(actual_url)
    parsed = urlparse(parse_target)
    hostname = (parsed.hostname or "").lower().strip(".")
    indicators: list[dict[str, object]] = []

    if not had_scheme or not hostname:
        indicators.append(
            _indicator(
                "malformed_url",
                "Incomplete or malformed URL",
                "The link does not include a clear, standard URL structure.",
                "Ask for a complete link and verify it through an official source.",
            )
        )

    if parsed.scheme.lower() == "http":
        indicators.append(
            _indicator(
                "http_url",
                "Unencrypted HTTP link",
                "The link uses HTTP rather than HTTPS. Encryption alone does not "
                "prove safety, but its absence increases exposure.",
                "Do not enter information. Navigate through the official site.",
            )
        )

    if hostname:
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            is_ip = False
        else:
            is_ip = True
        if is_ip:
            indicators.append(
                _indicator(
                    "ip_based_url",
                    "IP address used as the destination",
                    "The URL uses a numeric IP address instead of a recognisable "
                    "domain name.",
                    "Avoid the link and verify the destination independently.",
                    [hostname],
                )
            )

    if len(actual_url) > 100:
        indicators.append(
            _indicator(
                "long_url",
                "Excessively long URL",
                "Long URLs can hide the real destination among many characters.",
                "Inspect the hostname carefully before taking any action.",
            )
        )

    if hostname in SHORTENER_HOSTS:
        indicators.append(
            _indicator(
                "url_shortener",
                "URL-shortening service detected",
                "Shortened links conceal the final destination.",
                "Do not expand the link from the message; verify through an "
                "official channel.",
                [hostname],
            )
        )

    labels = [label for label in hostname.split(".") if label]
    subdomain_count = max(0, len(labels) - 2)
    if subdomain_count >= 3:
        indicators.append(
            _indicator(
                "excessive_subdomains",
                "Excessive subdomain depth",
                "Many subdomains can be used to make an unrelated destination "
                "look trustworthy.",
                "Read the domain from right to left and verify the registered "
                "domain.",
            )
        )

    authority = actual_url.split("/", 3)[2] if "://" in actual_url else actual_url.split("/", 1)[0]
    if "@" in authority:
        indicators.append(
            _indicator(
                "at_symbol",
                "@ symbol in the URL authority",
                "Text before an @ symbol may distract from the true destination.",
                "Treat the hostname after the @ symbol as the actual destination.",
            )
        )

    if "%" in actual_url or any(ord(character) > 127 for character in actual_url):
        indicators.append(
            _indicator(
                "encoded_characters",
                "Encoded or unusual URL characters",
                "Encoding or non-ASCII characters can make a destination harder "
                "to inspect.",
                "Do not use the link until its destination is independently verified.",
            )
        )

    if re.search(r"[A-Za-z][01][A-Za-z]|[01][A-Za-z]{2,}", hostname):
        indicators.append(
            _indicator(
                "numeric_substitution",
                "Possible look-alike spelling",
                "The domain mixes letters with 0 or 1, which can imitate similar "
                "letters.",
                "Compare every character with a known official domain.",
                [hostname],
            )
        )

    if hostname.count("-") >= 3:
        indicators.append(
            _indicator(
                "hyphen_heavy_domain",
                "Hyphen-heavy domain",
                "An unusually high number of hyphens can signal an imitation "
                "domain assembled from trust-related words.",
                "Verify the exact domain using an official source.",
                [hostname],
            )
        )

    lowered_path = parsed.path.casefold()
    matched_extension = next(
        (
            extension
            for extension in SUSPICIOUS_FILE_EXTENSIONS
            if lowered_path.endswith(extension)
        ),
        "",
    )
    if matched_extension:
        indicators.append(
            _indicator(
                "suspicious_extension",
                "Suspicious file extension in URL",
                f"The URL path appears to reference a {matched_extension} file.",
                "Do not download it; ask the sender to use a verified safe channel.",
                [matched_extension],
            )
        )

    if any(label.startswith("xn--") for label in labels):
        indicators.append(
            _indicator(
                "punycode_domain",
                "Punycode domain detected",
                "Punycode can represent international characters and may also be "
                "used for visually confusing domains.",
                "Inspect the decoded domain with a trusted security tool.",
                [hostname],
            )
        )

    try:
        port = parsed.port
    except ValueError:
        port = -1
    if port not in (None, 80, 443):
        indicators.append(
            _indicator(
                "non_standard_port",
                "Non-standard network port",
                f"The URL specifies port {port}, which is unusual for a normal "
                "web link.",
                "Avoid the link and confirm the service through official support.",
            )
        )

    query_keys = {key.casefold() for key in parse_qs(parsed.query)}
    redirect_hits = sorted(query_keys & REDIRECT_PARAMETERS)
    if redirect_hits:
        indicators.append(
            _indicator(
                "redirect_parameter",
                "Redirect-like query parameter",
                "The link contains a parameter that may forward the browser to "
                "another destination.",
                "Verify both the visible domain and any embedded destination.",
                redirect_hits,
            )
        )

    keyword_hits = sorted(
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in (hostname + parsed.path).casefold()
    )
    if keyword_hits:
        indicators.append(
            _indicator(
                "suspicious_url_keyword",
                "Security-sensitive words in URL",
                "The link uses login or verification language often seen in "
                "social-engineering messages.",
                "Open the service independently instead of using the message link.",
                keyword_hits,
            )
        )

    displayed_hostname = _extract_displayed_hostname(displayed_link)
    if (
        displayed_hostname
        and hostname
        and not _hosts_are_related(displayed_hostname, hostname)
    ):
        indicators.append(
            _indicator(
                "displayed_link_mismatch",
                "Displayed link and destination mismatch",
                f"The visible link refers to {displayed_hostname}, but the actual "
                f"destination is {hostname}.",
                "Do not open the link. Navigate to the expected site manually.",
                [displayed_hostname, hostname],
            )
        )

    points = sum(int(item["points"]) for item in indicators)
    if points >= 35:
        level = "Critical"
    elif points >= 20:
        level = "High"
    elif points > 0:
        level = "Medium"
    else:
        level = "Low"

    return {
        "indicators": indicators,
        "points": points,
        "hostname": hostname,
        "risk_level": level,
    }
