"""Tests for offline URL inspection."""

from url_analyzer import analyse_url


def _ids(result: dict[str, object]) -> set[str]:
    return {str(item["id"]) for item in result["indicators"]}


def test_http_url_detection() -> None:
    assert "http_url" in _ids(analyse_url("http://portal.example.org"))


def test_ip_address_url_detection() -> None:
    result = analyse_url("https://198.51.100.42/check")
    assert "ip_based_url" in _ids(result)


def test_suspicious_subdomain_detection() -> None:
    result = analyse_url(
        "https://login.verify.account.portal.example.org/check"
    )
    assert "excessive_subdomains" in _ids(result)


def test_displayed_link_and_actual_domain_mismatch() -> None:
    result = analyse_url(
        "https://destination.example.net/document",
        "https://portal.example.org/document",
    )
    assert "displayed_link_mismatch" in _ids(result)


def test_related_subdomains_do_not_trigger_mismatch() -> None:
    result = analyse_url(
        "https://learn.northstar.example.org/course",
        "https://northstar.example.org",
    )
    assert "displayed_link_mismatch" not in _ids(result)


def test_punycode_detection() -> None:
    result = analyse_url("https://xn--fictional-9za.example.org")
    assert "punycode_domain" in _ids(result)


def test_nonstandard_port_and_redirect_parameter() -> None:
    result = analyse_url(
        "https://portal.example.org:8443/check?redirect=https%3A%2F%2Fexample.invalid"
    )
    assert {"non_standard_port", "redirect_parameter"} <= _ids(result)


def test_empty_url_has_no_indicators() -> None:
    result = analyse_url("")
    assert result["indicators"] == []
    assert result["points"] == 0
