from detector import analyze_url


BENIGN_URLS = [
    "https://google.com",
    "https://github.com",
    "https://microsoft.com",
    "https://amazon.com",
    "https://wikipedia.org",
    "https://python.org",
    "https://openai.com",
    "https://cloudflare.com",
]


SUSPICIOUS_URLS = [
    "http://paypal-secure-login.example.com/verify",
    "http://microsoft-login.example.net/account/verify",
    "http://apple-id-confirm.example.org/login",
]


def test_benign_urls_have_low_ml_signal():

    for url in BENIGN_URLS:

        result = analyze_url(url)

        assert result["ml_probability"] is not None

        assert result["ml_probability"] < 0.30, (
            f"{url} got unexpectedly high ML risk: "
            f"{result['ml_probability']}"
        )


def test_synthetic_phishing_has_high_ml_signal():

    for url in SUSPICIOUS_URLS:

        result = analyze_url(url)

        assert result["ml_probability"] is not None

        assert result["ml_probability"] > 0.70, (
            f"{url} got unexpectedly low ML risk: "
            f"{result['ml_probability']}"
        )


def test_brand_impersonation():

    result = analyze_url(
        "http://microsoft-login.example.net/account/verify"
    )

    assert result["domain_score"] >= 20

    reasons = " ".join(
        result["reasons"]
    ).lower()

    assert "microsoft" in reasons


def test_ip_url_rule():

    result = analyze_url(
        "http://8.8.8.8/verify/account/login"
    )

    assert result["rule_score"] >= 30


def test_normal_url_rules():

    result = analyze_url(
        "https://google.com"
    )

    assert result["rule_score"] == 0
    assert result["domain_score"] == 0