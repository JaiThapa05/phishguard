from url_validator import validate_url


def test_google_is_valid():

    valid, url, error = validate_url(
        "google.com"
    )

    assert valid is True
    assert url == "https://google.com"
    assert error is None


def test_https_url_is_valid():

    valid, url, error = validate_url(
        "https://github.com"
    )

    assert valid is True


def test_localhost_rejected():

    valid, _, _ = validate_url(
        "http://localhost:5000"
    )

    assert valid is False


def test_private_ip_rejected():

    valid, _, _ = validate_url(
        "http://192.168.1.1"
    )

    assert valid is False


def test_file_scheme_rejected():

    valid, _, _ = validate_url(
        "file:///etc/passwd"
    )

    assert valid is False


def test_javascript_scheme_rejected():

    valid, _, _ = validate_url(
        "javascript://example.com"
    )

    assert valid is False


def test_ftp_rejected():

    valid, _, _ = validate_url(
        "ftp://example.com"
    )

    assert valid is False