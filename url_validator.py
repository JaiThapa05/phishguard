from urllib.parse import urlparse
import ipaddress


ALLOWED_SCHEMES = {
    "http",
    "https"
}


def validate_url(url):
    """
    Returns:
        (True, normalized_url, None)
    or:
        (False, None, error_message)
    """

    if not isinstance(url, str):
        return False, None, "Invalid URL"

    url = url.strip()

    # Empty URL
    if not url:
        return False, None, "Please enter a URL"

    # Limit input size
    if len(url) > 2048:
        return (
            False,
            None,
            "URL is too long"
        )

    # Reject control characters
    if any(
        ord(char) < 32
        for char in url
    ):
        return (
            False,
            None,
            "URL contains invalid characters"
        )

    # Add scheme when user enters google.com
    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return (
            False,
            None,
            "Invalid URL format"
        )

    # Only HTTP/HTTPS
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return (
            False,
            None,
            "Only HTTP and HTTPS URLs are allowed"
        )

    hostname = parsed.hostname

    if not hostname:
        return (
            False,
            None,
            "URL does not contain a valid hostname"
        )

    hostname = hostname.lower().rstrip(".")

    # Credentials inside URL
    if parsed.username or parsed.password:
        return (
            False,
            None,
            "URLs containing embedded credentials are not allowed"
        )

    # localhost
    if (
        hostname == "localhost"
        or hostname.endswith(".localhost")
    ):
        return (
            False,
            None,
            "Local addresses are not allowed"
        )

    # Check direct IP addresses
    try:
        ip = ipaddress.ip_address(hostname)

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return (
                False,
                None,
                "Private or local IP addresses are not allowed"
            )

    except ValueError:
        # Hostname is a domain, not an IP
        pass

    # Domain must contain a dot.
    # Example: google.com
    if "." not in hostname:
        return (
            False,
            None,
            "Please enter a valid domain name"
        )

    return (
        True,
        url,
        None
    )