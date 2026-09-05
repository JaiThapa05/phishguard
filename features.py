from urllib.parse import urlparse
import re

SUSPICIOUS_WORDS = [
    "verify", "account", "update", "secure", "banking",
    "password", "signin", "login", "confirm", "paypal",
    "ebay", "wallet", "free", "bonus", "suspend",
    "unlock", "webscr", "cmd"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co",
    "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"
]


def extract_features(url):
    # URL ko safely string me convert karo
    if url is None:
        url = ""

    url = str(url).strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        parsed = urlparse("http://invalid")

    # Hostname safely nikalo
    try:
        domain = (parsed.hostname or "").lower()
    except ValueError:
        domain = ""

    path = parsed.path or ""
    lower = url.lower()

    # Port safely check karo
    try:
        has_port = int(parsed.port is not None)
    except ValueError:
        has_port = 1

    # IP detection
    try:
        has_ip = int(
            bool(
                re.fullmatch(
                    r"(?:\d{1,3}\.){3}\d{1,3}",
                    domain
                )
            )
        )
    except Exception:
        has_ip = 0

    return {
        "url_length": len(url),
        "domain_length": len(domain),
        "path_length": len(path),

        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),

        "num_digits": sum(c.isdigit() for c in url),

        "num_query_params":
            lower.count("&") + (1 if "?" in url else 0),

        "num_special_chars":
            sum(c in "%=?&#~" for c in url),

        "has_at": int("@" in url),

        "has_ip": has_ip,

        "num_subdomains":
            max(domain.count(".") - 1, 0),

        "has_punycode":
            int("xn--" in domain),

        "is_shortener":
            int(domain in SHORTENERS),

        "suspicious_word_count":
            sum(word in lower for word in SUSPICIOUS_WORDS),

        "has_port": has_port,

        "double_slash_in_path":
            int("//" in path),

        "has_exe_or_zip":
            int(
                bool(
                    re.search(
                        r"\.(exe|zip|scr|apk)$",
                        path.lower()
                    )
                )
            ),

        "domain_has_digits":
            int(any(c.isdigit() for c in domain)),
    }


FEATURE_NAMES = list(
    extract_features("http://example.com").keys()
)