import math
from urllib.parse import urlparse

import tldextract
from rapidfuzz.fuzz import ratio


POPULAR_BRANDS = [
    "google",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "facebook",
    "instagram",
    "netflix",
    "linkedin",
    "github",
    "dropbox",
    "adobe",
    "coinbase"
]


def entropy(text):
    if not text:
        return 0.0

    result = 0.0

    for char in set(text):
        probability = text.count(char) / len(text)
        result -= probability * math.log2(probability)

    return round(result, 2)


def analyze_domain(url):
    try:
        normalized_url = str(url).strip()

        if not normalized_url.startswith(
            ("http://", "https://")
        ):
            normalized_url = "http://" + normalized_url

        parsed = urlparse(normalized_url)
        hostname = (parsed.hostname or "").lower()

        # Important: hostname analyze karo, full URL nahi
        extracted = tldextract.extract(hostname)

        domain = (extracted.domain or "").lower()
        suffix = (extracted.suffix or "").lower()
        subdomain = (extracted.subdomain or "").lower()

        registered_domain = domain

        if suffix:
            registered_domain = f"{domain}.{suffix}"

        risk = 0
        reasons = []

        if "xn--" in hostname:
            risk += 25
            reasons.append(
                "Punycode/IDN domain detected"
            )

        if domain.count("-") >= 2:
            risk += 10
            reasons.append(
                "Domain contains multiple hyphens"
            )

        if any(char.isdigit() for char in domain):
            risk += 7
            reasons.append(
                "Domain contains numbers"
            )

        if len(domain) > 25:
            risk += 8
            reasons.append(
                "Domain name is unusually long"
            )

        domain_entropy = entropy(domain)

        if (
            domain_entropy > 3.8
            and len(domain) > 12
        ):
            risk += 10
            reasons.append(
                "Domain has a random-looking pattern"
            )

        if subdomain.count(".") >= 2:
            risk += 10
            reasons.append(
                "Multiple subdomain levels detected"
            )

        normalized_domain = (
            domain
            .replace("0", "o")
            .replace("1", "l")
            .replace("3", "e")
            .replace("5", "s")
            .replace("7", "t")
        )

        # Lookalike brand detection
        for brand in POPULAR_BRANDS:
            similarity = ratio(
                normalized_domain,
                brand
            )

            if (
                similarity >= 75
                and normalized_domain != brand
            ):
                risk += 25

                reasons.append(
                    f"Domain resembles the brand '{brand}'"
                )

                break

        # Brand placed inside deceptive subdomain
        for brand in POPULAR_BRANDS:
            if (
                brand in subdomain
                and domain != brand
            ):
                risk += 20

                reasons.append(
                    f"Brand '{brand}' appears in a subdomain"
                )

                break

        return {
            "registered_domain": registered_domain,
            "subdomain": subdomain,
            "domain_entropy": domain_entropy,
            "domain_risk": min(risk, 100),
            "domain_reasons": reasons
        }

    except Exception as error:
        print("Domain analyzer error:", error)

        # Scanner ko crash nahi hone denge
        return {
            "registered_domain": "",
            "subdomain": "",
            "domain_entropy": 0,
            "domain_risk": 0,
            "domain_reasons": []
        }