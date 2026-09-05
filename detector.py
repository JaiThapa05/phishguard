from urllib.parse import urlparse
import re
import joblib

from domain_analyzer import analyze_domain


# ==========================================
# LOAD V3 ML MODEL
# ==========================================

try:
    model = joblib.load("url_model_v3.pkl")
    print("V3 URL model loaded successfully!")

except Exception as e:
    print("V3 model load error:", e)
    model = None


# ==========================================
# URL ANALYZER
# ==========================================

def analyze_url(url):

    original_url = str(url).strip()

    if not original_url:

        return {
            "url": "",
            "status": "Invalid URL",
            "score": 100,
            "rule_score": 100,
            "domain_score": 0,
            "ml_probability": None,
            "reasons": [
                "URL is empty"
            ]
        }


    # ==========================================
    # NORMALIZE URL
    # ==========================================

    if not original_url.startswith(
        ("http://", "https://")
    ):

        parsed_url = (
            "http://" + original_url
        )

    else:

        parsed_url = original_url


    try:

        parsed = urlparse(
            parsed_url
        )

        domain = (
            parsed.hostname or ""
        ).lower()

    except Exception:

        domain = ""


    # ==========================================
    # RULE ENGINE
    # ==========================================

    rule_score = 0

    reasons = []


    # IP address instead of domain

    if re.fullmatch(
        r"(?:\d{1,3}\.){3}\d{1,3}",
        domain
    ):

        rule_score += 30

        reasons.append(
            "IP address is used instead of a normal domain"
        )


    # @ symbol

    if "@" in original_url:

        rule_score += 20

        reasons.append(
            "URL contains @ symbol"
        )


    # Very long URL

    if len(original_url) > 100:

        rule_score += 15

        reasons.append(
            "URL is unusually long"
        )


    # Too many subdomains

    if domain.count(".") >= 3:

        rule_score += 15

        reasons.append(
            "Domain contains many subdomains"
        )


    # Punycode

    if "xn--" in domain:

        rule_score += 20

        reasons.append(
            "Domain uses Punycode / IDN encoding"
        )


    # ==========================================
    # SUSPICIOUS KEYWORDS
    # ==========================================

    suspicious_words = [

        "verify",
        "account",
        "update",
        "secure",
        "banking",
        "password",
        "signin",
        "login",
        "confirm",
        "wallet",
        "suspend",
        "unlock"

    ]


    matches = [

        word

        for word
        in suspicious_words

        if word
        in original_url.lower()

    ]


    if matches:

        points = min(
            len(matches) * 5,
            20
        )

        rule_score += points

        reasons.append(
            "Suspicious keywords: "
            + ", ".join(matches)
        )


    rule_score = min(
        rule_score,
        100
    )


    # ==========================================
    # DOMAIN ANALYSIS
    # ==========================================

    domain_analysis = analyze_domain(
        original_url
    )


    domain_score = (
        domain_analysis.get(
            "domain_risk",
            0
        )
    )


    domain_reasons = (
        domain_analysis.get(
            "domain_reasons",
            []
        )
    )


    for reason in domain_reasons:

        if reason not in reasons:

            reasons.append(
                reason
            )


    # ==========================================
    # V3 MACHINE LEARNING MODEL
    # ==========================================

    ml_probability = None


    if model is not None:

        try:

            probability = (
                model.predict_proba(
                    [original_url.lower()]
                )[0][1]
            )


            ml_probability = float(
                probability
            )


            reasons.append(

                "ML phishing risk signal: "
                f"{round(ml_probability * 100)}%"

            )


        except Exception as e:

            print(
                "V3 ML prediction error:",
                e
            )


    # ==========================================
    # TEMPORARY LOCAL SCORE
    # ==========================================
    #
    # app.py / risk_engine.py will later combine
    # this with VirusTotal.
    #

    ml_score = (

        ml_probability * 100

        if ml_probability is not None

        else 0

    )


    score = round(

        0.45 * ml_score
        + 0.30 * rule_score
        + 0.25 * domain_score

    )


    score = max(
        0,
        min(score, 100)
    )


    # ==========================================
    # INITIAL STATUS
    # ==========================================

    if score >= 70:

        status = (
            "Likely Phishing"
        )


    elif score >= 35:

        status = (
            "Suspicious"
        )


    else:

        status = (
            "Low Risk"
        )


    # ==========================================
    # FALLBACK EXPLANATION
    # ==========================================

    if not reasons:

        reasons.append(
            "No obvious phishing indicators detected"
        )


    # ==========================================
    # RESPONSE
    # ==========================================

    return {

        "url":
            original_url,

        "status":
            status,

        "score":
            score,

        "rule_score":
            rule_score,

        "domain_score":
            domain_score,

        "domain":
            domain_analysis.get(
                "registered_domain",
                domain
            ),

        "ml_probability":
            ml_probability,

        "reasons":
            reasons

    }