def calculate_final_risk(
    ml_probability,
    rule_score,
    domain_score,
    virustotal,
    domain_age=None
):
    ml_score = (
        ml_probability * 100
        if ml_probability is not None
        else 0
    )

    base_score = (
        0.45 * ml_score
        + 0.30 * rule_score
        + 0.25 * domain_score
    )

    reasons = []


    # ==========================================
    # DOMAIN AGE
    # ==========================================

    if domain_age is not None:

        if domain_age < 7:
            base_score += 20

            reasons.append(
                f"Domain is extremely new "
                f"({domain_age} days old)"
            )

        elif domain_age < 30:
            base_score += 15

            reasons.append(
                f"Domain was registered recently "
                f"({domain_age} days old)"
            )

        elif domain_age < 180:
            base_score += 7

            reasons.append(
                f"Domain is relatively new "
                f"({domain_age} days old)"
            )


    # ==========================================
    # MULTIPLE LOCAL SIGNALS AGREE
    # ==========================================

    if (
        ml_score >= 90
        and rule_score >= 15
        and domain_score >= 20
    ):
        base_score = max(
            base_score,
            70
        )

        reasons.append(
            "Multiple phishing indicators strongly agree"
        )


    # ==========================================
    # VIRUSTOTAL
    # ==========================================

    if (
        virustotal
        and virustotal.get("found")
    ):

        malicious = virustotal.get(
            "malicious",
            0
        )

        suspicious = virustotal.get(
            "suspicious",
            0
        )

        harmless = virustotal.get(
            "harmless",
            0
        )


        if malicious >= 5:

            base_score = max(
                base_score,
                85
            )

            reasons.append(
                f"VirusTotal: {malicious} security engines "
                "flagged this URL as malicious"
            )


        elif malicious >= 2:

            base_score = max(
                base_score,
                65
            )

            reasons.append(
                f"VirusTotal: {malicious} security engines "
                "flagged this URL"
            )


        elif malicious == 1:

            base_score += 5

            reasons.append(
                "VirusTotal: 1 engine reported this URL; "
                "a single detection may be a false positive"
            )


        if suspicious >= 2:

            base_score += 10

            reasons.append(
                "Multiple VirusTotal engines marked "
                "the URL as suspicious"
            )


        # Strong benign reputation.
        # Only apply when ALL local signals are weak.

        if (
            harmless >= 20
            and malicious <= 1
            and rule_score < 20
            and domain_score < 20
            and ml_score < 30
        ):

            base_score = min(
                base_score,
                20
            )

            reasons.append(
                "Strong benign reputation with no major "
                "local phishing indicators"
            )


    final_score = max(
        0,
        min(round(base_score), 100)
    )


    return (
        final_score,
        reasons
    )