import requests
from datetime import datetime, timezone
from functools import lru_cache


@lru_cache(maxsize=1000)
def check_domain_age(domain):
    domain = str(domain).strip().lower()

    if not domain:
        return {
            "available": False,
            "age_days": None,
            "age_years": None,
            "age_text": "Unknown",
            "created": None
        }

    try:
        response = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=8,
            headers={
                "User-Agent": "PhishGuard/1.0"
            }
        )

        if response.status_code != 200:
            return {
                "available": False,
                "age_days": None,
                "age_years": None,
                "age_text": "Unknown",
                "created": None
            }

        data = response.json()

        created_string = None

        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                created_string = event.get("eventDate")
                break

        if not created_string:
            return {
                "available": True,
                "age_days": None,
                "age_years": None,
                "age_text": "Unknown",
                "created": None
            }

        created = datetime.fromisoformat(
            created_string.replace("Z", "+00:00")
        )

        now = datetime.now(timezone.utc)

        age_days = (now - created).days

        # Exact completed calendar years
        age_years = now.year - created.year

        if (
            now.month,
            now.day
        ) < (
            created.month,
            created.day
        ):
            age_years -= 1

        # Human-readable age
        if age_days < 0:
            age_text = "Unknown"

        elif age_days < 30:
            age_text = f"{age_days} days"

        elif age_days < 365:
            months = max(
                1,
                (
                    (now.year - created.year) * 12
                    + now.month
                    - created.month
                )
            )

            age_text = f"{months} months"

        else:
            age_text = f"{age_years} years"

        return {
            "available": True,

            "age_days": age_days,

            "age_years": age_years,

            "age_text": age_text,

            "created": created.date().isoformat()
        }

    except Exception as e:
        print(
            f"RDAP error for {domain}:",
            e
        )

        return {
            "available": False,
            "age_days": None,
            "age_years": None,
            "age_text": "Unknown",
            "created": None
        }