import os
import base64

import requests

from dotenv import load_dotenv
from cachetools import TTLCache


# ==========================================
# ENVIRONMENT
# ==========================================

load_dotenv()

API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY"
)


# ==========================================
# CACHE
# 30 minutes
# ==========================================

vt_cache = TTLCache(
    maxsize=1000,
    ttl=1800
)


# ==========================================
# VIRUSTOTAL CHECK
# ==========================================

def check_virustotal(url):

    url = str(url).strip()


    # ------------------------------------------
    # API KEY
    # ------------------------------------------

    if not API_KEY:

        return {
            "available": False,
            "found": False,
            "error": (
                "VirusTotal API key "
                "is not configured"
            ),
            "cached": False
        }


    # ------------------------------------------
    # CACHE LOOKUP
    # ------------------------------------------

    if url in vt_cache:

        cached_result = (
            vt_cache[url].copy()
        )

        cached_result["cached"] = True

        print(
            "VirusTotal cache hit:",
            url
        )

        return cached_result


    # ------------------------------------------
    # CREATE VIRUSTOTAL URL ID
    # ------------------------------------------

    try:

        url_id = (
            base64
            .urlsafe_b64encode(
                url.encode("utf-8")
            )
            .decode("utf-8")
            .rstrip("=")
        )


        endpoint = (
            "https://www.virustotal.com"
            f"/api/v3/urls/{url_id}"
        )


        # ------------------------------------------
        # API REQUEST
        # ------------------------------------------

        response = requests.get(

            endpoint,

            headers={
                "x-apikey": API_KEY
            },

            timeout=10
        )


        # ------------------------------------------
        # URL NOT FOUND
        # ------------------------------------------

        if response.status_code == 404:

            result = {
                "available": True,
                "found": False,
                "message": (
                    "No existing VirusTotal "
                    "report found"
                ),
                "cached": False
            }

            vt_cache[url] = (
                result.copy()
            )

            return result


        # ------------------------------------------
        # RATE LIMIT
        # ------------------------------------------

        if response.status_code == 429:

            return {
                "available": False,
                "found": False,
                "error": (
                    "VirusTotal API "
                    "rate limit reached"
                ),
                "cached": False
            }


        # ------------------------------------------
        # AUTH ERROR
        # ------------------------------------------

        if response.status_code in (
            401,
            403
        ):

            return {
                "available": False,
                "found": False,
                "error": (
                    "VirusTotal API "
                    "authentication failed"
                ),
                "cached": False
            }


        # Raise unexpected HTTP errors

        response.raise_for_status()


        # ------------------------------------------
        # PARSE RESPONSE
        # ------------------------------------------

        data = response.json()


        attributes = (
            data
            .get("data", {})
            .get("attributes", {})
        )


        stats = attributes.get(
            "last_analysis_stats",
            {}
        )


        malicious = int(
            stats.get(
                "malicious",
                0
            )
        )


        suspicious = int(
            stats.get(
                "suspicious",
                0
            )
        )


        harmless = int(
            stats.get(
                "harmless",
                0
            )
        )


        undetected = int(
            stats.get(
                "undetected",
                0
            )
        )


        # ------------------------------------------
        # RESULT
        # ------------------------------------------

        result = {

            "available": True,

            "found": True,

            "malicious":
                malicious,

            "suspicious":
                suspicious,

            "harmless":
                harmless,

            "undetected":
                undetected,

            "cached": False
        }


        # Save to cache

        vt_cache[url] = (
            result.copy()
        )


        print(
            "VirusTotal API request:",
            url
        )


        return result


    # ------------------------------------------
    # NETWORK ERRORS
    # ------------------------------------------

    except requests.RequestException as e:

        print(
            "VirusTotal network error:",
            e
        )


        return {

            "available": False,

            "found": False,

            "error": (
                "VirusTotal service "
                "is temporarily unavailable"
            ),

            "cached": False
        }


    # ------------------------------------------
    # OTHER ERRORS
    # ------------------------------------------

    except Exception as e:

        print(
            "VirusTotal error:",
            e
        )


        return {

            "available": False,

            "found": False,

            "error": (
                "VirusTotal check failed"
            ),

            "cached": False
        }