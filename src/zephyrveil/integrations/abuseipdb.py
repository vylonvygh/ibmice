"""
integrations/abuseipdb.py — AbuseIPDB API client.

Provides abuse confidence score and report count for an IP.
Free tier: 1,000 lookups/day.

API docs: https://docs.abuseipdb.com/#check-endpoint
Endpoint: GET https://api.abuseipdb.com/api/v2/check

Score interpretation:
- 0-10:   Clean or very unlikely to be malicious
- 11-50:  Suspicious, warrants investigation
- 51-100: Highly likely malicious, take action
"""

import requests
from typing import Any


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
REQUEST_TIMEOUT = 5  # seconds


def query_abuseipdb(ip: str, api_key: str) -> dict[str, Any]:
    """
    Query AbuseIPDB for the abuse confidence score of an IP address.

    Args:
        ip: IP address to check.
        api_key: AbuseIPDB API key from abuseipdb.com/api.

    Returns:
        Dict with keys:
        - abuse_score: int 0-100 (confidence of malicious activity)
        - abuse_reports: int (number of user reports)
        - country_code: 2-letter country code
        - isp: ISP name
        - usage_type: e.g. "Data Center/Web Hosting/Transit"
        - is_whitelisted: bool
        - raw: full API response dict
        - error: error string if failed
        - skipped: True if API key missing
    """
    result: dict[str, Any] = {
        "abuse_score":    0,
        "abuse_reports":  0,
        "country_code":   "",
        "isp":            "",
        "usage_type":     "",
        "is_whitelisted": False,
        "raw":            {},
        "error":          "",
        "skipped":        False,
    }

    # ── Guard: require API key ────────────────────────────────────────────
    if not api_key or not api_key.strip():
        result["skipped"] = True
        result["error"]   = "AbuseIPDB key not configured — get one at abuseipdb.com/api"
        return result

    if not ip or not ip.strip():
        result["error"] = "No IP address provided"
        return result

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers={
                "Key":    api_key.strip(),
                "Accept": "application/json",
            },
            params={
                "ipAddress":     ip.strip(),
                "maxAgeInDays":  "90",   # Reports from last 90 days
                "verbose":       "",     # Don't request verbose report list
            },
            timeout=REQUEST_TIMEOUT,
        )

        # ── Handle HTTP errors ────────────────────────────────────────────
        if response.status_code == 429:
            result["error"] = "AbuseIPDB daily quota reached (1000/day free) — wait until tomorrow or upgrade"
            return result

        if response.status_code == 401:
            result["error"] = "AbuseIPDB API key invalid — check config.toml or get new key at abuseipdb.com/api"
            return result

        if response.status_code == 422:
            result["error"] = f"AbuseIPDB: invalid IP address format — '{ip}'"
            return result

        if response.status_code != 200:
            result["error"] = f"AbuseIPDB returned status {response.status_code}"
            return result

        # ── Parse response ────────────────────────────────────────────────
        try:
            data = response.json()
        except ValueError:
            result["error"] = "AbuseIPDB returned invalid JSON"
            return result

        result["raw"] = data

        # API returns data nested under "data" key
        payload = data.get("data", {})

        result["abuse_score"]    = int(payload.get("abuseConfidenceScore", 0))
        result["abuse_reports"]  = int(payload.get("totalReports", 0))
        result["country_code"]   = payload.get("countryCode", "")
        result["isp"]            = payload.get("isp", "")
        result["usage_type"]     = payload.get("usageType", "")
        result["is_whitelisted"] = bool(payload.get("isWhitelisted", False))

        return result

    except requests.Timeout:
        result["error"] = "AbuseIPDB request timed out — check your internet connection"
        return result
    except requests.ConnectionError:
        result["error"] = "Cannot reach AbuseIPDB — check your internet connection"
        return result
    except Exception:
        result["error"] = "AbuseIPDB lookup failed — unexpected error"
        return result
