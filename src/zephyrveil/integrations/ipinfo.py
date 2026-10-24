"""
integrations/ipinfo.py — IPInfo.io API client.

Provides GeoIP data: country, city, org, ISP, ASN, hostname.
Free tier: 50,000 lookups/month (no rate limit header needed for this).

API endpoint: https://ipinfo.io/{ip}?token={key}

If API key is missing: returns empty dict with a warning flag.
If request fails: returns empty dict with error info.
Never crashes the caller.
"""

import requests
from typing import Any


IPINFO_BASE_URL = "https://ipinfo.io"
REQUEST_TIMEOUT = 5  # seconds


def query_ipinfo(ip: str, api_key: str) -> dict[str, Any]:
    """
    Query IPInfo.io for geographic and network info about an IP.

    Args:
        ip: IP address to look up (e.g., "1.2.3.4").
        api_key: IPInfo API token from ipinfo.io/signup.

    Returns:
        Dict with keys:
        - country, city, org, isp, asn, hostname: enrichment data
        - raw: the full API response dict
        - error: error description if request failed (empty = success)
        - skipped: True if API key was missing (feature skipped)
    """
    # Return structure with safe defaults
    result: dict[str, Any] = {
        "country":  "",
        "city":     "",
        "org":      "",
        "isp":      "",
        "asn":      "",
        "hostname": "",
        "raw":      {},
        "error":    "",
        "skipped":  False,
    }

    # ── Guard: require API key ────────────────────────────────────────────
    if not api_key or not api_key.strip():
        result["skipped"] = True
        result["error"]   = "IPInfo API key not configured — add to config.toml [api_keys] ipinfo"
        return result

    # ── Guard: basic IP validation ────────────────────────────────────────
    if not ip or not ip.strip():
        result["error"] = "No IP address provided"
        return result

    try:
        # Build the API URL — IPInfo uses simple path routing
        url = f"{IPINFO_BASE_URL}/{ip.strip()}"

        response = requests.get(
            url,
            params={"token": api_key.strip()},
            timeout=REQUEST_TIMEOUT,
            headers={"Accept": "application/json"},
        )

        # ── Handle HTTP errors ────────────────────────────────────────────
        if response.status_code == 429:
            result["error"] = "IPInfo rate limit reached — wait and retry, or upgrade plan at ipinfo.io"
            return result

        if response.status_code == 401:
            result["error"] = "IPInfo API key invalid — check config.toml and get a new key at ipinfo.io/signup"
            return result

        if response.status_code == 404:
            result["error"] = f"IPInfo has no data for IP: {ip}"
            return result

        if response.status_code != 200:
            result["error"] = f"IPInfo returned status {response.status_code} — service may be down"
            return result

        # ── Parse JSON response ───────────────────────────────────────────
        try:
            data = response.json()
        except ValueError:
            result["error"] = "IPInfo returned invalid JSON — service may be experiencing issues"
            return result

        result["raw"] = data

        # ── Extract the fields we care about ─────────────────────────────
        result["country"]  = data.get("country", "")
        result["city"]     = data.get("city", "")
        result["hostname"] = data.get("hostname", "")

        # "org" field in IPInfo contains "AS12345 Company Name"
        org_raw = data.get("org", "")
        if org_raw:
            parts = org_raw.split(" ", 1)  # Split "AS12345 Name" into [ASN, Name]
            if len(parts) == 2 and parts[0].startswith("AS"):
                result["asn"] = parts[0]
                result["org"] = parts[1]
                result["isp"] = parts[1]  # Same as org in IPInfo free tier
            else:
                result["org"] = org_raw
                result["isp"] = org_raw

        # Region and postal code as bonus info (stored in org field if org empty)
        if not result["org"]:
            result["org"] = data.get("region", "")

        return result

    except requests.Timeout:
        result["error"] = "IPInfo request timed out — check your internet connection"
        return result
    except requests.ConnectionError:
        result["error"] = "Cannot reach IPInfo — check your internet connection"
        return result
    except requests.HTTPError as exc:
        result["error"] = f"IPInfo HTTP error — {exc}"
        return result
    except Exception:
        result["error"] = "IPInfo lookup failed — unexpected error"
        return result
