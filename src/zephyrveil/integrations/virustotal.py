"""
integrations/virustotal.py — VirusTotal API v3 client.

Checks an IP against 70+ antivirus/security engines.
Free tier: 500 lookups/day, 4 requests/minute.

API docs: https://developers.virustotal.com/reference/ip-info
Endpoint: GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
"""

import requests
from typing import Any


VT_BASE_URL    = "https://www.virustotal.com/api/v3/ip_addresses"
REQUEST_TIMEOUT = 8  # VT can be slow — give it more time


def query_virustotal(ip: str, api_key: str) -> dict[str, Any]:
    """
    Query VirusTotal for malicious detection count for an IP.

    Args:
        ip: IP address to check.
        api_key: VirusTotal API key from virustotal.com/gui/my-apikey.

    Returns:
        Dict with keys:
        - malicious: int — number of engines that flagged as malicious
        - suspicious: int — number flagging as suspicious
        - harmless: int — engines that found it clean
        - total: int — total engines that analyzed this IP
        - engine_names: list of engine names that flagged it
        - reputation: int — VT reputation score
        - raw: full API response dict
        - error: error string if failed
        - skipped: True if API key missing
    """
    result: dict[str, Any] = {
        "malicious":    0,
        "suspicious":   0,
        "harmless":     0,
        "total":        0,
        "engine_names": [],
        "reputation":   0,
        "raw":          {},
        "error":        "",
        "skipped":      False,
    }

    # ── Guard: require API key ────────────────────────────────────────────
    if not api_key or not api_key.strip():
        result["skipped"] = True
        result["error"]   = "VirusTotal key not configured — get one at virustotal.com/gui/my-apikey"
        return result

    if not ip or not ip.strip():
        result["error"] = "No IP address provided"
        return result

    try:
        url = f"{VT_BASE_URL}/{ip.strip()}"

        response = requests.get(
            url,
            headers={
                "x-apikey": api_key.strip(),
                "Accept":   "application/json",
            },
            timeout=REQUEST_TIMEOUT,
        )

        # ── Handle HTTP errors ────────────────────────────────────────────
        if response.status_code == 429:
            result["error"] = "VirusTotal rate limit reached (4/min, 500/day free) — wait and retry"
            return result

        if response.status_code == 401:
            result["error"] = "VirusTotal API key invalid — check config or get new key at virustotal.com/gui/my-apikey"
            return result

        if response.status_code == 404:
            # VT doesn't have data for this IP — not an error
            result["error"] = ""
            return result

        if response.status_code != 200:
            result["error"] = f"VirusTotal returned status {response.status_code}"
            return result

        # ── Parse JSON ────────────────────────────────────────────────────
        try:
            data = response.json()
        except ValueError:
            result["error"] = "VirusTotal returned invalid JSON"
            return result

        result["raw"] = data

        # Navigate the VT v3 response structure
        attributes = data.get("data", {}).get("attributes", {})

        # Last analysis stats
        stats = attributes.get("last_analysis_stats", {})
        result["malicious"]  = int(stats.get("malicious", 0))
        result["suspicious"] = int(stats.get("suspicious", 0))
        result["harmless"]   = int(stats.get("harmless", 0))
        result["total"]      = sum(stats.values()) if stats else 0

        # Reputation score (negative = bad)
        result["reputation"] = int(attributes.get("reputation", 0))

        # Get list of engine names that flagged this IP as malicious
        analysis_results = attributes.get("last_analysis_results", {})
        flagging_engines = []
        for engine_name, engine_data in analysis_results.items():
            try:
                if engine_data.get("category") == "malicious":
                    flagging_engines.append(engine_name)
            except Exception:
                continue
        result["engine_names"] = flagging_engines[:10]  # Top 10 to keep it manageable

        return result

    except requests.Timeout:
        result["error"] = "VirusTotal request timed out — check your internet connection"
        return result
    except requests.ConnectionError:
        result["error"] = "Cannot reach VirusTotal — check your internet connection"
        return result
    except Exception:
        result["error"] = "VirusTotal lookup failed — unexpected error"
        return result
