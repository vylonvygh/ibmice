"""
integrations/shodan.py — Shodan API client.

Provides open ports, running services, banners, and known CVEs for an IP.
Uses the official `shodan` Python SDK.

API docs: https://developer.shodan.io/api
Free account: limited to 1 query/second, no filters.
"""

from typing import Any


REQUEST_TIMEOUT = 10  # Shodan can be slow — give it more time


def query_shodan(ip: str, api_key: str) -> dict[str, Any]:
    """
    Query Shodan for open ports, services, and vulnerabilities on an IP.

    Uses the official shodan SDK which handles auth and parsing for us.

    Args:
        ip: IP address to look up.
        api_key: Shodan API key from account.shodan.io.

    Returns:
        Dict with keys:
        - ports: list of open port numbers
        - vulns: list of CVE IDs found by Shodan
        - org: organization name
        - isp: ISP name
        - os: detected operating system
        - hostnames: list of hostnames
        - services: list of service dicts (port, banner, product)
        - raw: full Shodan host dict
        - error: error string if failed
        - skipped: True if API key missing
    """
    result: dict[str, Any] = {
        "ports":     [],
        "vulns":     [],
        "org":       "",
        "isp":       "",
        "os":        "",
        "hostnames": [],
        "services":  [],
        "raw":       {},
        "error":     "",
        "skipped":   False,
    }

    # ── Guard: require API key ────────────────────────────────────────────
    if not api_key or not api_key.strip():
        result["skipped"] = True
        result["error"]   = "Shodan API key not configured — get one at account.shodan.io"
        return result

    if not ip or not ip.strip():
        result["error"] = "No IP address provided"
        return result

    try:
        # Import the shodan SDK — it's a project dependency
        import shodan as shodan_sdk

        # Initialize the Shodan API client with our key
        api = shodan_sdk.Shodan(api_key.strip())

        # ── Query Shodan for host info ──────────────────────────────────
        # This is the main host lookup — returns ports, services, vulns
        host_data = api.host(ip.strip())

        result["raw"] = host_data

        # Basic fields
        result["org"]       = host_data.get("org", "")
        result["isp"]       = host_data.get("isp", "")
        result["os"]        = host_data.get("os", "") or ""
        result["hostnames"] = host_data.get("hostnames", [])

        # Open ports list
        result["ports"] = host_data.get("ports", [])

        # Vulnerabilities — Shodan provides CVE IDs directly
        vulns_raw = host_data.get("vulns", {})
        if isinstance(vulns_raw, dict):
            result["vulns"] = list(vulns_raw.keys())  # Just the CVE IDs
        elif isinstance(vulns_raw, list):
            result["vulns"] = vulns_raw

        # Service details — each service is a dict with port, banner, etc.
        services = []
        for service in host_data.get("data", []):
            try:
                services.append({
                    "port":     service.get("port", 0),
                    "protocol": service.get("transport", "tcp"),
                    "product":  service.get("product", ""),
                    "version":  service.get("version", ""),
                    "banner":   service.get("data", "")[:200],  # Truncate long banners
                })
            except Exception:
                continue

        result["services"] = services

        return result

    except Exception as exc:
        # Handle Shodan-specific errors by checking the error message
        error_str = str(exc).lower()

        if "invalid api key" in error_str or "api key" in error_str:
            result["error"] = "Shodan API key invalid — check config or get new key at account.shodan.io"
        elif "no information available" in error_str or "not found" in error_str:
            # Shodan has no data for this IP — not an error
            result["error"] = ""
            return result
        elif "403" in error_str:
            result["error"] = "Shodan access denied — your plan may not allow this query type"
        elif "timeout" in error_str or "timed out" in error_str:
            result["error"] = "Shodan request timed out — check your internet connection"
        elif "connection" in error_str:
            result["error"] = "Cannot reach Shodan — check your internet connection"
        else:
            result["error"] = f"Shodan lookup failed — {type(exc).__name__}"

        return result
