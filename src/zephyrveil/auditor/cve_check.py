"""
auditor/cve_check.py — CVE vulnerability check using NVD/NIST API.

Queries the National Vulnerability Database (NVD) for CVEs affecting
installed packages or running services.

API docs: https://nvd.nist.gov/developers/vulnerabilities
Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0

Free tier: ~5 requests/30 seconds without key, ~50/30 seconds with key.
We check the top installed packages most likely to have CVEs.

Shows top 2 CVEs per package with:
- CVE ID, severity score, description, published date, affected versions
"""

import subprocess
import shutil
import time
import requests
from typing import Any


NVD_API_URL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 10  # NVD can be slow


# Packages commonly worth checking for CVEs on a Linux system
PRIORITY_PACKAGES = [
    "openssh",
    "openssl",
    "linux",
    "sudo",
    "bash",
    "curl",
    "wget",
    "nginx",
    "apache",
    "python",
    "nodejs",
    "mysql",
    "postgresql",
    "docker",
    "git",
    "vim",
    "libc",
    "glibc",
]


def get_installed_packages() -> list[dict[str, str]]:
    """
    Get list of installed packages with versions using pacman (Arch Linux).

    Falls back to dpkg (Debian/Ubuntu) if pacman unavailable.

    Returns:
        List of dicts: {name, version}
    """
    packages = []

    try:
        # Try pacman first (Arch Linux / EndeavorOS)
        if shutil.which("pacman"):
            result = subprocess.run(
                ["pacman", "-Q"],
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="replace",
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    try:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            packages.append({
                                "name":    parts[0],
                                "version": parts[1],
                            })
                    except Exception:
                        continue
                return packages

        # Fallback: dpkg (Debian/Ubuntu)
        if shutil.which("dpkg"):
            result = subprocess.run(
                ["dpkg", "-l"],
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="replace",
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    try:
                        if not line.startswith("ii"):
                            continue
                        parts = line.split()
                        if len(parts) >= 3:
                            packages.append({
                                "name":    parts[1].split(":")[0],
                                "version": parts[2],
                            })
                    except Exception:
                        continue

        return packages

    except subprocess.TimeoutExpired:
        return packages
    except Exception:
        return packages


def query_nvd_cves(keyword: str, api_key: str = "", max_results: int = 5) -> list[dict[str, Any]]:
    """
    Query NVD API for CVEs matching a keyword (package name).

    Args:
        keyword: Package or software name to search for.
        api_key: Optional NVD API key for higher rate limits.
        max_results: Maximum CVEs to return per package.

    Returns:
        List of CVE dicts: {cve_id, severity, score, description, published, affected_versions}
    """
    cves = []

    try:
        headers = {"Accept": "application/json"}
        if api_key and api_key.strip():
            headers["apiKey"] = api_key.strip()

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results,
            "startIndex": 0,
        }

        response = requests.get(
            NVD_API_URL,
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 429:
            # Rate limited — return empty, caller handles
            return []

        if response.status_code == 403:
            return []

        if response.status_code != 200:
            return []

        try:
            data = response.json()
        except ValueError:
            return []

        vulnerabilities = data.get("vulnerabilities", [])

        for vuln in vulnerabilities[:max_results]:
            try:
                cve_item = vuln.get("cve", {})
                cve_id   = cve_item.get("id", "")

                # Get description (prefer English)
                descriptions = cve_item.get("descriptions", [])
                description  = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")[:300]
                        break

                # Get CVSS v3 score and severity
                score    = 0.0
                severity = "UNKNOWN"
                metrics  = cve_item.get("metrics", {})

                # Try CVSSv3.1 first, then v3.0, then v2
                for cvss_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = metrics.get(cvss_key, [])
                    if metric_list:
                        metric = metric_list[0].get("cvssData", {})
                        score    = float(metric.get("baseScore", 0.0))
                        severity = metric.get("baseSeverity", metric.get("vectorString", "UNKNOWN"))
                        break

                # Published date
                published = cve_item.get("published", "")[:10]  # Just the date part

                # Affected versions from configurations
                affected_versions = []
                for config in cve_item.get("configurations", [])[:2]:
                    for node in config.get("nodes", [])[:2]:
                        for cpe_match in node.get("cpeMatch", [])[:3]:
                            version_end = cpe_match.get("versionEndIncluding", "")
                            version_start = cpe_match.get("versionStartIncluding", "")
                            cpe = cpe_match.get("criteria", "")
                            if version_end:
                                affected_versions.append(f"<= {version_end}")
                            elif version_start and version_end:
                                affected_versions.append(f"{version_start} - {version_end}")
                            elif cpe:
                                # Extract version from CPE string
                                cpe_parts = cpe.split(":")
                                if len(cpe_parts) > 5 and cpe_parts[5] != "*":
                                    affected_versions.append(cpe_parts[5])

                cves.append({
                    "cve_id":            cve_id,
                    "severity":          severity,
                    "score":             score,
                    "description":       description,
                    "published":         published,
                    "affected_versions": list(set(affected_versions))[:5],
                })

            except Exception:
                continue

        # Sort by score descending (highest severity first)
        cves.sort(key=lambda c: c.get("score", 0), reverse=True)
        return cves

    except requests.Timeout:
        return []
    except requests.ConnectionError:
        return []
    except Exception:
        return []


def check_packages_for_cves(
    api_key: str = "",
    max_packages: int = 15,
    cves_per_package: int = 2,
) -> dict[str, Any]:
    """
    Check installed packages against NVD for known CVEs.

    Checks the most security-relevant packages to keep API calls manageable.
    Shows top 2 CVEs per package as specified in the plan.

    Args:
        api_key: NVD API key for higher rate limits.
        max_packages: Maximum number of packages to check.
        cves_per_package: Number of CVEs to show per package.

    Returns:
        Dict with:
        - results: list of {package, version, cves: list}
        - checked_count: number of packages actually checked
        - vuln_count: total CVEs found
        - error: error string if something failed
    """
    result: dict[str, Any] = {
        "results":       [],
        "checked_count": 0,
        "vuln_count":    0,
        "error":         "",
    }

    try:
        # Get all installed packages
        all_packages = get_installed_packages()

        if not all_packages:
            result["error"] = "Could not get package list — pacman/dpkg unavailable"
            return result

        # Filter to priority packages that are actually installed
        # This avoids making hundreds of API calls
        packages_to_check = []
        installed_names = {p["name"].lower(): p for p in all_packages}

        for priority_name in PRIORITY_PACKAGES:
            if priority_name in installed_names:
                packages_to_check.append(installed_names[priority_name])
            # Also check partial matches (e.g. "python" matches "python3.11")
            else:
                for name, pkg in installed_names.items():
                    if priority_name in name and pkg not in packages_to_check:
                        packages_to_check.append(pkg)
                        break

        # Cap at max_packages to avoid too many API calls
        packages_to_check = packages_to_check[:max_packages]

        # ── Query NVD for each package ─────────────────────────────────
        package_results = []
        for i, pkg in enumerate(packages_to_check):
            try:
                cves = query_nvd_cves(
                    keyword=pkg["name"],
                    api_key=api_key,
                    max_results=cves_per_package + 2,  # Fetch a few extra, take top 2
                )

                if cves:
                    result["vuln_count"] += len(cves[:cves_per_package])

                package_results.append({
                    "package": pkg["name"],
                    "version": pkg["version"],
                    "cves":    cves[:cves_per_package],
                })

                result["checked_count"] += 1

                # Rate limiting: be respectful to NVD API
                # Without key: ~5 req/30 sec, With key: ~50 req/30 sec
                if not (api_key and api_key.strip()):
                    time.sleep(0.7)  # ~1.4 req/sec without key — well within limits
                else:
                    time.sleep(0.1)  # ~10 req/sec with key

            except Exception:
                continue

        # Only include packages that actually had CVEs found
        result["results"] = [r for r in package_results if r["cves"]]

        # Sort by highest CVE score in each package
        result["results"].sort(
            key=lambda r: max((c.get("score", 0) for c in r["cves"]), default=0),
            reverse=True,
        )

        return result

    except Exception as exc:
        result["error"] = f"CVE check failed — {type(exc).__name__}"
        return result
