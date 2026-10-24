"""
integrations/fail2ban.py — Check if an IP is currently banned by fail2ban.

This is a LOCAL check — no API key needed. It reads fail2ban's status
using the `fail2ban-client` command.

Fail2ban is a popular intrusion prevention tool that automatically bans
IPs that have too many failed authentication attempts.

If fail2ban is not installed, returns not-banned with a note.
If fail2ban is installed but we can't read it (permissions), shows a helpful error.
"""

import subprocess
import shutil
import re
from typing import Any


def is_fail2ban_installed() -> bool:
    """
    Check if fail2ban-client binary exists on this system.

    Returns:
        True if fail2ban-client is found in PATH.
    """
    return shutil.which("fail2ban-client") is not None


def get_active_jails() -> list[str]:
    """
    Get the list of active fail2ban jails (e.g., sshd, apache-auth).

    Returns:
        List of jail name strings, or empty list if fail2ban unavailable.
    """
    try:
        if not is_fail2ban_installed():
            return []

        result = subprocess.run(
            ["fail2ban-client", "status"],
            capture_output=True,
            text=True,
            timeout=5,
            encoding="utf-8",
            errors="replace",
        )

        if result.returncode != 0:
            return []

        # Output looks like: "Jail list: sshd, apache-auth"
        for line in result.stdout.splitlines():
            if "Jail list" in line:
                # Extract jail names after the colon
                jails_str = line.split(":", 1)[-1].strip()
                # Split by comma and clean up
                return [j.strip() for j in jails_str.split(",") if j.strip()]

        return []

    except subprocess.TimeoutExpired:
        return []
    except FileNotFoundError:
        return []
    except Exception:
        return []


def check_ip_banned(ip: str) -> dict[str, Any]:
    """
    Check if a specific IP is currently banned in any fail2ban jail.

    Queries each active jail and looks for the IP in its banned list.
    This is the main function called by the threat intel pipeline.

    Args:
        ip: IP address to check.

    Returns:
        Dict with keys:
        - banned: bool — True if IP is currently banned in any jail
        - jails_banned_in: list of jail names where this IP is banned
        - fail2ban_installed: bool — whether fail2ban is on this system
        - error: error string if check failed
    """
    result: dict[str, Any] = {
        "banned":            False,
        "jails_banned_in":   [],
        "fail2ban_installed": False,
        "error":             "",
    }

    try:
        # ── Check if fail2ban is available ────────────────────────────────
        if not is_fail2ban_installed():
            result["error"] = "fail2ban not installed — install with: pacman -S fail2ban"
            return result

        result["fail2ban_installed"] = True

        if not ip or not ip.strip():
            result["error"] = "No IP address provided"
            return result

        ip = ip.strip()

        # ── Get list of active jails to search ───────────────────────────
        jails = get_active_jails()
        if not jails:
            # fail2ban is running but no jails active — normal
            return result

        # ── Check each jail for this IP ───────────────────────────────────
        jails_found = []
        for jail in jails:
            try:
                jail_result = subprocess.run(
                    ["fail2ban-client", "status", jail],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    encoding="utf-8",
                    errors="replace",
                )

                if jail_result.returncode != 0:
                    continue

                output = jail_result.stdout

                # Look for "Banned IP list:" line and check if our IP is there
                for line in output.splitlines():
                    if "Banned IP list" in line:
                        # IPs are space-separated after the colon
                        banned_part = line.split(":", 1)[-1].strip()
                        banned_ips  = banned_part.split()
                        if ip in banned_ips:
                            jails_found.append(jail)
                        break

            except subprocess.TimeoutExpired:
                continue  # This jail query timed out — skip it
            except Exception:
                continue

        # ── Build final result ────────────────────────────────────────────
        result["jails_banned_in"] = jails_found
        result["banned"]          = len(jails_found) > 0

        return result

    except subprocess.TimeoutExpired:
        result["error"] = "fail2ban query timed out — service may be slow"
        return result
    except PermissionError:
        result["error"] = "Cannot query fail2ban — try running as root: sudo zephyrveil"
        return result
    except Exception:
        result["error"] = "fail2ban check failed — unexpected error"
        return result


def get_fail2ban_stats() -> dict[str, Any]:
    """
    Get overall fail2ban statistics — total banned IPs per jail.

    Used by the health/audit module to show fail2ban effectiveness.

    Returns:
        Dict with jail names as keys and stats dicts as values.
        Empty dict if fail2ban unavailable.
    """
    stats: dict[str, Any] = {}

    try:
        if not is_fail2ban_installed():
            return stats

        jails = get_active_jails()
        for jail in jails:
            try:
                result = subprocess.run(
                    ["fail2ban-client", "status", jail],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    encoding="utf-8",
                    errors="replace",
                )

                if result.returncode != 0:
                    continue

                jail_stats: dict[str, Any] = {
                    "currently_banned": 0,
                    "total_banned":     0,
                    "total_failed":     0,
                }

                for line in result.stdout.splitlines():
                    line = line.strip()
                    if "Currently banned" in line:
                        m = re.search(r"(\d+)", line)
                        if m:
                            jail_stats["currently_banned"] = int(m.group(1))
                    elif "Total banned" in line:
                        m = re.search(r"(\d+)", line)
                        if m:
                            jail_stats["total_banned"] = int(m.group(1))
                    elif "Total failed" in line:
                        m = re.search(r"(\d+)", line)
                        if m:
                            jail_stats["total_failed"] = int(m.group(1))

                stats[jail] = jail_stats

            except Exception:
                continue

        return stats

    except Exception:
        return stats
