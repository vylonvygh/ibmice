"""
auditor/tool_checker.py — Check which security tools are installed.

Checks for common Linux security tools and reports their status.
This helps identify gaps in the system's defense posture.

Tools checked: fail2ban, auditd, firewalld, ufw, clamav, rkhunter,
               lynis, chkrootkit, aide, snort, suricata, tripwire
"""

import shutil
import subprocess
from typing import Any


# ── Tool definitions: (name, binary, check_service, description, fix_cmd) ────
SECURITY_TOOLS = [
    {
        "name":        "fail2ban",
        "binary":      "fail2ban-client",
        "service":     "fail2ban",
        "description": "Intrusion prevention — auto-bans brute force IPs",
        "install":     "pacman -S fail2ban",
        "importance":  "HIGH",
    },
    {
        "name":        "firewalld",
        "binary":      "firewall-cmd",
        "service":     "firewalld",
        "description": "Dynamic firewall management",
        "install":     "pacman -S firewalld",
        "importance":  "HIGH",
    },
    {
        "name":        "ufw",
        "binary":      "ufw",
        "service":     "ufw",
        "description": "Uncomplicated Firewall (alternative to firewalld)",
        "install":     "pacman -S ufw",
        "importance":  "HIGH",
    },
    {
        "name":        "auditd",
        "binary":      "auditctl",
        "service":     "auditd",
        "description": "Linux audit daemon — tracks system calls",
        "install":     "pacman -S audit",
        "importance":  "MEDIUM",
    },
    {
        "name":        "clamav",
        "binary":      "clamscan",
        "service":     "clamav-daemon",
        "description": "Antivirus engine for Linux",
        "install":     "pacman -S clamav",
        "importance":  "MEDIUM",
    },
    {
        "name":        "rkhunter",
        "binary":      "rkhunter",
        "service":     None,
        "description": "Rootkit detection tool",
        "install":     "pacman -S rkhunter",
        "importance":  "MEDIUM",
    },
    {
        "name":        "lynis",
        "binary":      "lynis",
        "service":     None,
        "description": "Security auditing and hardening tool",
        "install":     "pacman -S lynis",
        "importance":  "LOW",
    },
    {
        "name":        "chkrootkit",
        "binary":      "chkrootkit",
        "service":     None,
        "description": "Check for signs of rootkits",
        "install":     "yay -S chkrootkit",
        "importance":  "LOW",
    },
    {
        "name":        "aide",
        "binary":      "aide",
        "service":     None,
        "description": "File integrity monitoring",
        "install":     "pacman -S aide",
        "importance":  "LOW",
    },
    {
        "name":        "snort",
        "binary":      "snort",
        "service":     "snort",
        "description": "Network intrusion detection (NIDS)",
        "install":     "pacman -S snort",
        "importance":  "LOW",
    },
    {
        "name":        "suricata",
        "binary":      "suricata",
        "service":     "suricata",
        "description": "Network IDS/IPS/NSM engine",
        "install":     "pacman -S suricata",
        "importance":  "LOW",
    },
]


def check_service_running(service_name: str) -> bool:
    """
    Check if a systemd service is currently active (running).

    Args:
        service_name: The systemd unit name (e.g., "fail2ban").

    Returns:
        True if service is active, False otherwise.
    """
    try:
        if not shutil.which("systemctl"):
            return False

        result = subprocess.run(
            ["systemctl", "is-active", service_name],
            capture_output=True,
            text=True,
            timeout=5,
            encoding="utf-8",
        )
        # "is-active" returns "active" if running
        return result.stdout.strip() == "active"

    except subprocess.TimeoutExpired:
        return False
    except FileNotFoundError:
        return False
    except Exception:
        return False


def check_tool(tool: dict[str, Any]) -> dict[str, Any]:
    """
    Check the installation and running status of a single security tool.

    Args:
        tool: Tool definition dict from SECURITY_TOOLS list.

    Returns:
        Dict with keys: name, installed, running, version, description,
        install_cmd, importance, status_label.
    """
    result: dict[str, Any] = {
        "name":        tool["name"],
        "installed":   False,
        "running":     False,
        "version":     "",
        "description": tool["description"],
        "install_cmd": tool["install"],
        "importance":  tool["importance"],
        "status_label": "MISSING",
    }

    try:
        # Check if binary exists in PATH
        binary_path = shutil.which(tool["binary"])
        result["installed"] = binary_path is not None

        if result["installed"]:
            # Try to get version string
            try:
                ver_result = subprocess.run(
                    [tool["binary"], "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    encoding="utf-8",
                    errors="replace",
                )
                # Take first line, first 80 chars
                ver_line = (ver_result.stdout or ver_result.stderr or "").splitlines()
                result["version"] = ver_line[0][:80] if ver_line else ""
            except Exception:
                result["version"] = "installed"

            # Check if service is running (only for tools with services)
            if tool.get("service"):
                result["running"] = check_service_running(tool["service"])

            # Set status label
            if tool.get("service"):
                result["status_label"] = "RUNNING" if result["running"] else "INSTALLED (not running)"
            else:
                result["status_label"] = "INSTALLED"
        else:
            result["status_label"] = "NOT INSTALLED"

    except Exception:
        result["status_label"] = "CHECK FAILED"

    return result


def check_all_tools() -> dict[str, Any]:
    """
    Check all security tools and return a comprehensive status report.

    Returns:
        Dict with keys:
        - tools: list of tool status dicts
        - installed_count: number of tools installed
        - running_count: number of services running
        - missing_high: list of HIGH importance tools not installed
        - summary: short summary string
    """
    results: dict[str, Any] = {
        "tools":          [],
        "installed_count": 0,
        "running_count":   0,
        "missing_high":    [],
        "summary":        "",
    }

    try:
        tool_results = []
        for tool_def in SECURITY_TOOLS:
            try:
                status = check_tool(tool_def)
                tool_results.append(status)

                if status["installed"]:
                    results["installed_count"] += 1
                if status["running"]:
                    results["running_count"] += 1
                if not status["installed"] and tool_def["importance"] == "HIGH":
                    results["missing_high"].append(tool_def["name"])

            except Exception:
                continue

        results["tools"] = tool_results

        # Build summary string
        total = len(SECURITY_TOOLS)
        inst  = results["installed_count"]
        miss  = results["missing_high"]

        if miss:
            results["summary"] = (
                f"{inst}/{total} tools installed. MISSING high-priority: {', '.join(miss)}"
            )
        else:
            results["summary"] = f"{inst}/{total} tools installed. All high-priority tools present."

    except Exception:
        results["summary"] = "Tool check encountered an error"

    return results
