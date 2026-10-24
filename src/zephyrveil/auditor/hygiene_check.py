"""
auditor/hygiene_check.py — Security hygiene checks.

Checks key security configuration settings that are commonly misconfigured:
- SSH configuration (/etc/ssh/sshd_config)
- LUKS disk encryption status
- Firewall rules (firewalld or ufw)
- Sudo configuration (/etc/sudoers)
- Password policy (/etc/login.defs)

Each check returns a status (PASS/WARN/FAIL) and a fix suggestion.
"""

import subprocess
import shutil
import re
from pathlib import Path
from typing import Any


# ── SSH configuration checks ──────────────────────────────────────────────────

SSH_CONFIG_CHECKS = [
    {
        "setting":      "PermitRootLogin",
        "safe_values":  ["no", "prohibit-password"],
        "risky_values": ["yes"],
        "description":  "Root SSH login should be disabled",
        "fix":          "Edit /etc/ssh/sshd_config: set PermitRootLogin no",
        "severity":     "HIGH",
    },
    {
        "setting":      "PasswordAuthentication",
        "safe_values":  ["no"],
        "risky_values": ["yes"],
        "description":  "Password auth should be disabled — use SSH keys only",
        "fix":          "Edit /etc/ssh/sshd_config: set PasswordAuthentication no",
        "severity":     "MEDIUM",
    },
    {
        "setting":      "PermitEmptyPasswords",
        "safe_values":  ["no"],
        "risky_values": ["yes"],
        "description":  "Empty passwords must be forbidden",
        "fix":          "Edit /etc/ssh/sshd_config: set PermitEmptyPasswords no",
        "severity":     "HIGH",
    },
    {
        "setting":      "X11Forwarding",
        "safe_values":  ["no"],
        "risky_values": ["yes"],
        "description":  "X11 forwarding expands attack surface",
        "fix":          "Edit /etc/ssh/sshd_config: set X11Forwarding no",
        "severity":     "LOW",
    },
    {
        "setting":      "MaxAuthTries",
        "safe_values":  None,  # Numeric — checked differently
        "safe_max":     4,
        "description":  "Max auth tries should be 4 or fewer",
        "fix":          "Edit /etc/ssh/sshd_config: set MaxAuthTries 3",
        "severity":     "MEDIUM",
    },
    {
        "setting":      "LoginGraceTime",
        "safe_values":  None,
        "safe_max":     60,
        "description":  "Login grace time should be 60s or less",
        "fix":          "Edit /etc/ssh/sshd_config: set LoginGraceTime 30",
        "severity":     "LOW",
    },
]


def read_ssh_config() -> dict[str, str]:
    """
    Parse /etc/ssh/sshd_config into a dict of {setting: value}.

    Returns empty dict if file not readable.
    """
    settings: dict[str, str] = {}
    ssh_config_path = Path("/etc/ssh/sshd_config")

    try:
        if not ssh_config_path.exists():
            return settings

        content = ssh_config_path.read_text(encoding="utf-8", errors="replace")

        for line in content.splitlines():
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue
            # Parse "Setting Value" format
            parts = line.split(None, 1)
            if len(parts) == 2:
                key   = parts[0].strip()
                value = parts[1].strip().lower()
                settings[key] = value

        return settings

    except PermissionError:
        return {}
    except Exception:
        return {}


def check_ssh_config() -> list[dict[str, Any]]:
    """
    Check SSH configuration for security issues.

    Returns:
        List of check result dicts: {setting, status, current_value, description, fix, severity}
    """
    results = []

    try:
        ssh_settings = read_ssh_config()
        ssh_available = bool(ssh_settings) or Path("/etc/ssh/sshd_config").exists()

        if not ssh_available:
            return [{
                "setting":       "SSH Config",
                "status":        "INFO",
                "current_value": "not found",
                "description":   "SSH daemon config not found — SSH may not be installed",
                "fix":           "Install OpenSSH: pacman -S openssh",
                "severity":      "INFO",
            }]

        for check in SSH_CONFIG_CHECKS:
            try:
                setting      = check["setting"]
                current_val  = ssh_settings.get(setting, "not set")
                safe_values  = check.get("safe_values")
                risky_values = check.get("risky_values", [])

                # Numeric check (MaxAuthTries, LoginGraceTime)
                if safe_values is None and "safe_max" in check:
                    try:
                        num_val = int(current_val.split()[0]) if current_val != "not set" else 999
                        if num_val <= check["safe_max"]:
                            status = "PASS"
                        else:
                            status = "WARN"
                    except ValueError:
                        status = "INFO"

                # Value check
                elif current_val in (risky_values or []):
                    status = "FAIL"
                elif safe_values and current_val in safe_values:
                    status = "PASS"
                elif current_val == "not set":
                    status = "WARN"
                else:
                    status = "WARN"

                results.append({
                    "setting":       setting,
                    "status":        status,
                    "current_value": current_val,
                    "description":   check["description"],
                    "fix":           check["fix"],
                    "severity":      check["severity"],
                })
            except Exception:
                continue

    except Exception:
        pass

    return results


def check_luks_status() -> dict[str, Any]:
    """
    Check if LUKS disk encryption is active on block devices.

    Uses `lsblk` to list devices and `dmsetup` to check for dm-crypt mappings.

    Returns:
        Dict with: luks_active, encrypted_devices, plaintext_devices, error.
    """
    result: dict[str, Any] = {
        "luks_active":        False,
        "encrypted_devices":  [],
        "plaintext_devices":  [],
        "error":              "",
    }

    try:
        # Use lsblk to check for crypto_LUKS type devices
        if shutil.which("lsblk"):
            lsblk_result = subprocess.run(
                ["lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT", "-J"],
                capture_output=True,
                text=True,
                timeout=5,
                encoding="utf-8",
            )

            # Try JSON output first
            if lsblk_result.returncode == 0:
                try:
                    import json
                    data = json.loads(lsblk_result.stdout)
                    devices = data.get("blockdevices", [])

                    def scan_device(dev: dict) -> None:
                        fstype = dev.get("fstype", "") or ""
                        name   = dev.get("name", "")
                        if "crypto_LUKS" in fstype:
                            result["encrypted_devices"].append(name)
                            result["luks_active"] = True
                        for child in dev.get("children", []):
                            scan_device(child)

                    for device in devices:
                        scan_device(device)

                except (ValueError, KeyError):
                    pass

        # Also check dmsetup for active dm-crypt devices (LUKS unlocked volumes)
        if shutil.which("dmsetup"):
            dm_result = subprocess.run(
                ["dmsetup", "ls", "--target", "crypt"],
                capture_output=True,
                text=True,
                timeout=5,
                encoding="utf-8",
            )
            if dm_result.returncode == 0:
                dm_lines = dm_result.stdout.strip().splitlines()
                if dm_lines and dm_lines[0] != "No devices found":
                    result["luks_active"] = True
                    for line in dm_lines:
                        name = line.split()[0]
                        if name not in result["encrypted_devices"]:
                            result["encrypted_devices"].append(name)

        return result

    except subprocess.TimeoutExpired:
        result["error"] = "LUKS check timed out"
        return result
    except Exception:
        result["error"] = "LUKS check failed"
        return result


def check_firewall_status() -> dict[str, Any]:
    """
    Check firewall status — supports firewalld and ufw.

    Returns:
        Dict with: active, type (firewalld/ufw/none), active_zones, default_policy, error.
    """
    result: dict[str, Any] = {
        "active":         False,
        "type":           "none",
        "active_zones":   [],
        "default_policy": "",
        "rules_count":    0,
        "error":          "",
    }

    try:
        # Check firewalld first (common on Arch/RHEL based systems)
        if shutil.which("firewall-cmd"):
            fw_result = subprocess.run(
                ["firewall-cmd", "--state"],
                capture_output=True,
                text=True,
                timeout=5,
                encoding="utf-8",
            )
            if fw_result.stdout.strip() == "running":
                result["active"] = True
                result["type"]   = "firewalld"

                # Get active zones
                zones_result = subprocess.run(
                    ["firewall-cmd", "--get-active-zones"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    encoding="utf-8",
                )
                if zones_result.returncode == 0:
                    # Parse zone names from output
                    zones = []
                    for line in zones_result.stdout.splitlines():
                        if not line.startswith(" ") and line.strip():
                            zones.append(line.strip())
                    result["active_zones"] = zones

                return result

        # Check ufw
        if shutil.which("ufw"):
            ufw_result = subprocess.run(
                ["ufw", "status"],
                capture_output=True,
                text=True,
                timeout=5,
                encoding="utf-8",
            )
            if ufw_result.returncode == 0:
                output = ufw_result.stdout
                if "Status: active" in output:
                    result["active"] = True
                    result["type"]   = "ufw"
                    # Count rules
                    rules = [l for l in output.splitlines() if l.strip() and "Status" not in l and "To" not in l]
                    result["rules_count"] = len(rules)

                return result

        # Check iptables as last resort
        if shutil.which("iptables"):
            ipt_result = subprocess.run(
                ["iptables", "-L", "-n", "--line-numbers"],
                capture_output=True,
                text=True,
                timeout=5,
                encoding="utf-8",
            )
            if ipt_result.returncode == 0:
                rules = [l for l in ipt_result.stdout.splitlines() if l.strip() and "Chain" not in l and "target" not in l.lower()]
                if rules:
                    result["active"]      = True
                    result["type"]        = "iptables"
                    result["rules_count"] = len(rules)

        return result

    except subprocess.TimeoutExpired:
        result["error"] = "Firewall check timed out"
        return result
    except PermissionError:
        result["error"] = "Cannot check firewall — try: sudo zephyrveil"
        return result
    except Exception:
        result["error"] = "Firewall check failed"
        return result


def check_sudo_config() -> dict[str, Any]:
    """
    Check sudo configuration for common security issues.

    Returns:
        Dict with: nopasswd_entries (dangerous), error.
    """
    result: dict[str, Any] = {
        "nopasswd_entries": [],
        "requires_password": True,
        "error":            "",
    }

    try:
        sudoers_path = Path("/etc/sudoers")
        if not sudoers_path.exists():
            result["error"] = "/etc/sudoers not found"
            return result

        content = sudoers_path.read_text(encoding="utf-8", errors="replace")

        # Look for NOPASSWD entries — these let users sudo without a password
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "NOPASSWD" in line.upper():
                result["nopasswd_entries"].append(line)

        # Also check sudoers.d directory
        sudoers_d = Path("/etc/sudoers.d")
        if sudoers_d.exists():
            try:
                for f in sudoers_d.iterdir():
                    if f.is_file():
                        try:
                            extra = f.read_text(encoding="utf-8", errors="replace")
                            for line in extra.splitlines():
                                line = line.strip()
                                if "NOPASSWD" in line.upper() and not line.startswith("#"):
                                    result["nopasswd_entries"].append(f"{f.name}: {line}")
                        except Exception:
                            continue
            except Exception:
                pass

        result["requires_password"] = len(result["nopasswd_entries"]) == 0
        return result

    except PermissionError:
        result["error"] = "Cannot read /etc/sudoers — try: sudo zephyrveil"
        return result
    except Exception:
        result["error"] = "Sudo check failed"
        return result


def run_hygiene_checks() -> dict[str, Any]:
    """
    Main entry point: run all security hygiene checks.

    Returns:
        Dict with all hygiene check results combined.
    """
    result: dict[str, Any] = {
        "ssh_checks":  [],
        "luks":        {},
        "firewall":    {},
        "sudo":        {},
        "errors":      [],
    }

    try:
        result["ssh_checks"] = check_ssh_config()
    except Exception:
        result["errors"].append("SSH config check failed")

    try:
        result["luks"] = check_luks_status()
    except Exception:
        result["errors"].append("LUKS check failed")

    try:
        result["firewall"] = check_firewall_status()
    except Exception:
        result["errors"].append("Firewall check failed")

    try:
        result["sudo"] = check_sudo_config()
    except Exception:
        result["errors"].append("Sudo check failed")

    return result
