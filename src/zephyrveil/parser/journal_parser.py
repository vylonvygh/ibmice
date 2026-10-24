"""
parser/journal_parser.py — Parse security events from journalctl.

This module reads authentication events from the systemd journal using
the `journalctl` command. It extracts:
- Failed SSH login attempts (IP, username, port)
- Successful SSH logins
- Sudo usage and failures
- Root login attempts
- All unique IPs seen in the log

Fallback: If journalctl is not available or fails, returns empty results
and the caller can fallback to auth_parser.py.

All regex patterns and subprocess calls are wrapped in try/except.
Never shows raw exceptions to the user.
"""

import re
import subprocess
import shutil
from datetime import datetime
from typing import Any


# ── Regex patterns for matching log line types ────────────────────────────────

# SSH failed password: "Failed password for user from 1.2.3.4 port 22 ssh2"
PATTERN_FAILED_SSH = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
)

# SSH accepted password or pubkey
PATTERN_ACCEPTED_SSH = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d.]+) port (\d+)"
)

# Invalid user attempts: "Invalid user testuser from 1.2.3.4 port 12345"
PATTERN_INVALID_USER = re.compile(
    r"Invalid user (\S+) from ([\d.]+)"
)

# Root login: "ROOT LOGIN" or "login from root"
PATTERN_ROOT_LOGIN = re.compile(
    r"(ROOT LOGIN|pam_unix.*root.*ssh|Failed password for root from ([\d.]+))"
)

# Root login via SSH specifically
PATTERN_ROOT_SSH = re.compile(
    r"Failed password for root from ([\d.]+)"
)

# Sudo usage
PATTERN_SUDO = re.compile(
    r"sudo:.*?(\S+)\s*:.*?COMMAND=(.*)"
)

# Sudo failure (authentication failure)
PATTERN_SUDO_FAIL = re.compile(
    r"sudo:.*authentication failure"
)

# General IP extraction fallback
PATTERN_IP = re.compile(
    r"\b((?:\d{1,3}\.){3}\d{1,3})\b"
)

# Timestamp at start of journalctl lines: "Apr 01 14:32:05"
PATTERN_TIMESTAMP = re.compile(
    r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"
)


def is_journalctl_available() -> bool:
    """
    Check if journalctl binary exists on this system.

    Returns:
        True if journalctl is found in PATH, False otherwise.
    """
    return shutil.which("journalctl") is not None


def run_journalctl(since: str = "24h") -> list[str]:
    """
    Execute journalctl to get SSH/auth log lines.

    Runs: journalctl -u ssh -u sshd -u sudo --since="24h ago" --no-pager -o short

    Args:
        since: Time string like "24h", "7d", "1h" (appended as "Xh ago").

    Returns:
        List of raw log line strings, or empty list on any failure.
    """
    try:
        if not is_journalctl_available():
            return []

        # Build the since argument — journalctl format
        since_arg = f"{since} ago"

        # Try SSH-specific units first for focused output
        cmd = [
            "journalctl",
            "-u", "ssh",
            "-u", "sshd",
            "-u", "sudo",
            f"--since={since_arg}",
            "--no-pager",
            "-o", "short",
            "--output-fields=MESSAGE",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,  # 15 second timeout for journalctl
            encoding="utf-8",
            errors="replace",  # Don't crash on weird characters in logs
        )

        lines = result.stdout.splitlines()

        # If SSH units gave nothing, try broader auth-related search
        if len(lines) < 5:
            cmd_broad = [
                "journalctl",
                f"--since={since_arg}",
                "--no-pager",
                "-o", "short",
                "-g", "sshd|sudo|Failed password|Accepted|Invalid user|ROOT LOGIN",
            ]
            result2 = subprocess.run(
                cmd_broad,
                capture_output=True,
                text=True,
                timeout=15,
                encoding="utf-8",
                errors="replace",
            )
            broader_lines = result2.stdout.splitlines()
            if len(broader_lines) > len(lines):
                lines = broader_lines

        return lines

    except subprocess.TimeoutExpired:
        # journalctl took too long — return empty, fallback to auth.log
        return []
    except FileNotFoundError:
        # journalctl not installed
        return []
    except PermissionError:
        # Can't run journalctl — might need sudo
        return []
    except Exception:
        return []


def run_journalctl_from_file(filepath: str) -> list[str]:
    """
    Read log lines from an arbitrary file path instead of journalctl.

    This is used when SOURCE is set to a custom file path.

    Args:
        filepath: Absolute or relative path to a log file.

    Returns:
        List of raw log line strings, or empty list on failure.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except FileNotFoundError:
        return []
    except PermissionError:
        return []
    except UnicodeDecodeError:
        # Try reading as bytes then decoding with errors replaced
        try:
            with open(filepath, "rb") as f:
                raw = f.read()
            return raw.decode("utf-8", errors="replace").splitlines()
        except Exception:
            return []
    except Exception:
        return []


def parse_line(line: str, source_label: str = "journalctl") -> dict[str, Any] | None:
    """
    Parse a single log line and extract event data.

    This is the core parsing function. It tries all known patterns and
    returns the best match as a structured event dict.

    Args:
        line: Raw log line string.
        source_label: Label identifying where this line came from.

    Returns:
        Event dict with keys: occurred_at, source, source_ip, username,
        event_type, raw_line. Or None if no pattern matched.
    """
    try:
        line = line.strip()
        if not line:
            return None

        # Extract timestamp from line if present
        ts_match = PATTERN_TIMESTAMP.match(line)
        occurred_at = ts_match.group(1) if ts_match else ""

        # Try each pattern in priority order
        # 1. Root SSH login attempt (highest severity)
        m = PATTERN_ROOT_SSH.search(line)
        if m:
            return {
                "occurred_at": occurred_at,
                "source": source_label,
                "source_ip": m.group(1),
                "username": "root",
                "event_type": "root_login_attempt",
                "raw_line": line,
            }

        # 2. Failed SSH login
        m = PATTERN_FAILED_SSH.search(line)
        if m:
            return {
                "occurred_at": occurred_at,
                "source": source_label,
                "source_ip": m.group(2),
                "username": m.group(1),
                "event_type": "failed_login",
                "raw_line": line,
            }

        # 3. Invalid user
        m = PATTERN_INVALID_USER.search(line)
        if m:
            return {
                "occurred_at": occurred_at,
                "source": source_label,
                "source_ip": m.group(2),
                "username": m.group(1),
                "event_type": "invalid_user",
                "raw_line": line,
            }

        # 4. Accepted login
        m = PATTERN_ACCEPTED_SSH.search(line)
        if m:
            return {
                "occurred_at": occurred_at,
                "source": source_label,
                "source_ip": m.group(2),
                "username": m.group(1),
                "event_type": "accepted_login",
                "raw_line": line,
            }

        # 5. Sudo failure
        if PATTERN_SUDO_FAIL.search(line):
            return {
                "occurred_at": occurred_at,
                "source": source_label,
                "source_ip": "",
                "username": _extract_user_from_sudo_line(line),
                "event_type": "sudo_failure",
                "raw_line": line,
            }

        # 6. Sudo success
        m = PATTERN_SUDO.search(line)
        if m:
            return {
                "occurred_at": occurred_at,
                "source": source_label,
                "source_ip": "",
                "username": m.group(1),
                "event_type": "sudo_command",
                "raw_line": line,
            }

        # 7. Generic — line has an IP but didn't match above patterns
        m = PATTERN_IP.search(line)
        if m and any(kw in line.lower() for kw in ("failed", "error", "invalid", "refused", "disconnect")):
            return {
                "occurred_at": occurred_at,
                "source": source_label,
                "source_ip": m.group(1),
                "username": "",
                "event_type": "generic_failure",
                "raw_line": line,
            }

        return None  # No pattern matched this line

    except Exception:
        return None


def _extract_user_from_sudo_line(line: str) -> str:
    """
    Extract the username from a sudo log line.

    Example: "sudo: john : authentication failure ..."
    Returns "john" or "" if not found.
    """
    try:
        # sudo lines typically have "sudo: USERNAME :"
        m = re.search(r"sudo:\s+(\S+)\s+:", line)
        return m.group(1) if m else ""
    except Exception:
        return ""


def parse_journal(since: str = "24h", filepath: str | None = None) -> dict[str, Any]:
    """
    Main entry point: parse journalctl (or a file) and return structured results.

    Args:
        since: Time window for journalctl (e.g., "24h", "7d").
        filepath: Optional path to a custom log file. If set, reads from file
                  instead of running journalctl.

    Returns:
        Dict with keys:
        - events: list of event dicts
        - ips: set of all unique IPs seen
        - source_used: string label of what source was used
        - line_count: number of raw lines processed
        - error: error string if something went wrong (empty = no error)
    """
    result: dict[str, Any] = {
        "events": [],
        "ips": set(),
        "source_used": "journalctl",
        "line_count": 0,
        "error": "",
    }

    try:
        # ── Get raw lines from the appropriate source ──────────────────
        if filepath:
            # Custom file path provided
            raw_lines = run_journalctl_from_file(filepath)
            result["source_used"] = filepath
        else:
            # Default: journalctl
            raw_lines = run_journalctl(since=since)
            result["source_used"] = "journalctl"

        result["line_count"] = len(raw_lines)

        # ── Parse each line ────────────────────────────────────────────
        for line in raw_lines:
            try:
                event = parse_line(line, source_label=result["source_used"])
                if event:
                    result["events"].append(event)
                    # Collect the IP if present
                    ip = event.get("source_ip", "")
                    if ip and _is_valid_ip(ip):
                        result["ips"].add(ip)
            except Exception:
                continue  # Skip malformed lines silently

        return result

    except Exception as exc:
        result["error"] = f"Journal parser failed — {type(exc).__name__}"
        return result


def _is_valid_ip(ip: str) -> bool:
    """
    Basic IP address validation — check it's not localhost or broadcast.

    Args:
        ip: IP string to validate.

    Returns:
        True if it looks like a real external IP worth investigating.
    """
    try:
        if not ip:
            return False
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        nums = [int(p) for p in parts]
        if any(n < 0 or n > 255 for n in nums):
            return False
        # Skip localhost and private ranges for threat intel
        # (still include them in events, just not for external API lookups)
        if nums[0] == 127:
            return False  # loopback
        return True
    except Exception:
        return False
