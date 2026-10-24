"""
parser/auth_parser.py — Parse /var/log/auth.log for security events.

This is the fallback parser when journalctl is unavailable.
It reads /var/log/auth.log directly and extracts the same event types
as journal_parser.py so the rest of the pipeline is identical.

Auth.log path varies by distro:
- Debian/Ubuntu: /var/log/auth.log
- Arch/RHEL: may not exist (use journalctl instead)

If auth.log doesn't exist or isn't readable, returns a clear error
so the caller can show the user a helpful message.
"""

import re
from pathlib import Path
from typing import Any


# ── Common auth.log paths to try ─────────────────────────────────────────────
AUTH_LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/auth.log.1",  # rotated log as fallback
    "/var/log/secure",      # RHEL/CentOS equivalent
]

# ── Reuse same regex patterns as journal_parser ───────────────────────────────
PATTERN_FAILED_SSH = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
)
PATTERN_ACCEPTED_SSH = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d.]+) port (\d+)"
)
PATTERN_INVALID_USER = re.compile(
    r"Invalid user (\S+) from ([\d.]+)"
)
PATTERN_ROOT_SSH = re.compile(
    r"Failed password for root from ([\d.]+)"
)
PATTERN_SUDO_FAIL = re.compile(
    r"sudo:.*authentication failure"
)
PATTERN_SUDO = re.compile(
    r"sudo:.*?(\S+)\s*:.*?COMMAND=(.*)"
)
PATTERN_IP = re.compile(
    r"\b((?:\d{1,3}\.){3}\d{1,3})\b"
)
# Auth.log timestamp: "Jan  1 14:32:05" or "Apr 01 14:32:05"
PATTERN_TIMESTAMP = re.compile(
    r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"
)


def find_auth_log() -> str | None:
    """
    Find the first readable auth log file on this system.

    Tries AUTH_LOG_PATHS in order and returns the first one that exists
    and is readable. Returns None if none found.
    """
    try:
        for path in AUTH_LOG_PATHS:
            p = Path(path)
            if p.exists() and p.is_file():
                # Check we can actually read it (not just stat it)
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        f.read(1)  # Read 1 byte to confirm access
                    return path
                except PermissionError:
                    continue  # Try next path
        return None
    except Exception:
        return None


def read_auth_log(path: str, max_lines: int = 50000) -> tuple[list[str], str]:
    """
    Read lines from an auth.log file.

    Args:
        path: Path to the auth.log file.
        max_lines: Maximum number of lines to read (prevents OOM on huge logs).

    Returns:
        Tuple of (lines: list[str], error: str).
        If error is non-empty, lines may be empty.
    """
    try:
        lines = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                lines.append(line.rstrip())
        return lines, ""

    except FileNotFoundError:
        return [], f"Auth log not found at {path}"
    except PermissionError:
        return [], f"Cannot read {path} — try: sudo zephyrveil"
    except UnicodeDecodeError:
        # Fallback: read as binary then decode
        try:
            with open(path, "rb") as f:
                raw = f.read(10 * 1024 * 1024)  # 10MB max
            lines = raw.decode("utf-8", errors="replace").splitlines()
            return lines[:max_lines], ""
        except Exception as exc:
            return [], f"Cannot decode {path}: {type(exc).__name__}"
    except OSError as exc:
        return [], f"OS error reading {path}: {exc.strerror}"
    except Exception:
        return [], f"Unexpected error reading {path}"


def parse_auth_line(line: str, source_label: str = "auth.log") -> dict[str, Any] | None:
    """
    Parse a single auth.log line and extract event data.

    Identical logic to journal_parser.parse_line() — same event structure
    so downstream threat detection works the same regardless of source.

    Args:
        line: Raw auth.log line.
        source_label: Label for the source field in the returned event.

    Returns:
        Event dict or None if no pattern matched.
    """
    try:
        line = line.strip()
        if not line:
            return None

        # Extract timestamp
        ts_match = PATTERN_TIMESTAMP.match(line)
        occurred_at = ts_match.group(1) if ts_match else ""

        # Root SSH login attempt
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

        # Failed SSH login
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

        # Invalid user
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

        # Accepted login
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

        # Sudo failure
        if PATTERN_SUDO_FAIL.search(line):
            return {
                "occurred_at": occurred_at,
                "source": source_label,
                "source_ip": "",
                "username": _extract_sudo_user(line),
                "event_type": "sudo_failure",
                "raw_line": line,
            }

        # Sudo success
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

        # Generic failure with IP
        m = PATTERN_IP.search(line)
        if m and any(kw in line.lower() for kw in ("failed", "error", "invalid", "refused")):
            return {
                "occurred_at": occurred_at,
                "source": source_label,
                "source_ip": m.group(1),
                "username": "",
                "event_type": "generic_failure",
                "raw_line": line,
            }

        return None

    except Exception:
        return None


def _extract_sudo_user(line: str) -> str:
    """Extract username from a sudo auth failure line."""
    try:
        m = re.search(r"sudo:\s+(\S+)\s+:", line)
        return m.group(1) if m else ""
    except Exception:
        return ""


def _is_valid_ip(ip: str) -> bool:
    """Basic IP validation — exclude localhost."""
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        nums = [int(p) for p in parts]
        if any(n < 0 or n > 255 for n in nums):
            return False
        return nums[0] != 127  # Exclude loopback
    except Exception:
        return False


def parse_auth_log(path: str | None = None) -> dict[str, Any]:
    """
    Main entry point: parse auth.log and return structured results.

    Args:
        path: Optional explicit path to auth log. If None, auto-detects.

    Returns:
        Dict with keys:
        - events: list of event dicts
        - ips: set of all unique IPs seen
        - source_used: path of auth.log that was read
        - line_count: number of raw lines processed
        - error: error string if something went wrong
    """
    result: dict[str, Any] = {
        "events": [],
        "ips": set(),
        "source_used": "",
        "line_count": 0,
        "error": "",
    }

    try:
        # ── Find the auth log ──────────────────────────────────────────
        log_path = path or find_auth_log()

        if not log_path:
            result["error"] = (
                "No auth log found — journalctl unavailable and /var/log/auth.log missing. "
                "Try: sudo zephyrveil, or set SOURCE to a custom log file."
            )
            return result

        result["source_used"] = log_path

        # ── Read the file ──────────────────────────────────────────────
        raw_lines, read_error = read_auth_log(log_path)
        if read_error:
            result["error"] = read_error
            return result

        result["line_count"] = len(raw_lines)

        # ── Parse each line ────────────────────────────────────────────
        for line in raw_lines:
            try:
                event = parse_auth_line(line, source_label=log_path)
                if event:
                    result["events"].append(event)
                    ip = event.get("source_ip", "")
                    if ip and _is_valid_ip(ip):
                        result["ips"].add(ip)
            except Exception:
                continue

        return result

    except Exception as exc:
        result["error"] = f"Auth log parser failed — {type(exc).__name__}"
        return result
