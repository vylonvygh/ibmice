"""
detector/threat_engine.py — Threat detection engine for Zephyrveil.

This module takes a list of parsed log events and runs 5 threat detection
rules against them. Each rule checks for a specific attack pattern.

The 5 threat types:
1. SSH_BRUTE_FORCE      — 5+ failed logins from same IP within 60 seconds
2. CREDENTIAL_STUFFING  — 3+ different usernames tried from same IP
3. ROOT_LOGIN_ATTEMPT   — any direct root SSH login attempt
4. SUDO_ABUSE           — failed sudo or unusual sudo pattern
5. REPEATED_AUTH_FAILURE — 10+ total failures from same username

Severity levels:
- CRITICAL: Immediate threat, active attack in progress
- HIGH:     Serious threat, likely malicious activity
- MEDIUM:   Suspicious, warrants investigation
- LOW:      Minor anomaly, probably benign
- INFO:     Informational only

Config thresholds are read from the config dict so they're customizable.
Default thresholds are used if config is not available.
"""

from collections import defaultdict
from typing import Any


# ── Default thresholds (overridable via config) ───────────────────────────────
DEFAULT_BRUTE_FORCE_ATTEMPTS  = 5    # Number of fails to trigger brute force
DEFAULT_BRUTE_FORCE_WINDOW    = 60   # Time window in seconds (not enforced without timestamps)
DEFAULT_CRED_STUFFING_NAMES   = 3    # Number of different usernames from one IP
DEFAULT_REPEATED_AUTH_FAILS   = 10   # Number of total fails for one username


def _get_thresholds(config: dict[str, Any] | None) -> dict[str, int]:
    """
    Extract detection thresholds from config, using defaults for missing values.

    Args:
        config: App config dict or None.

    Returns:
        Dict of threshold values.
    """
    try:
        t = config.get("thresholds", {}) if config else {}
        return {
            "brute_force_attempts":  int(t.get("brute_force_attempts",  DEFAULT_BRUTE_FORCE_ATTEMPTS)),
            "brute_force_window":    int(t.get("brute_force_window",    DEFAULT_BRUTE_FORCE_WINDOW)),
            "cred_stuffing_usernames": int(t.get("cred_stuffing_usernames", DEFAULT_CRED_STUFFING_NAMES)),
            "repeated_auth_failures": int(t.get("repeated_auth_failures", DEFAULT_REPEATED_AUTH_FAILS)),
        }
    except Exception:
        return {
            "brute_force_attempts":  DEFAULT_BRUTE_FORCE_ATTEMPTS,
            "brute_force_window":    DEFAULT_BRUTE_FORCE_WINDOW,
            "cred_stuffing_usernames": DEFAULT_CRED_STUFFING_NAMES,
            "repeated_auth_failures": DEFAULT_REPEATED_AUTH_FAILS,
        }


def detect_ssh_brute_force(events: list[dict[str, Any]], threshold: int) -> list[dict[str, Any]]:
    """
    Rule 1: SSH Brute Force Detection.

    Triggers when: 5+ failed logins from the SAME IP address are found.
    (The 60-second window is noted in output but we operate per-session
    since log timestamps vary in format — we count total fails per IP.)

    Args:
        events: List of parsed log event dicts.
        threshold: Number of failures required to trigger.

    Returns:
        List of threat dicts, one per attacking IP that crossed the threshold.
    """
    threats = []
    try:
        # Count failed logins per source IP
        ip_fail_counts: dict[str, list[dict]] = defaultdict(list)

        for event in events:
            try:
                if event.get("event_type") in ("failed_login", "invalid_user"):
                    ip = event.get("source_ip", "")
                    if ip:
                        ip_fail_counts[ip].append(event)
            except Exception:
                continue

        # Check each IP against the threshold
        for ip, fail_events in ip_fail_counts.items():
            try:
                if len(fail_events) >= threshold:
                    # Collect all usernames tried from this IP
                    usernames_tried = list({e.get("username", "") for e in fail_events if e.get("username")})
                    threats.append({
                        "threat_type": "SSH_BRUTE_FORCE",
                        "severity": "CRITICAL",
                        "source_ip": ip,
                        "username": ", ".join(usernames_tried[:5]),  # Top 5 usernames
                        "event_count": len(fail_events),
                        "raw_data": {
                            "ip": ip,
                            "failed_attempts": len(fail_events),
                            "threshold": threshold,
                            "usernames_tried": usernames_tried,
                            "first_event": fail_events[0].get("occurred_at", ""),
                            "last_event": fail_events[-1].get("occurred_at", ""),
                            "sample_lines": [e.get("raw_line", "") for e in fail_events[:3]],
                        },
                    })
            except Exception:
                continue

    except Exception:
        pass

    return threats


def detect_credential_stuffing(events: list[dict[str, Any]], threshold: int) -> list[dict[str, Any]]:
    """
    Rule 2: Credential Stuffing Detection.

    Triggers when: 3+ DIFFERENT usernames are attempted from the SAME IP.
    This indicates the attacker is trying a list of known credentials.

    Args:
        events: List of parsed log event dicts.
        threshold: Minimum unique username count to trigger.

    Returns:
        List of threat dicts.
    """
    threats = []
    try:
        # Map IP → set of unique usernames tried
        ip_usernames: dict[str, set] = defaultdict(set)
        ip_events: dict[str, list] = defaultdict(list)

        for event in events:
            try:
                event_type = event.get("event_type", "")
                if event_type in ("failed_login", "invalid_user"):
                    ip = event.get("source_ip", "")
                    username = event.get("username", "")
                    if ip and username:
                        ip_usernames[ip].add(username)
                        ip_events[ip].append(event)
            except Exception:
                continue

        # Flag IPs that tried many different usernames
        for ip, usernames in ip_usernames.items():
            try:
                if len(usernames) >= threshold:
                    evts = ip_events[ip]
                    threats.append({
                        "threat_type": "CREDENTIAL_STUFFING",
                        "severity": "HIGH",
                        "source_ip": ip,
                        "username": f"{len(usernames)} unique usernames tried",
                        "event_count": len(evts),
                        "raw_data": {
                            "ip": ip,
                            "unique_usernames": list(usernames),
                            "unique_username_count": len(usernames),
                            "threshold": threshold,
                            "total_attempts": len(evts),
                            "sample_lines": [e.get("raw_line", "") for e in evts[:3]],
                        },
                    })
            except Exception:
                continue

    except Exception:
        pass

    return threats


def detect_root_login_attempts(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Rule 3: Root Login Attempt Detection.

    Triggers on ANY event where username == 'root' and it's a failed or
    invalid login attempt. Root SSH login should never succeed on a
    hardened system, so any attempt is notable.

    Args:
        events: List of parsed log event dicts.

    Returns:
        List of threat dicts — one per attacking IP attempting root.
    """
    threats = []
    try:
        # Group root attempts by IP
        root_attempts: dict[str, list] = defaultdict(list)

        for event in events:
            try:
                username = event.get("username", "").lower()
                event_type = event.get("event_type", "")
                if username == "root" and event_type in ("root_login_attempt", "failed_login", "invalid_user"):
                    ip = event.get("source_ip", "N/A")
                    root_attempts[ip].append(event)
            except Exception:
                continue

        # One threat per source IP
        for ip, evts in root_attempts.items():
            try:
                threats.append({
                    "threat_type": "ROOT_LOGIN_ATTEMPT",
                    "severity": "HIGH",
                    "source_ip": ip,
                    "username": "root",
                    "event_count": len(evts),
                    "raw_data": {
                        "ip": ip,
                        "attempts": len(evts),
                        "timestamps": [e.get("occurred_at", "") for e in evts[:5]],
                        "sample_lines": [e.get("raw_line", "") for e in evts[:3]],
                        "note": "Root SSH login attempted — verify PermitRootLogin is disabled",
                    },
                })
            except Exception:
                continue

    except Exception:
        pass

    return threats


def detect_sudo_abuse(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Rule 4: Sudo Abuse Detection.

    Triggers on sudo authentication failures. Multiple sudo failures
    from the same user could indicate privilege escalation attempts.

    Args:
        events: List of parsed log event dicts.

    Returns:
        List of threat dicts.
    """
    threats = []
    try:
        # Group sudo failures by username
        sudo_fails: dict[str, list] = defaultdict(list)

        for event in events:
            try:
                if event.get("event_type") == "sudo_failure":
                    username = event.get("username", "unknown")
                    sudo_fails[username].append(event)
            except Exception:
                continue

        # Any sudo failure is suspicious — flag them all
        for username, evts in sudo_fails.items():
            try:
                severity = "HIGH" if len(evts) >= 3 else "MEDIUM"
                threats.append({
                    "threat_type": "SUDO_ABUSE",
                    "severity": severity,
                    "source_ip": evts[0].get("source_ip", "local"),
                    "username": username,
                    "event_count": len(evts),
                    "raw_data": {
                        "username": username,
                        "sudo_failures": len(evts),
                        "severity_reason": "3+ failures" if len(evts) >= 3 else "sudo auth failure detected",
                        "sample_lines": [e.get("raw_line", "") for e in evts[:3]],
                    },
                })
            except Exception:
                continue

    except Exception:
        pass

    return threats


def detect_repeated_auth_failures(events: list[dict[str, Any]], threshold: int) -> list[dict[str, Any]]:
    """
    Rule 5: Repeated Authentication Failure Detection.

    Triggers when: 10+ failures are recorded for the SAME username,
    regardless of source IP. This catches password-spray and account
    lockout attempts targeting specific users.

    Args:
        events: List of parsed log event dicts.
        threshold: Number of failures to trigger.

    Returns:
        List of threat dicts.
    """
    threats = []
    try:
        # Count failures per username
        user_fails: dict[str, list] = defaultdict(list)

        for event in events:
            try:
                event_type = event.get("event_type", "")
                if event_type in ("failed_login", "invalid_user", "sudo_failure"):
                    username = event.get("username", "")
                    if username:
                        user_fails[username].append(event)
            except Exception:
                continue

        # Flag users with too many failures
        for username, fail_evts in user_fails.items():
            try:
                if len(fail_evts) >= threshold:
                    # Collect all source IPs targeting this user
                    source_ips = list({e.get("source_ip", "") for e in fail_evts if e.get("source_ip")})
                    threats.append({
                        "threat_type": "REPEATED_AUTH_FAILURE",
                        "severity": "MEDIUM",
                        "source_ip": source_ips[0] if source_ips else "multiple",
                        "username": username,
                        "event_count": len(fail_evts),
                        "raw_data": {
                            "username": username,
                            "total_failures": len(fail_evts),
                            "threshold": threshold,
                            "source_ips": source_ips,
                            "note": f"Account '{username}' targeted with {len(fail_evts)} auth failures",
                            "sample_lines": [e.get("raw_line", "") for e in fail_evts[:3]],
                        },
                    })
            except Exception:
                continue

    except Exception:
        pass

    return threats


def run_all_detections(
    events: list[dict[str, Any]],
    config: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Run all 5 threat detection rules against a list of events.

    This is the main entry point for threat detection.
    Returns a deduplicated, severity-sorted list of all threats found.

    Args:
        events: List of parsed log event dicts from journal_parser or auth_parser.
        config: App config dict for custom thresholds (uses defaults if None).

    Returns:
        List of threat dicts sorted by severity (CRITICAL first).
        Empty list if no threats found or on error.
    """
    all_threats: list[dict[str, Any]] = []

    try:
        # Get detection thresholds from config
        thresholds = _get_thresholds(config)

        # Run each detection rule
        # Each function is independent — failure of one doesn't stop others
        try:
            brute_threats = detect_ssh_brute_force(
                events,
                threshold=thresholds["brute_force_attempts"],
            )
            all_threats.extend(brute_threats)
        except Exception:
            pass

        try:
            stuffing_threats = detect_credential_stuffing(
                events,
                threshold=thresholds["cred_stuffing_usernames"],
            )
            all_threats.extend(stuffing_threats)
        except Exception:
            pass

        try:
            root_threats = detect_root_login_attempts(events)
            all_threats.extend(root_threats)
        except Exception:
            pass

        try:
            sudo_threats = detect_sudo_abuse(events)
            all_threats.extend(sudo_threats)
        except Exception:
            pass

        try:
            repeat_threats = detect_repeated_auth_failures(
                events,
                threshold=thresholds["repeated_auth_failures"],
            )
            all_threats.extend(repeat_threats)
        except Exception:
            pass

        # ── Deduplicate: remove threats with same type+IP that overlap ────
        seen = set()
        deduped = []
        for threat in all_threats:
            try:
                key = (threat.get("threat_type"), threat.get("source_ip"), threat.get("username"))
                if key not in seen:
                    seen.add(key)
                    deduped.append(threat)
            except Exception:
                deduped.append(threat)

        # ── Sort by severity (CRITICAL → HIGH → MEDIUM → LOW → INFO) ─────
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        try:
            deduped.sort(key=lambda t: severity_order.get(t.get("severity", "INFO"), 4))
        except Exception:
            pass

        return deduped

    except Exception:
        # Return whatever we collected before the error
        return all_threats
