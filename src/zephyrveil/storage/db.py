"""
storage/db.py — SQLite database layer for Zephyrveil.

This module handles:
- Creating the database and all tables on first run
- Inserting scan sessions, threats, events, IP intel, audit results, alerts
- Querying history for IPs and scan sessions
- Never overwrites — always appends new rows
- All operations wrapped in try/except — never expose raw SQLite errors

Tables:
    scans         - every scan session
    threats       - every threat detected
    events        - every raw log event
    ip_intel      - every IP enrichment result
    audit_results - every health/audit run result
    alerts_sent   - every Telegram alert sent
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Any


# ── Schema SQL ───────────────────────────────────────────────────────────────

CREATE_SCANS_TABLE = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL UNIQUE,   -- UUID or timestamp-based unique ID
    started_at  TEXT NOT NULL,          -- ISO timestamp
    finished_at TEXT,                   -- ISO timestamp, filled after scan ends
    source      TEXT,                   -- log source used (journalctl, auth.log, path)
    threat_count INTEGER DEFAULT 0,
    event_count  INTEGER DEFAULT 0,
    ip_count     INTEGER DEFAULT 0,
    notes        TEXT                   -- any free-form notes
)
"""

CREATE_THREATS_TABLE = """
CREATE TABLE IF NOT EXISTS threats (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT NOT NULL,         -- references scans.scan_id
    detected_at  TEXT NOT NULL,         -- ISO timestamp
    threat_type  TEXT NOT NULL,         -- e.g. SSH_BRUTE_FORCE
    severity     TEXT NOT NULL,         -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    source_ip    TEXT,                  -- attacker IP if known
    username     TEXT,                  -- targeted username if known
    event_count  INTEGER DEFAULT 1,     -- number of events triggering this threat
    raw_data     TEXT                   -- JSON blob of all raw details
)
"""

CREATE_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT NOT NULL,
    occurred_at  TEXT,                  -- timestamp from log line
    inserted_at  TEXT NOT NULL,         -- when we inserted this row
    source       TEXT,                  -- log source file/command
    source_ip    TEXT,
    username     TEXT,
    event_type   TEXT,                  -- failed_login, accepted_login, sudo, etc.
    raw_line     TEXT                   -- original log line
)
"""

CREATE_IP_INTEL_TABLE = """
CREATE TABLE IF NOT EXISTS ip_intel (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT,
    queried_at      TEXT NOT NULL,
    ip_address      TEXT NOT NULL,
    country         TEXT,
    city            TEXT,
    org             TEXT,
    isp             TEXT,
    asn             TEXT,
    hostname        TEXT,
    abuse_score     INTEGER,            -- AbuseIPDB confidence score 0-100
    abuse_reports   INTEGER,           -- number of abuse reports
    vt_malicious    INTEGER,           -- VirusTotal malicious engine count
    vt_total        INTEGER,           -- VirusTotal total engines
    shodan_ports    TEXT,              -- JSON list of open ports
    shodan_vulns    TEXT,              -- JSON list of CVEs from Shodan
    shodan_org      TEXT,
    fail2ban_banned INTEGER DEFAULT 0, -- 1 if currently banned locally
    raw_ipinfo      TEXT,              -- full JSON from IPInfo
    raw_abuseipdb   TEXT,             -- full JSON from AbuseIPDB
    raw_virustotal  TEXT,             -- full JSON from VirusTotal
    raw_shodan      TEXT              -- full JSON from Shodan
)
"""

CREATE_AUDIT_RESULTS_TABLE = """
CREATE TABLE IF NOT EXISTS audit_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT,
    audited_at  TEXT NOT NULL,
    audit_type  TEXT NOT NULL,          -- tool_check, network, system_health, hygiene, cve
    result_json TEXT NOT NULL           -- full JSON blob of audit output
)
"""

CREATE_ALERTS_SENT_TABLE = """
CREATE TABLE IF NOT EXISTS alerts_sent (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT,
    sent_at     TEXT NOT NULL,
    platform    TEXT NOT NULL,          -- telegram
    status      TEXT NOT NULL,          -- sent, failed
    message     TEXT,
    error       TEXT                    -- error message if failed
)
"""


def get_connection(db_path: str) -> sqlite3.Connection | None:
    """
    Open a SQLite connection with row_factory set to Row for dict-like access.

    Args:
        db_path: Absolute path to the .db file.

    Returns:
        sqlite3.Connection or None if connection fails.
        Caller must handle None gracefully.
    """
    try:
        # Ensure parent directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(db_path, check_same_thread=False)
        # row_factory lets us access columns by name: row["scan_id"]
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for better concurrent access
        conn.execute("PRAGMA journal_mode=WAL")
        # Enforce foreign keys
        conn.execute("PRAGMA foreign_keys=ON")
        return conn
    except sqlite3.OperationalError as exc:
        # Return None — caller will show user-friendly message
        return None
    except Exception:
        return None


def initialize_database(db_path: str) -> tuple[bool, str]:
    """
    Create all tables if they don't exist. Safe to call every launch.

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        (success: bool, message: str)
        success=True means DB is ready to use.
    """
    conn = get_connection(db_path)
    if conn is None:
        return False, f"Cannot open database at {db_path} — check permissions"

    try:
        cursor = conn.cursor()
        # Create all tables — CREATE IF NOT EXISTS is idempotent
        cursor.execute(CREATE_SCANS_TABLE)
        cursor.execute(CREATE_THREATS_TABLE)
        cursor.execute(CREATE_EVENTS_TABLE)
        cursor.execute(CREATE_IP_INTEL_TABLE)
        cursor.execute(CREATE_AUDIT_RESULTS_TABLE)
        cursor.execute(CREATE_ALERTS_SENT_TABLE)
        conn.commit()
        conn.close()
        return True, "Database ready"
    except sqlite3.OperationalError as exc:
        return False, f"Database schema error — {exc}"
    except sqlite3.DatabaseError as exc:
        return False, f"Database error — {exc}"
    except Exception as exc:
        return False, f"Unexpected database error — {exc}"


# ── Insert operations ────────────────────────────────────────────────────────

def insert_scan(db_path: str, scan_id: str, source: str) -> bool:
    """
    Insert a new scan session row.

    Args:
        db_path: Database path.
        scan_id: Unique scan identifier (e.g. timestamp-based).
        source: Log source used for this scan.

    Returns:
        True on success, False on failure.
    """
    conn = get_connection(db_path)
    if conn is None:
        return False
    try:
        now = datetime.now().isoformat()
        conn.execute(
            "INSERT OR IGNORE INTO scans (scan_id, started_at, source) VALUES (?, ?, ?)",
            (scan_id, now, source),
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        # scan_id already exists — not an error, skip silently
        conn.close()
        return True
    except sqlite3.OperationalError:
        return False
    except Exception:
        return False


def finish_scan(db_path: str, scan_id: str, threat_count: int, event_count: int, ip_count: int) -> bool:
    """
    Update a scan row with finished timestamp and summary counts.

    Args:
        db_path: Database path.
        scan_id: Scan to update.
        threat_count: Number of threats detected.
        event_count: Number of log events parsed.
        ip_count: Number of unique IPs seen.

    Returns:
        True on success.
    """
    conn = get_connection(db_path)
    if conn is None:
        return False
    try:
        now = datetime.now().isoformat()
        conn.execute(
            """UPDATE scans
               SET finished_at=?, threat_count=?, event_count=?, ip_count=?
               WHERE scan_id=?""",
            (now, threat_count, event_count, ip_count, scan_id),
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def insert_threat(db_path: str, scan_id: str, threat: dict[str, Any]) -> bool:
    """
    Save a detected threat to the threats table.

    Args:
        db_path: Database path.
        scan_id: Associated scan ID.
        threat: Dict with keys: threat_type, severity, source_ip, username,
                event_count, raw_data (dict).

    Returns:
        True on success.
    """
    conn = get_connection(db_path)
    if conn is None:
        return False
    try:
        now = datetime.now().isoformat()
        raw_json = json.dumps(threat.get("raw_data", {}))
        conn.execute(
            """INSERT INTO threats
               (scan_id, detected_at, threat_type, severity, source_ip, username, event_count, raw_data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                now,
                threat.get("threat_type", "UNKNOWN"),
                threat.get("severity", "INFO"),
                threat.get("source_ip", ""),
                threat.get("username", ""),
                threat.get("event_count", 1),
                raw_json,
            ),
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.OperationalError:
        return False
    except Exception:
        return False


def insert_event(db_path: str, scan_id: str, event: dict[str, Any]) -> bool:
    """
    Save a raw log event to the events table.

    Args:
        db_path: Database path.
        scan_id: Associated scan ID.
        event: Dict with keys: occurred_at, source, source_ip, username,
               event_type, raw_line.

    Returns:
        True on success.
    """
    conn = get_connection(db_path)
    if conn is None:
        return False
    try:
        now = datetime.now().isoformat()
        conn.execute(
            """INSERT INTO events
               (scan_id, occurred_at, inserted_at, source, source_ip, username, event_type, raw_line)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                event.get("occurred_at", ""),
                now,
                event.get("source", ""),
                event.get("source_ip", ""),
                event.get("username", ""),
                event.get("event_type", ""),
                event.get("raw_line", ""),
            ),
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def insert_ip_intel(db_path: str, scan_id: str, intel: dict[str, Any]) -> bool:
    """
    Save enriched IP intelligence data to the ip_intel table.

    Args:
        db_path: Database path.
        scan_id: Associated scan ID.
        intel: Dict with all IP intelligence fields.

    Returns:
        True on success.
    """
    conn = get_connection(db_path)
    if conn is None:
        return False
    try:
        now = datetime.now().isoformat()
        conn.execute(
            """INSERT INTO ip_intel
               (scan_id, queried_at, ip_address, country, city, org, isp, asn, hostname,
                abuse_score, abuse_reports, vt_malicious, vt_total,
                shodan_ports, shodan_vulns, shodan_org, fail2ban_banned,
                raw_ipinfo, raw_abuseipdb, raw_virustotal, raw_shodan)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                now,
                intel.get("ip_address", ""),
                intel.get("country", ""),
                intel.get("city", ""),
                intel.get("org", ""),
                intel.get("isp", ""),
                intel.get("asn", ""),
                intel.get("hostname", ""),
                intel.get("abuse_score", 0),
                intel.get("abuse_reports", 0),
                intel.get("vt_malicious", 0),
                intel.get("vt_total", 0),
                json.dumps(intel.get("shodan_ports", [])),
                json.dumps(intel.get("shodan_vulns", [])),
                intel.get("shodan_org", ""),
                1 if intel.get("fail2ban_banned") else 0,
                json.dumps(intel.get("raw_ipinfo", {})),
                json.dumps(intel.get("raw_abuseipdb", {})),
                json.dumps(intel.get("raw_virustotal", {})),
                json.dumps(intel.get("raw_shodan", {})),
            ),
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def insert_audit_result(db_path: str, scan_id: str, audit_type: str, result: dict[str, Any]) -> bool:
    """
    Save an audit result (health check output) to the audit_results table.

    Args:
        db_path: Database path.
        scan_id: Associated scan ID.
        audit_type: Type label like 'tool_check', 'network', 'system_health', etc.
        result: Audit result dict — serialized to JSON.

    Returns:
        True on success.
    """
    conn = get_connection(db_path)
    if conn is None:
        return False
    try:
        now = datetime.now().isoformat()
        conn.execute(
            """INSERT INTO audit_results (scan_id, audited_at, audit_type, result_json)
               VALUES (?, ?, ?, ?)""",
            (scan_id, now, audit_type, json.dumps(result)),
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def insert_alert(db_path: str, scan_id: str, platform: str, status: str,
                 message: str, error: str = "") -> bool:
    """
    Record a sent (or failed) Telegram alert.

    Args:
        db_path: Database path.
        scan_id: Associated scan ID.
        platform: e.g. "telegram"
        status: "sent" or "failed"
        message: The message text that was sent.
        error: Error description if status is "failed".

    Returns:
        True on success.
    """
    conn = get_connection(db_path)
    if conn is None:
        return False
    try:
        now = datetime.now().isoformat()
        conn.execute(
            """INSERT INTO alerts_sent (scan_id, sent_at, platform, status, message, error)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (scan_id, now, platform, status, message, error),
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


# ── Query operations ─────────────────────────────────────────────────────────

def get_ip_history(db_path: str, ip_address: str) -> list[dict[str, Any]]:
    """
    Retrieve all historical intel records for a given IP address.

    Args:
        db_path: Database path.
        ip_address: IP to look up.

    Returns:
        List of dicts (one per historic record), most recent first.
        Returns empty list if none found or on error.
    """
    conn = get_connection(db_path)
    if conn is None:
        return []
    try:
        cursor = conn.execute(
            "SELECT * FROM ip_intel WHERE ip_address=? ORDER BY queried_at DESC",
            (ip_address,),
        )
        rows = cursor.fetchall()
        conn.close()
        # Convert sqlite3.Row objects to plain dicts
        return [dict(row) for row in rows]
    except Exception:
        return []


def get_recent_scans(db_path: str, limit: int = 10) -> list[dict[str, Any]]:
    """
    Return the most recent scan sessions.

    Args:
        db_path: Database path.
        limit: Maximum number of scans to return.

    Returns:
        List of scan dicts, newest first.
    """
    conn = get_connection(db_path)
    if conn is None:
        return []
    try:
        cursor = conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?",
            (limit,),
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception:
        return []


def get_scan_threats(db_path: str, scan_id: str) -> list[dict[str, Any]]:
    """
    Return all threats detected in a specific scan.

    Args:
        db_path: Database path.
        scan_id: Scan to query.

    Returns:
        List of threat dicts.
    """
    conn = get_connection(db_path)
    if conn is None:
        return []
    try:
        cursor = conn.execute(
            "SELECT * FROM threats WHERE scan_id=? ORDER BY detected_at DESC",
            (scan_id,),
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception:
        return []


def get_scan_ip_intel(db_path: str, scan_id: str) -> list[dict[str, Any]]:
    """
    Return all IP intel records for a specific scan.

    Args:
        db_path: Database path.
        scan_id: Scan to query.

    Returns:
        List of ip_intel dicts.
    """
    conn = get_connection(db_path)
    if conn is None:
        return []
    try:
        cursor = conn.execute(
            "SELECT * FROM ip_intel WHERE scan_id=? ORDER BY queried_at DESC",
            (scan_id,),
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception:
        return []


def get_last_scan_id(db_path: str) -> str | None:
    """
    Return the scan_id of the most recently completed scan.

    Returns:
        scan_id string or None if no scans exist.
    """
    conn = get_connection(db_path)
    if conn is None:
        return None
    try:
        cursor = conn.execute(
            "SELECT scan_id FROM scans WHERE finished_at IS NOT NULL ORDER BY finished_at DESC LIMIT 1"
        )
        row = cursor.fetchone()
        conn.close()
        return row["scan_id"] if row else None
    except Exception:
        return None


def get_scan_events(db_path: str, scan_id: str) -> list[dict[str, Any]]:
    """
    Return all raw log events for a specific scan.

    Args:
        db_path: Database path.
        scan_id: Scan to query.

    Returns:
        List of event dicts.
    """
    conn = get_connection(db_path)
    if conn is None:
        return []
    try:
        cursor = conn.execute(
            "SELECT * FROM events WHERE scan_id=? ORDER BY occurred_at ASC",
            (scan_id,),
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception:
        return []


def get_scan_audit_results(db_path: str, scan_id: str) -> list[dict[str, Any]]:
    """
    Return all audit results for a specific scan.

    Args:
        db_path: Database path.
        scan_id: Scan to query.

    Returns:
        List of audit result dicts.
    """
    conn = get_connection(db_path)
    if conn is None:
        return []
    try:
        cursor = conn.execute(
            "SELECT * FROM audit_results WHERE scan_id=? ORDER BY audited_at ASC",
            (scan_id,),
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception:
        return []
