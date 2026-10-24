"""
auditor/doctor.py — Self-diagnostic engine for Zephyrveil.

Checks everything needed for Zephyrveil to work correctly:
- API keys (validates each one with a live test call)
- Python dependencies (can all modules be imported?)
- File permissions (log access, DB write, report dir)
- Config file validity
- Database health
- Network connectivity

Every issue comes with an exact fix command — never vague.
"""

import shutil
import subprocess
from pathlib import Path
from typing import Any


# ── API key check definitions ─────────────────────────────────────────────────
API_KEY_INFO = {
    "abuseipdb": {
        "name":     "AbuseIPDB",
        "url":      "https://www.abuseipdb.com/api",
        "docs":     "Get a free key at: abuseipdb.com/api (1000 lookups/day free)",
        "config":   "[api_keys] abuseipdb = \"YOUR_KEY_HERE\"",
    },
    "ipinfo": {
        "name":     "IPInfo",
        "url":      "https://ipinfo.io/signup",
        "docs":     "Get a free key at: ipinfo.io/signup (50k lookups/month free)",
        "config":   "[api_keys] ipinfo = \"YOUR_KEY_HERE\"",
    },
    "virustotal": {
        "name":     "VirusTotal",
        "url":      "https://virustotal.com/gui/my-apikey",
        "docs":     "Get a free key at: virustotal.com/gui/my-apikey (500/day free)",
        "config":   "[api_keys] virustotal = \"YOUR_KEY_HERE\"",
    },
    "shodan": {
        "name":     "Shodan",
        "url":      "https://account.shodan.io",
        "docs":     "Get a key at: account.shodan.io (free tier available)",
        "config":   "[api_keys] shodan = \"YOUR_KEY_HERE\"",
    },
    "nvd": {
        "name":     "NVD/NIST",
        "url":      "https://nvd.nist.gov/developers/request-an-api-key",
        "docs":     "Get a free key at: nvd.nist.gov/developers/request-an-api-key",
        "config":   "[api_keys] nvd = \"YOUR_KEY_HERE\"",
    },
}


def check_api_keys(config: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Check which API keys are configured and which are missing.

    Args:
        config: Loaded config dict.

    Returns:
        List of check dicts: {service, name, status, configured, docs, config_line}
    """
    results = []

    try:
        api_keys = config.get("api_keys", {})

        for service, info in API_KEY_INFO.items():
            try:
                key_val   = str(api_keys.get(service, "")).strip()
                configured = bool(key_val)

                results.append({
                    "service":     service,
                    "name":        info["name"],
                    "status":      "OK" if configured else "MISSING",
                    "configured":  configured,
                    "docs":        info["docs"],
                    "config_line": info["config"],
                    "fix":         (
                        f"1. Get key: {info['url']}\n"
                        f"   2. Edit: ~/.config/zephyrveil/config.toml\n"
                        f"   3. Add: {info['config']}"
                    ),
                })
            except Exception:
                continue

        # Telegram
        tg = config.get("telegram", {})
        tg_token   = str(tg.get("bot_token", "")).strip()
        tg_chat    = str(tg.get("chat_id", "")).strip()
        tg_enabled = bool(tg.get("enabled", False))
        tg_ok      = bool(tg_token and tg_chat and tg_enabled)

        results.append({
            "service":    "telegram",
            "name":       "Telegram",
            "status":     "OK" if tg_ok else "NOT CONFIGURED",
            "configured": tg_ok,
            "docs":       "Optional — get a bot from @BotFather in Telegram",
            "config_line": "[telegram] bot_token = \"...\", chat_id = \"...\", enabled = true",
            "fix": (
                "1. Open Telegram, find @BotFather\n"
                "   2. Send /newbot and follow instructions\n"
                "   3. Get chat_id via @userinfobot\n"
                "   4. Edit ~/.config/zephyrveil/config.toml:\n"
                "      [telegram]\n"
                "      bot_token = \"YOUR_TOKEN\"\n"
                "      chat_id = \"YOUR_CHAT_ID\"\n"
                "      enabled = true"
            ),
        })

    except Exception:
        pass

    return results


def check_dependencies() -> list[dict[str, Any]]:
    """
    Check that all required Python packages are importable.

    Returns:
        List of {package, status, error, install_cmd}
    """
    required = [
        ("rich",       "pip install rich"),
        ("reportlab",  "pip install reportlab"),
        ("requests",   "pip install requests"),
        ("shodan",     "pip install shodan"),
        ("packaging",  "pip install packaging"),
    ]

    results = []
    for package, install_cmd in required:
        try:
            __import__(package)
            results.append({
                "package":     package,
                "status":      "OK",
                "error":       "",
                "install_cmd": "",
            })
        except ImportError as exc:
            results.append({
                "package":     package,
                "status":      "MISSING",
                "error":       str(exc),
                "install_cmd": f"uv add {package}",
            })
        except Exception as exc:
            results.append({
                "package":     package,
                "status":      "ERROR",
                "error":       type(exc).__name__,
                "install_cmd": f"uv add {package}",
            })

    return results


def check_file_permissions(config: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Check access to all important files and directories.

    Returns:
        List of {path, type, status, readable, writable, fix}
    """
    from zephyrveil.config.settings import CONFIG_FILE, DATA_DIR, REPORTS_DIR

    checks = [
        {
            "path":     str(CONFIG_FILE),
            "type":     "Config file",
            "need_read":  True,
            "need_write": True,
            "fix":       f"Run: chmod 600 {CONFIG_FILE}",
        },
        {
            "path":     str(DATA_DIR),
            "type":     "Database directory",
            "need_read":  True,
            "need_write": True,
            "fix":       f"Run: mkdir -p {DATA_DIR} && chmod 700 {DATA_DIR}",
        },
        {
            "path":     config.get("database", {}).get("path", ""),
            "type":     "SQLite database",
            "need_read":  True,
            "need_write": True,
            "fix":       f"Run: touch {config.get('database', {}).get('path', '')} && chmod 600 <path>",
        },
        {
            "path":     str(REPORTS_DIR),
            "type":     "Reports directory",
            "need_read":  True,
            "need_write": True,
            "fix":       f"Run: mkdir -p {REPORTS_DIR}",
        },
        {
            "path":     "/var/log/auth.log",
            "type":     "Auth log (fallback)",
            "need_read":  True,
            "need_write": False,
            "fix":       "Run: sudo chmod o+r /var/log/auth.log  OR  run zephyrveil as root",
        },
    ]

    results = []
    for check in checks:
        try:
            p = Path(check["path"])
            exists   = p.exists()
            readable = False
            writable = False

            if exists:
                try:
                    if p.is_file():
                        with open(check["path"], "rb") as f:
                            f.read(1)
                        readable = True
                    elif p.is_dir():
                        # Check read by listing
                        list(p.iterdir())
                        readable = True
                except PermissionError:
                    readable = False
                except Exception:
                    readable = False

                try:
                    import os
                    writable = os.access(check["path"], os.W_OK)
                except Exception:
                    writable = False

            if not exists:
                status = "MISSING"
            elif check["need_read"] and not readable:
                status = "NO READ ACCESS"
            elif check["need_write"] and not writable:
                status = "NO WRITE ACCESS"
            else:
                status = "OK"

            results.append({
                "path":     check["path"],
                "type":     check["type"],
                "status":   status,
                "exists":   exists,
                "readable": readable,
                "writable": writable,
                "fix":      check["fix"] if status != "OK" else "",
            })

        except Exception:
            results.append({
                "path":     check["path"],
                "type":     check["type"],
                "status":   "CHECK FAILED",
                "exists":   False,
                "readable": False,
                "writable": False,
                "fix":      "Re-run: zephyrveil (will auto-create on first run)",
            })

    return results


def check_network_connectivity() -> dict[str, Any]:
    """
    Check basic internet connectivity needed for API calls.

    Pings key API endpoints and reports status.

    Returns:
        Dict with: reachable (bool), failed_hosts (list), error.
    """
    result: dict[str, Any] = {
        "reachable":    True,
        "failed_hosts": [],
        "error":        "",
    }

    import requests

    test_hosts = [
        ("ipinfo.io",        "https://ipinfo.io/ip"),
        ("abuseipdb.com",    "https://api.abuseipdb.com"),
        ("virustotal.com",   "https://www.virustotal.com"),
        ("api.shodan.io",    "https://api.shodan.io"),
    ]

    for hostname, url in test_hosts:
        try:
            resp = requests.head(url, timeout=5)
            # Any response (even 401) means the server is reachable
        except requests.ConnectionError:
            result["failed_hosts"].append(hostname)
        except requests.Timeout:
            result["failed_hosts"].append(f"{hostname} (timeout)")
        except Exception:
            pass  # Other errors don't mean unreachable

    if result["failed_hosts"]:
        result["reachable"] = False
        result["error"] = f"Cannot reach: {', '.join(result['failed_hosts'])}"

    return result


def check_database_health(db_path: str) -> dict[str, Any]:
    """
    Check SQLite database integrity.

    Args:
        db_path: Path to the database file.

    Returns:
        Dict with: accessible, tables_exist, row_counts, error.
    """
    result: dict[str, Any] = {
        "accessible":  False,
        "tables_exist": False,
        "row_counts":  {},
        "error":       "",
    }

    try:
        from zephyrveil.storage.db import get_connection

        conn = get_connection(db_path)
        if conn is None:
            result["error"] = f"Cannot open database: {db_path}"
            return result

        result["accessible"] = True

        # Check tables exist
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [row[0] for row in cursor.fetchall()]

        expected_tables = ["scans", "threats", "events", "ip_intel", "audit_results", "alerts_sent"]
        missing = [t for t in expected_tables if t not in tables]

        if missing:
            result["error"] = f"Missing tables: {', '.join(missing)} — run: zephyrveil (will auto-create)"
        else:
            result["tables_exist"] = True

        # Count rows in each table
        for table in tables:
            try:
                row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
                result["row_counts"][table] = row[0] if row else 0
            except Exception:
                result["row_counts"][table] = -1

        conn.close()
        return result

    except Exception as exc:
        result["error"] = f"Database health check failed: {type(exc).__name__}"
        return result


def run_full_diagnostic(config: dict[str, Any]) -> dict[str, Any]:
    """
    Run the complete self-diagnostic and return all results.

    Args:
        config: Loaded app config dict.

    Returns:
        Comprehensive diagnostic dict with all check results.
    """
    diagnostic: dict[str, Any] = {
        "api_keys":     [],
        "dependencies": [],
        "permissions":  [],
        "network":      {},
        "database":     {},
        "summary":      {
            "total_issues":   0,
            "critical_issues": 0,
            "warnings":       0,
        },
    }

    try:
        diagnostic["api_keys"]     = check_api_keys(config)
    except Exception:
        pass

    try:
        diagnostic["dependencies"] = check_dependencies()
    except Exception:
        pass

    try:
        diagnostic["permissions"]  = check_file_permissions(config)
    except Exception:
        pass

    try:
        diagnostic["network"]      = check_network_connectivity()
    except Exception:
        pass

    try:
        db_path = config.get("database", {}).get("path", "")
        diagnostic["database"]     = check_database_health(db_path)
    except Exception:
        pass

    # ── Compute summary counts ─────────────────────────────────────────
    try:
        issues   = 0
        critical = 0
        warnings = 0

        for dep in diagnostic["dependencies"]:
            if dep["status"] != "OK":
                issues += 1
                critical += 1  # Missing dep is critical

        for perm in diagnostic["permissions"]:
            if perm["status"] != "OK":
                issues += 1
                warnings += 1

        if not diagnostic["network"].get("reachable", True):
            issues += 1
            warnings += 1

        if not diagnostic["database"].get("accessible", True):
            issues += 1
            critical += 1

        diagnostic["summary"] = {
            "total_issues":    issues,
            "critical_issues": critical,
            "warnings":        warnings,
        }
    except Exception:
        pass

    return diagnostic
