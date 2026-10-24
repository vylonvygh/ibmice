"""
reporter/json_report.py — JSON report generation for Zephyrveil.

Exports all scan data to a structured JSON file.
Every scan creates a new file — never overwrites.
Filename includes timestamp: zephyrveil_report_2025-01-15_14-32-05.json

JSON structure contains everything:
- Scan metadata
- All detected threats
- All IP intelligence results
- All audit results
- All log events (summary)
- System info
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any


def generate_json_report(
    scan_data: dict[str, Any],
    output_dir: str,
) -> tuple[bool, str]:
    """
    Generate a JSON report file from scan data.

    Args:
        scan_data: Complete scan data dict containing all results.
        output_dir: Directory to save the report in.

    Returns:
        Tuple of (success: bool, filepath_or_error: str).
        On success, returns the path to the created file.
        On failure, returns an error description.
    """
    try:
        # ── Build output path with timestamp ─────────────────────────────
        output_path = Path(output_dir).expanduser()
        output_path.mkdir(parents=True, exist_ok=True)

        timestamp  = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        scan_id    = scan_data.get("scan_id", "unknown")
        filename   = f"zephyrveil_report_{timestamp}.json"
        filepath   = output_path / filename

        # ── Build the report structure ────────────────────────────────────
        report = {
            "report_metadata": {
                "generated_at":   datetime.now().isoformat(),
                "generator":      "Zephyrveil v1.0.0",
                "report_type":    "security_scan",
                "format_version": "1.0",
            },
            "scan_info": {
                "scan_id":       scan_id,
                "started_at":    scan_data.get("started_at", ""),
                "finished_at":   scan_data.get("finished_at", datetime.now().isoformat()),
                "log_source":    scan_data.get("source", ""),
                "hostname":      scan_data.get("hostname", ""),
                "kernel":        scan_data.get("kernel", ""),
                "total_events":  scan_data.get("event_count", 0),
                "total_threats": len(scan_data.get("threats", [])),
                "total_ips":     len(scan_data.get("ip_intel", [])),
            },
            "threats": _serialize_threats(scan_data.get("threats", [])),
            "ip_intelligence": _serialize_ip_intel(scan_data.get("ip_intel", [])),
            "system_audit": {
                "tools":    scan_data.get("audit_tools", {}),
                "network":  scan_data.get("audit_network", {}),
                "health":   scan_data.get("audit_health", {}),
                "hygiene":  scan_data.get("audit_hygiene", {}),
                "cve_check": scan_data.get("audit_cve", {}),
            },
            "events_summary": _summarize_events(scan_data.get("events", [])),
        }

        # ── Write JSON to file ────────────────────────────────────────────
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

        return True, str(filepath)

    except PermissionError:
        return False, f"Cannot write to {output_dir} — check directory permissions"
    except OSError as exc:
        return False, f"File system error writing JSON report: {exc.strerror}"
    except Exception as exc:
        return False, f"JSON report generation failed: {type(exc).__name__}"


def _serialize_threats(threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Prepare threats list for JSON serialization."""
    serialized = []
    for threat in threats:
        try:
            t = dict(threat)
            # Ensure raw_data is a dict not a string
            if isinstance(t.get("raw_data"), str):
                try:
                    t["raw_data"] = json.loads(t["raw_data"])
                except Exception:
                    pass
            serialized.append(t)
        except Exception:
            continue
    return serialized


def _serialize_ip_intel(ip_intel: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Prepare IP intel list for JSON serialization."""
    serialized = []
    for intel in ip_intel:
        try:
            item = dict(intel)
            # Deserialize JSON strings stored in DB
            for field in ("shodan_ports", "shodan_vulns", "raw_ipinfo",
                          "raw_abuseipdb", "raw_virustotal", "raw_shodan"):
                if isinstance(item.get(field), str):
                    try:
                        item[field] = json.loads(item[field])
                    except Exception:
                        pass
            serialized.append(item)
        except Exception:
            continue
    return serialized


def _summarize_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a summary of log events for the report."""
    try:
        event_types: dict[str, int] = {}
        source_ips: dict[str, int]  = {}

        for event in events:
            try:
                etype = event.get("event_type", "unknown")
                event_types[etype] = event_types.get(etype, 0) + 1

                ip = event.get("source_ip", "")
                if ip:
                    source_ips[ip] = source_ips.get(ip, 0) + 1
            except Exception:
                continue

        # Top 10 most active IPs
        top_ips = sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_events":       len(events),
            "event_type_counts":  event_types,
            "unique_source_ips":  len(source_ips),
            "top_attacking_ips":  [{"ip": ip, "events": count} for ip, count in top_ips],
        }
    except Exception:
        return {"total_events": len(events)}
