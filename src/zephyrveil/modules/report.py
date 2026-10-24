"""
modules/report.py — Report generation module.

'use report' generates a PDF and/or JSON report from the last scan.
Each report has a unique timestamp in the filename — never overwrites.
"""

from datetime import datetime
from typing import Any

from rich.console import Console

from zephyrveil.console.output import (
    print_error,
    print_info,
    print_section,
    print_success,
    print_warning,
)
from zephyrveil.modules.base import BaseModule


class ReportModule(BaseModule):
    """Report generation module — PDF and JSON from last scan data."""

    NAME = "report"
    DESCRIPTION = "Generate PDF and/or JSON report from the last scan"

    DEFAULT_OPTIONS = {
        "FORMAT": ("all", "Output format: pdf, json, html, or all"),
        "OUTPUT": ("", "Output directory (default: ~/Documents/zephyrveil/)"),
    }

    def run(self, console: Console) -> None:
        """
        Generate report(s) from the last scan stored in SQLite.

        Steps:
        1. Get the last scan_id from the DB
        2. Pull all data for that scan
        3. Generate PDF and/or JSON
        4. Show output file paths
        """
        try:
            fmt = self.options.get("FORMAT", "both").lower()
            output_dir = (
                self.options.get("OUTPUT", "").strip() or self.get_reports_dir()
            )

            print_section(console, "REPORT GENERATION")

            # ── Get last scan data ────────────────────────────────────────
            print_info(console, "Loading last scan from database...")
            scan_data = self._load_last_scan()

            if not scan_data:
                print_error(
                    console,
                    "No previous scan found — run 'use scan' first to generate data",
                )
                return

            scan_id = scan_data.get("scan_id", "unknown")
            threat_count = len(scan_data.get("threats", []))
            ip_count = len(scan_data.get("ip_intel", []))

            print_success(console, f"Loaded scan: {scan_id}")
            print_success(
                console, f"Threats: {threat_count}  |  IPs analyzed: {ip_count}"
            )
            console.print()

            # ── Generate reports ──────────────────────────────────────────
            generated = []

            if fmt in ("pdf", "all"):
                print_info(console, "Generating PDF report...")
                try:
                    from zephyrveil.reporter.pdf_report import generate_pdf_report

                    ok, path_or_err = generate_pdf_report(scan_data, output_dir)
                    if ok:
                        print_success(console, f"PDF saved: {path_or_err}")
                        generated.append(("PDF", path_or_err))
                    else:
                        print_error(console, f"PDF failed: {path_or_err}")
                except Exception as exc:
                    print_error(console, f"PDF generation error: {type(exc).__name__}")

            if fmt in ("json", "all"):
                print_info(console, "Generating JSON report...")
                try:
                    from zephyrveil.reporter.json_report import generate_json_report

                    ok, path_or_err = generate_json_report(scan_data, output_dir)
                    if ok:
                        print_success(console, f"JSON saved: {path_or_err}")
                        generated.append(("JSON", path_or_err))
                    else:
                        print_error(console, f"JSON failed: {path_or_err}")
                except Exception as exc:
                    print_error(console, f"JSON generation error: {type(exc).__name__}")

            if fmt in ("html", "all"):
                print_info(console, "Generating HTML report...")
                try:
                    from zephyrveil.reporter.html_report import generate_html_report

                    ok, path_or_err = generate_html_report(scan_data, output_dir)
                    if ok:
                        print_success(console, f"HTML saved: {path_or_err}")
                        generated.append(("HTML", path_or_err))
                    else:
                        print_error(console, f"HTML failed: {path_or_err}")
                except Exception as exc:
                    print_error(console, f"HTML generation error: {type(exc).__name__}")

            console.print()
            if generated:
                print_section(console, "REPORTS READY")
                for fmt_name, path in generated:
                    console.print(
                        f"  [bold green]✓[/bold green] [{fmt_name}] [bold white]{path}[/bold white]"
                    )
                console.print()
            else:
                print_error(
                    console,
                    "No reports were generated — check permissions and try again",
                )

        except KeyboardInterrupt:
            print_warning(console, "Report generation interrupted")
        except Exception:
            print_error(
                console, "Report module encountered an error — try 'use doctor'"
            )

    def _load_last_scan(self) -> dict[str, Any] | None:
        """Load all data from the most recent scan in the database."""
        try:
            import json

            from zephyrveil.storage.db import (
                get_last_scan_id,
                get_recent_scans,
                get_scan_audit_results,
                get_scan_events,
                get_scan_ip_intel,
                get_scan_threats,
            )

            db_path = self.get_db_path()

            # Get the last finished scan
            scan_id = get_last_scan_id(db_path)
            if not scan_id:
                # Try any scan
                scans = get_recent_scans(db_path, limit=1)
                if not scans:
                    return None
                scan_id = scans[0].get("scan_id")

            if not scan_id:
                return None

            # Get the scan metadata
            scans = get_recent_scans(db_path, limit=50)
            scan_row = next((s for s in scans if s.get("scan_id") == scan_id), {})

            # Pull all related data
            threats = get_scan_threats(db_path, scan_id)
            ip_intel = get_scan_ip_intel(db_path, scan_id)
            events = get_scan_events(db_path, scan_id)
            audit_rows = get_scan_audit_results(db_path, scan_id)

            # Deserialize audit results
            audit_by_type: dict[str, Any] = {}
            for row in audit_rows:
                atype = row.get("audit_type", "")
                try:
                    audit_by_type[atype] = json.loads(row.get("result_json", "{}"))
                except Exception:
                    audit_by_type[atype] = {}

            # Build comprehensive scan_data dict
            scan_data: dict[str, Any] = {
                "scan_id": scan_id,
                "started_at": scan_row.get("started_at", ""),
                "finished_at": scan_row.get("finished_at", ""),
                "source": scan_row.get("source", ""),
                "threats": threats,
                "ip_intel": ip_intel,
                "events": events,
                "event_count": len(events),
                "audit_tools": audit_by_type.get(
                    "health_tools", audit_by_type.get("scan_tools", {})
                ),
                "audit_network": audit_by_type.get(
                    "health_network", audit_by_type.get("scan_network", {})
                ),
                "audit_health": audit_by_type.get(
                    "health_health", audit_by_type.get("scan_health", {})
                ),
                "audit_hygiene": audit_by_type.get(
                    "health_hygiene", audit_by_type.get("scan_hygiene", {})
                ),
                "audit_cve": audit_by_type.get(
                    "health_cve", audit_by_type.get("scan_cve", {})
                ),
            }

            # Add hostname/kernel from health data if available
            health = scan_data.get("audit_health", {})
            if isinstance(health, dict):
                scan_data["hostname"] = health.get("hostname", "")
                scan_data["kernel"] = health.get("kernel", "")

            return scan_data

        except Exception:
            return None
