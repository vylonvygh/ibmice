"""
modules/ip.py — Single IP investigation module.

'use ip' in the console then 'set TARGET 1.2.3.4' then 'run'.

Pulls all log events for the IP, its full SQLite history,
and runs all threat intel APIs against it.
Shows everything in one detailed view.
"""

from datetime import datetime
from typing import Any
from rich.console import Console

from zephyrveil.modules.base import BaseModule
from zephyrveil.console.output import (
    print_section, print_success, print_warning, print_error, print_info,
    print_ip_intel_table,
)


class IPModule(BaseModule):
    """Single IP address investigation module."""

    NAME        = "ip"
    DESCRIPTION = "Investigate a single IP with all threat intel APIs + history"

    DEFAULT_OPTIONS = {
        "TARGET": ("", "IP address to investigate (required)"),
    }

    def run(self, console: Console) -> None:
        """
        Execute the IP investigation:
        1. Validate TARGET is set
        2. Pull log events for this IP from current logs
        3. Pull historical DB records for this IP
        4. Run all threat intel APIs
        5. Display everything together
        6. Save result to DB
        """
        try:
            target_ip = self.options.get("TARGET", "").strip()

            if not target_ip:
                print_error(console, "No target IP set — run: set TARGET <ip_address>")
                return

            # Basic IP format validation
            if not self._is_valid_ip_format(target_ip):
                print_error(console, f"'{target_ip}' does not look like a valid IP address")
                return

            print_section(console, f"IP INVESTIGATION: {target_ip}")

            # ── Step 1: Pull current log events for this IP ───────────────
            print_info(console, "Searching current logs for this IP...")
            log_events = self._find_ip_in_logs(target_ip)

            if log_events:
                print_success(console, f"Found {len(log_events)} log events for {target_ip}")
                self._show_log_events(console, log_events)
            else:
                print_info(console, f"No recent log events found for {target_ip}")
            console.print()

            # ── Step 2: Pull historical DB records ────────────────────────
            print_info(console, "Checking threat history database...")
            history = self._get_ip_history(target_ip)

            if history:
                print_success(console, f"Found {len(history)} historical records for {target_ip}")
                self._show_history_summary(console, history)
            else:
                print_info(console, "No previous records for this IP in the database")
            console.print()

            # ── Step 3: Run threat intel APIs ─────────────────────────────
            print_section(console, f"THREAT INTELLIGENCE: {target_ip}")
            intel = self._enrich_ip(console, target_ip)

            # Show the enriched intel table
            print_ip_intel_table(console, intel)

            # ── Step 4: Save to DB ────────────────────────────────────────
            self._save_to_db(target_ip, log_events, intel)
            print_success(console, "Investigation saved to database")

        except KeyboardInterrupt:
            print_warning(console, "IP investigation interrupted")
        except Exception:
            print_error(console, "IP module encountered an error — try 'use doctor'")

    def _is_valid_ip_format(self, ip: str) -> bool:
        """Basic IP format check — 4 octets each 0-255."""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            return all(0 <= int(p) <= 255 for p in parts)
        except Exception:
            return False

    def _find_ip_in_logs(self, ip: str) -> list[dict[str, Any]]:
        """Search current logs for events involving this IP."""
        try:
            from zephyrveil.parser.journal_parser import parse_journal, is_journalctl_available
            from zephyrveil.parser.auth_parser import parse_auth_log

            if is_journalctl_available():
                result = parse_journal(since="7d")  # Look back 7 days for IP lookup
            else:
                result = parse_auth_log()

            events = result.get("events", [])
            # Filter to only events involving this IP
            return [e for e in events if e.get("source_ip") == ip]

        except Exception:
            return []

    def _get_ip_history(self, ip: str) -> list[dict[str, Any]]:
        """Fetch all historical DB records for this IP."""
        try:
            from zephyrveil.storage.db import get_ip_history
            return get_ip_history(self.get_db_path(), ip)
        except Exception:
            return []

    def _show_log_events(self, console: Console, events: list[dict[str, Any]]) -> None:
        """Display log events for this IP in a table."""
        try:
            from rich.table import Table
            from rich import box

            table = Table(
                title="[bold white]Log Events for this IP[/bold white]",
                box=box.SIMPLE,
                border_style="dim",
                header_style="bold cyan",
            )
            table.add_column("Time",       style="dim white", width=20)
            table.add_column("Type",       style="cyan",      width=22)
            table.add_column("Username",   style="white",     width=16)
            table.add_column("Source",     style="dim",       width=16)

            for event in events[:30]:  # Show up to 30
                table.add_row(
                    event.get("occurred_at", "—")[:19],
                    event.get("event_type", "—").replace("_", " "),
                    event.get("username", "—"),
                    event.get("source", "—"),
                )

            console.print(table)

        except Exception:
            pass

    def _show_history_summary(self, console: Console, history: list[dict[str, Any]]) -> None:
        """Show a summary of historical database records for this IP."""
        try:
            latest = history[0]
            oldest = history[-1]

            console.print(
                f"  [dim]First seen:[/dim]  [white]{oldest.get('queried_at', '—')[:19]}[/white]\n"
                f"  [dim]Last seen:[/dim]   [white]{latest.get('queried_at', '—')[:19]}[/white]\n"
                f"  [dim]Total lookups:[/dim] [white]{len(history)}[/white]"
            )
        except Exception:
            pass

    def _enrich_ip(self, console: Console, ip: str) -> dict[str, Any]:
        """Run all threat intel APIs against this IP."""
        intel: dict[str, Any] = {"ip_address": ip}

        ipinfo_key = self.get_api_key("ipinfo")
        abuse_key  = self.get_api_key("abuseipdb")
        vt_key     = self.get_api_key("virustotal")
        shodan_key = self.get_api_key("shodan")

        def run_with_status(label: str, func, *args):
            """Run an API call and print status."""
            try:
                print_info(console, f"Querying {label}...")
                return func(*args)
            except Exception:
                print_warning(console, f"{label} failed")
                return {}

        # IPInfo
        try:
            from zephyrveil.integrations.ipinfo import query_ipinfo
            ipinfo = run_with_status("IPInfo", query_ipinfo, ip, ipinfo_key)
            if ipinfo and not ipinfo.get("skipped"):
                intel.update({
                    "country":    ipinfo.get("country", ""),
                    "city":       ipinfo.get("city", ""),
                    "org":        ipinfo.get("org", ""),
                    "isp":        ipinfo.get("isp", ""),
                    "asn":        ipinfo.get("asn", ""),
                    "hostname":   ipinfo.get("hostname", ""),
                    "raw_ipinfo": ipinfo.get("raw", {}),
                })
            elif ipinfo.get("skipped"):
                print_warning(console, "IPInfo: key not configured")
        except Exception:
            pass

        # AbuseIPDB
        try:
            from zephyrveil.integrations.abuseipdb import query_abuseipdb
            abuse = run_with_status("AbuseIPDB", query_abuseipdb, ip, abuse_key)
            if abuse and not abuse.get("skipped"):
                intel.update({
                    "abuse_score":   abuse.get("abuse_score", 0),
                    "abuse_reports": abuse.get("abuse_reports", 0),
                    "raw_abuseipdb": abuse.get("raw", {}),
                })
            elif abuse.get("skipped"):
                print_warning(console, "AbuseIPDB: key not configured")
        except Exception:
            pass

        # VirusTotal
        try:
            from zephyrveil.integrations.virustotal import query_virustotal
            vt = run_with_status("VirusTotal", query_virustotal, ip, vt_key)
            if vt and not vt.get("skipped"):
                intel.update({
                    "vt_malicious":   vt.get("malicious", 0),
                    "vt_total":       vt.get("total", 0),
                    "raw_virustotal": vt.get("raw", {}),
                })
            elif vt.get("skipped"):
                print_warning(console, "VirusTotal: key not configured")
        except Exception:
            pass

        # Shodan
        try:
            from zephyrveil.integrations.shodan import query_shodan
            shodan = run_with_status("Shodan", query_shodan, ip, shodan_key)
            if shodan and not shodan.get("skipped"):
                intel.update({
                    "shodan_ports":  shodan.get("ports", []),
                    "shodan_vulns":  shodan.get("vulns", []),
                    "shodan_org":    shodan.get("org", ""),
                    "raw_shodan":    shodan.get("raw", {}),
                })
            elif shodan.get("skipped"):
                print_warning(console, "Shodan: key not configured")
        except Exception:
            pass

        # Fail2ban (local, always try)
        try:
            from zephyrveil.integrations.fail2ban import check_ip_banned
            f2b = check_ip_banned(ip)
            intel["fail2ban_banned"] = f2b.get("banned", False)
            if f2b.get("error") and "not installed" not in f2b["error"]:
                print_warning(console, f"Fail2ban: {f2b['error']}")
        except Exception:
            pass

        console.print()
        return intel

    def _save_to_db(self, ip: str, events: list, intel: dict[str, Any]) -> None:
        """Save investigation results to database."""
        try:
            from zephyrveil.storage.db import (
                insert_scan, insert_event, insert_ip_intel, finish_scan
            )
            db_path = self.get_db_path()
            scan_id = f"ip_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{ip.replace('.', '_')}"

            insert_scan(db_path, scan_id, f"ip_lookup:{ip}")
            for event in events:
                insert_event(db_path, scan_id, event)
            insert_ip_intel(db_path, scan_id, intel)
            finish_scan(db_path, scan_id, 0, len(events), 1)

        except Exception:
            pass
