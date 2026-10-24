"""
modules/log.py — Log parsing and IP enrichment module.

'use log' in the console runs this module.
It parses system logs and automatically enriches every IP found
with threat intelligence from all configured APIs.

Options:
- SOURCE: auto (journalctl), auth.log, or custom file path
- SINCE:  24h (how far back to look)
- VERBOSE: false (show extra raw event detail)
"""

import shutil
from datetime import datetime
from typing import Any
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from zephyrveil.modules.base import BaseModule
from zephyrveil.console.output import (
    print_section, print_success, print_warning, print_error, print_info,
    print_ip_intel_table, build_threats_summary_table,
)


class LogModule(BaseModule):
    """
    Log parsing and IP enrichment module.

    Parses journalctl or auth.log, extracts all IPs, runs threat intel
    on each one, and shows full results with historical context.
    """

    NAME        = "log"
    DESCRIPTION = "Parse system logs and enrich all IPs found with threat intel"

    DEFAULT_OPTIONS = {
        "SOURCE":  ("auto",  "Log source: auto, journalctl, /path/to/file"),
        "SINCE":   ("24h",   "How far back to look: 24h, 7d, 1h, etc."),
        "VERBOSE": ("false", "Show extra raw event detail: true/false"),
    }

    def run(self, console: Console) -> None:
        """
        Execute the log module:
        1. Parse logs from configured source
        2. Show parsed events summary
        3. Enrich every unique IP with all threat intel APIs
        4. Show IP intel results
        5. Show historical data from SQLite
        6. Save everything to DB
        """
        try:
            source  = self.options.get("SOURCE", "auto")
            since   = self.options.get("SINCE", "24h")
            verbose = self.options.get("VERBOSE", "false").lower() == "true"

            print_section(console, "LOG PARSER + IP ENRICHMENT")

            # ── Step 1: Parse Logs ────────────────────────────────────────
            print_info(console, f"Parsing logs — source: {source}, since: {since}")

            parse_result = self._parse_logs(source, since)

            if parse_result.get("error"):
                print_error(console, parse_result["error"])
                if not parse_result.get("events"):
                    return

            events     = parse_result.get("events", [])
            all_ips    = parse_result.get("ips", set())
            source_used = parse_result.get("source_used", source)

            print_success(console, f"Source: {source_used}")
            print_success(console, f"Lines processed: {parse_result.get('line_count', 0):,}")
            print_success(console, f"Security events found: {len(events):,}")
            print_success(console, f"Unique IPs found: {len(all_ips)}")
            console.print()

            # ── Step 2: Show event summary table ──────────────────────────
            if events:
                self._show_events_summary(console, events, verbose)

            # ── Step 3: Enrich each IP ────────────────────────────────────
            if all_ips:
                print_section(console, "IP THREAT INTELLIGENCE")
                ip_intel_results = self._enrich_ips(console, list(all_ips))

                # Show each result
                for intel in ip_intel_results:
                    print_ip_intel_table(console, intel)

                # ── Step 4: Save to DB ────────────────────────────────────
                self._save_to_db(events, ip_intel_results, source_used)
                print_success(console, "Results saved to database")

            else:
                print_info(console, "No external IPs found in logs to enrich")

        except KeyboardInterrupt:
            print_warning(console, "Log scan interrupted")
        except Exception:
            print_error(console, "Log module encountered an unexpected error — try 'use doctor'")

    def _parse_logs(self, source: str, since: str) -> dict[str, Any]:
        """
        Parse logs from the configured source.

        Tries journalctl first (if source=auto), falls back to auth.log.
        Supports custom file paths.
        """
        try:
            from zephyrveil.parser.journal_parser import parse_journal, is_journalctl_available
            from zephyrveil.parser.auth_parser import parse_auth_log

            if source == "auto":
                # Try journalctl first
                if is_journalctl_available():
                    result = parse_journal(since=since)
                    if result.get("events") or not result.get("error"):
                        return result
                # Fallback to auth.log
                return parse_auth_log()

            elif source == "journalctl":
                return parse_journal(since=since)

            elif source.startswith("/") or source.startswith("~"):
                # Custom file path
                from zephyrveil.parser.journal_parser import parse_journal
                return parse_journal(filepath=source)

            else:
                return parse_auth_log(path=source)

        except Exception as exc:
            return {
                "events": [], "ips": set(), "source_used": source,
                "line_count": 0, "error": f"Parser failed: {type(exc).__name__}",
            }

    def _show_events_summary(self, console: Console, events: list, verbose: bool) -> None:
        """Show a summary table of log events by type."""
        try:
            from rich.table import Table
            from rich import box

            # Count by event type
            type_counts: dict[str, int] = {}
            for event in events:
                etype = event.get("event_type", "unknown")
                type_counts[etype] = type_counts.get(etype, 0) + 1

            table = Table(
                title="[bold white]Log Events Summary[/bold white]",
                box=box.ROUNDED,
                border_style="white",
                header_style="bold cyan",
            )
            table.add_column("Event Type",  style="cyan",       width=28)
            table.add_column("Count",       style="bold white", width=10)
            table.add_column("% of Total",  style="dim white",  width=12)

            total = len(events)
            for etype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                pct = f"{(count / total * 100):.1f}%" if total > 0 else "0%"
                table.add_row(etype.replace("_", " ").title(), str(count), pct)

            console.print(table)
            console.print()

            # Verbose: show raw events
            if verbose:
                print_section(console, "RAW EVENTS (VERBOSE)")
                for event in events[:50]:  # Cap at 50 to avoid flooding
                    console.print(f"  [dim]{event.get('occurred_at', '')}[/dim] "
                                  f"[cyan]{event.get('event_type', '')}[/cyan] "
                                  f"[white]{event.get('source_ip', '')}[/white] "
                                  f"[dim]{event.get('username', '')}[/dim]")

        except Exception:
            pass

    def _enrich_ips(self, console: Console, ips: list[str]) -> list[dict[str, Any]]:
        """Run all threat intel APIs on each IP."""
        results = []

        # Get API keys
        ipinfo_key    = self.get_api_key("ipinfo")
        abuse_key     = self.get_api_key("abuseipdb")
        vt_key        = self.get_api_key("virustotal")
        shodan_key    = self.get_api_key("shodan")
        db_path       = self.get_db_path()

        # Warn about missing keys once
        if not ipinfo_key:
            print_warning(console, "IPInfo key missing — skipping GeoIP (add to config.toml)")
        if not abuse_key:
            print_warning(console, "AbuseIPDB key missing — skipping abuse score (add to config.toml)")
        if not vt_key:
            print_warning(console, "VirusTotal key missing — skipping VT check (add to config.toml)")
        if not shodan_key:
            print_warning(console, "Shodan key missing — skipping Shodan data (add to config.toml)")
        console.print()

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.description}"),
            BarColumn(),
            TextColumn("[bold white]{task.completed}/{task.total}"),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("Enriching IPs...", total=len(ips))

            for ip in ips:
                try:
                    progress.update(task, description=f"Enriching {ip}...", advance=0)

                    intel = self._enrich_single_ip(ip, ipinfo_key, abuse_key, vt_key, shodan_key)
                    results.append(intel)

                    # Check historical data
                    history = self._get_ip_history(db_path, ip)
                    if history:
                        intel["_history_count"] = len(history)
                        intel["_first_seen"] = history[-1].get("queried_at", "")

                    progress.advance(task)

                except Exception:
                    progress.advance(task)
                    continue

        return results

    def _enrich_single_ip(
        self,
        ip: str,
        ipinfo_key: str,
        abuse_key: str,
        vt_key: str,
        shodan_key: str,
    ) -> dict[str, Any]:
        """Run all APIs against a single IP and merge results."""
        intel: dict[str, Any] = {"ip_address": ip}

        try:
            from zephyrveil.integrations.ipinfo    import query_ipinfo
            from zephyrveil.integrations.abuseipdb import query_abuseipdb
            from zephyrveil.integrations.virustotal import query_virustotal
            from zephyrveil.integrations.shodan    import query_shodan
            from zephyrveil.integrations.fail2ban  import check_ip_banned

            # IPInfo
            try:
                ipinfo = query_ipinfo(ip, ipinfo_key)
                if not ipinfo.get("skipped"):
                    intel.update({
                        "country":  ipinfo.get("country", ""),
                        "city":     ipinfo.get("city", ""),
                        "org":      ipinfo.get("org", ""),
                        "isp":      ipinfo.get("isp", ""),
                        "asn":      ipinfo.get("asn", ""),
                        "hostname": ipinfo.get("hostname", ""),
                        "raw_ipinfo": ipinfo.get("raw", {}),
                    })
            except Exception:
                pass

            # AbuseIPDB
            try:
                abuse = query_abuseipdb(ip, abuse_key)
                if not abuse.get("skipped"):
                    intel.update({
                        "abuse_score":   abuse.get("abuse_score", 0),
                        "abuse_reports": abuse.get("abuse_reports", 0),
                        "raw_abuseipdb": abuse.get("raw", {}),
                    })
            except Exception:
                pass

            # VirusTotal
            try:
                vt = query_virustotal(ip, vt_key)
                if not vt.get("skipped"):
                    intel.update({
                        "vt_malicious":   vt.get("malicious", 0),
                        "vt_total":       vt.get("total", 0),
                        "raw_virustotal": vt.get("raw", {}),
                    })
            except Exception:
                pass

            # Shodan
            try:
                shodan = query_shodan(ip, shodan_key)
                if not shodan.get("skipped"):
                    intel.update({
                        "shodan_ports":  shodan.get("ports", []),
                        "shodan_vulns":  shodan.get("vulns", []),
                        "shodan_org":    shodan.get("org", ""),
                        "raw_shodan":    shodan.get("raw", {}),
                    })
            except Exception:
                pass

            # Fail2ban (local, no key needed)
            try:
                f2b = check_ip_banned(ip)
                intel["fail2ban_banned"] = f2b.get("banned", False)
            except Exception:
                pass

        except Exception:
            pass

        return intel

    def _get_ip_history(self, db_path: str, ip: str) -> list:
        """Fetch historical records for an IP from SQLite."""
        try:
            from zephyrveil.storage.db import get_ip_history
            return get_ip_history(db_path, ip)
        except Exception:
            return []

    def _save_to_db(self, events: list, ip_intel: list, source: str) -> None:
        """Save events and IP intel to SQLite."""
        try:
            from zephyrveil.storage.db import (
                insert_scan, insert_event, insert_ip_intel, finish_scan
            )
            db_path  = self.get_db_path()
            scan_id  = f"log_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            insert_scan(db_path, scan_id, source)

            for event in events:
                try:
                    insert_event(db_path, scan_id, event)
                except Exception:
                    continue

            for intel in ip_intel:
                try:
                    insert_ip_intel(db_path, scan_id, intel)
                except Exception:
                    continue

            finish_scan(db_path, scan_id, 0, len(events), len(ip_intel))

        except Exception:
            pass
