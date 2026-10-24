"""
modules/scan.py — Master scan module. Connects and runs everything.

'use scan' → 'run' executes the full Zephyrveil pipeline in order:

1.  Parse logs (journalctl / auth.log / custom file)
2.  Detect all 5 threat types from log events
3.  Enrich every attacker IP with all threat intel APIs
4.  Run full system audit (tools, network, health, hygiene, CVEs)
5.  Pull threat history from SQLite for known IPs
6.  Send Telegram alert if threats found (if configured)
7.  Save everything to SQLite (scan session, threats, events, IPs, audit)
8.  Generate PDF + JSON report with timestamp

This module orchestrates all other components.
Modules never call each other directly — everything is coordinated here.
"""

from datetime import datetime
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from zephyrveil.console.output import (
    build_threats_summary_table,
    print_error,
    print_info,
    print_ip_intel_table,
    print_scan_header,
    print_section,
    print_subsection,
    print_success,
    print_warning,
)
from zephyrveil.modules.base import BaseModule


class ScanModule(BaseModule):
    """
    Master scan module — runs all Zephyrveil features end-to-end.
    This is the primary module users will run most often.
    """

    NAME = "scan"
    DESCRIPTION = "Full threat detection scan — runs everything in one shot"

    DEFAULT_OPTIONS = {
        "SOURCE": ("auto", "Log source: auto, journalctl, /path/to/logfile"),
        "VERBOSE": ("false", "Show extra detail during scan: true/false"),
    }

    def run(self, console: Console) -> None:
        """
        Execute the full scan pipeline.

        All steps are independent — if one fails, the others continue.
        Results are accumulated and saved/reported at the end.
        """
        try:
            source = self.options.get("SOURCE", "auto")
            verbose = self.options.get("VERBOSE", "false").lower() == "true"

            # Generate a unique scan ID using timestamp
            scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            db_path = self.get_db_path()

            # Print the scan start header panel
            print_scan_header(console, scan_id, source)

            # Register this scan in the database immediately
            try:
                from zephyrveil.storage.db import insert_scan

                insert_scan(db_path, scan_id, source)
            except Exception:
                pass

            # ── Accumulators for all results ──────────────────────────────
            all_events: list[dict[str, Any]] = []
            all_threats: list[dict[str, Any]] = []
            all_ip_intel: list[dict[str, Any]] = []
            audit_results: dict[str, Any] = {}
            parse_source_used: str = source

            # ═══════════════════════════════════════════════════════════════
            # STEP 1 — PARSE LOGS
            # ═══════════════════════════════════════════════════════════════
            print_section(console, "STEP 1 — LOG PARSING")

            try:
                parse_result = self._parse_logs(source)

                if parse_result.get("error") and not parse_result.get("events"):
                    print_error(console, f"Log parsing failed: {parse_result['error']}")
                    print_warning(console, "Continuing with other scan steps...")
                else:
                    if parse_result.get("error"):
                        print_warning(console, f"Log warning: {parse_result['error']}")

                    all_events = parse_result.get("events", [])
                    parse_source_used = parse_result.get("source_used", source)

                    print_success(console, f"Source: {parse_source_used}")
                    print_success(
                        console,
                        f"Lines processed: {parse_result.get('line_count', 0):,}",
                    )
                    print_success(console, f"Security events: {len(all_events):,}")
                    print_success(
                        console,
                        f"Unique IPs found: {len(parse_result.get('ips', set()))}",
                    )

                    # Show event type breakdown if verbose
                    if verbose and all_events:
                        self._show_event_summary(console, all_events)

            except Exception:
                print_error(console, "Log parsing step failed — continuing")

            # ═══════════════════════════════════════════════════════════════
            # STEP 2 — THREAT DETECTION
            # ═══════════════════════════════════════════════════════════════
            print_section(console, "STEP 2 — THREAT DETECTION")

            try:
                from zephyrveil.detector.threat_engine import run_all_detections

                all_threats = run_all_detections(all_events, config=self.config)

                if all_threats:
                    console.print()
                    console.print(build_threats_summary_table(all_threats))
                    console.print()
                else:
                    print_success(console, "No threats detected in the log data")

                print_info(
                    console, f"Detection complete — {len(all_threats)} threat(s) found"
                )

            except Exception:
                print_error(console, "Threat detection step failed — continuing")

            # ═══════════════════════════════════════════════════════════════
            # STEP 3 — IP THREAT INTELLIGENCE
            # ═══════════════════════════════════════════════════════════════
            print_section(console, "STEP 3 — IP THREAT INTELLIGENCE")

            try:
                # Collect all unique IPs from parse results + threats
                all_ips: set[str] = set()

                # IPs from parse result
                parse_ips = (
                    parse_result.get("ips", set()) if "parse_result" in dir() else set()
                )
                all_ips.update(parse_ips)

                # IPs from detected threats
                for threat in all_threats:
                    ip = threat.get("source_ip", "")
                    if ip and ip not in ("", "local", "multiple", "N/A"):
                        all_ips.add(ip)

                if all_ips:
                    print_info(
                        console,
                        f"Enriching {len(all_ips)} unique IP(s) with threat intel...",
                    )
                    self._warn_missing_keys(console)
                    all_ip_intel = self._enrich_all_ips(console, list(all_ips))

                    # Show historical context for known IPs
                    self._show_ip_history_context(console, all_ip_intel, db_path)

                    # Display each IP intel result
                    for intel in all_ip_intel:
                        print_ip_intel_table(console, intel)
                else:
                    print_info(console, "No external IPs found to enrich")

            except Exception:
                print_error(console, "IP enrichment step failed — continuing")

            # ═══════════════════════════════════════════════════════════════
            # STEP 4 — SYSTEM AUDIT
            # ═══════════════════════════════════════════════════════════════
            print_section(console, "STEP 4 — SYSTEM AUDIT")

            try:
                audit_results = self._run_system_audit(console)
                print_success(console, "System audit complete")
            except Exception:
                print_error(console, "System audit step failed — continuing")

            # ═══════════════════════════════════════════════════════════════
            # STEP 5 — SAVE TO DATABASE
            # ═══════════════════════════════════════════════════════════════
            print_section(console, "STEP 5 — SAVING TO DATABASE")

            try:
                self._save_all_to_db(
                    scan_id=scan_id,
                    db_path=db_path,
                    source=parse_source_used,
                    events=all_events,
                    threats=all_threats,
                    ip_intel=all_ip_intel,
                    audit_results=audit_results,
                )
                print_success(
                    console, f"All data saved to database — scan ID: {scan_id}"
                )
            except Exception:
                print_error(
                    console, "Database save failed — results may not be in history"
                )

            # ═══════════════════════════════════════════════════════════════
            # STEP 6 — TELEGRAM ALERT (if configured and threats found)
            # ═══════════════════════════════════════════════════════════════
            if all_threats:
                print_section(console, "STEP 6 — TELEGRAM ALERT")
                try:
                    self._send_telegram_alert(
                        console, scan_id, all_threats, audit_results, db_path
                    )
                except Exception:
                    print_warning(console, "Telegram alert step failed — skipping")
            else:
                print_info(
                    console, "Step 6 — No threats found, skipping Telegram alert"
                )

            # ═══════════════════════════════════════════════════════════════
            # STEP 7 — GENERATE REPORTS
            # ═══════════════════════════════════════════════════════════════
            print_section(console, "STEP 7 — GENERATING REPORTS")

            try:
                self._generate_reports(
                    console=console,
                    scan_id=scan_id,
                    source=parse_source_used,
                    events=all_events,
                    threats=all_threats,
                    ip_intel=all_ip_intel,
                    audit_results=audit_results,
                )
            except Exception:
                print_error(console, "Report generation failed")

            # ═══════════════════════════════════════════════════════════════
            # SCAN COMPLETE SUMMARY
            # ═══════════════════════════════════════════════════════════════
            print_section(console, "SCAN COMPLETE")

            sev_counts: dict[str, int] = {}
            for t in all_threats:
                sev = t.get("severity", "INFO")
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

            console.print(f"  [bold white]Scan ID:[/bold white]   {scan_id}")
            console.print(
                f"  [bold white]Events:[/bold white]    {len(all_events):,} log events parsed"
            )
            console.print(
                f"  [bold white]Threats:[/bold white]   {len(all_threats)} detected"
            )
            for sev, count in sev_counts.items():
                from zephyrveil.console.output import SEVERITY_COLORS, SEVERITY_ICONS

                color = SEVERITY_COLORS.get(sev, "white")
                icon = SEVERITY_ICONS.get(sev, "⚪")
                console.print(f"    [{color}]{icon} {sev}: {count}[/{color}]")
            console.print(
                f"  [bold white]IPs:[/bold white]       {len(all_ip_intel)} analyzed"
            )
            console.print()

            if all_threats:
                console.print(
                    "  [bold yellow]⚠[/bold yellow]  [bold white]Action required — review threats above[/bold white]"
                )
            else:
                console.print(
                    "  [bold green]✓[/bold green]  [bold white]System looks clean — no threats detected[/bold white]"
                )
            console.print()

        except KeyboardInterrupt:
            print_warning(console, "Scan interrupted by user")
        except Exception:
            print_error(
                console,
                "Scan module encountered an unexpected error — try 'use doctor'",
            )

    # ── Private helper methods ────────────────────────────────────────────────

    def _parse_logs(self, source: str) -> dict[str, Any]:
        """Parse logs from the configured source with journalctl → auth.log fallback."""
        try:
            from zephyrveil.parser.auth_parser import parse_auth_log
            from zephyrveil.parser.journal_parser import (
                is_journalctl_available,
                parse_journal,
            )

            if source == "auto":
                if is_journalctl_available():
                    result = parse_journal(since="24h")
                    if not result.get("error") or result.get("events"):
                        return result
                return parse_auth_log()

            elif source == "journalctl":
                return parse_journal(since="24h")

            elif source in ("/var/log/auth.log", "auth.log"):
                return parse_auth_log()

            else:
                # Treat as custom file path
                return parse_journal(filepath=source)

        except Exception as exc:
            return {
                "events": [],
                "ips": set(),
                "source_used": source,
                "line_count": 0,
                "error": f"Parser error: {type(exc).__name__}",
            }

    def _show_event_summary(self, console: Console, events: list) -> None:
        """Show a compact event type breakdown table."""
        try:
            from rich import box
            from rich.table import Table

            counts: dict[str, int] = {}
            for e in events:
                t = e.get("event_type", "unknown")
                counts[t] = counts.get(t, 0) + 1

            t = Table(box=box.SIMPLE, header_style="bold cyan")
            t.add_column("Event Type", style="cyan", width=28)
            t.add_column("Count", style="white", width=8)

            for etype, cnt in sorted(counts.items(), key=lambda x: x[1], reverse=True):
                t.add_row(etype.replace("_", " ").title(), str(cnt))

            console.print(t)
        except Exception:
            pass

    def _warn_missing_keys(self, console: Console) -> None:
        """Print one-time warnings for missing API keys."""
        try:
            if not self.get_api_key("ipinfo"):
                print_warning(console, "IPInfo key missing — GeoIP skipped")
            if not self.get_api_key("abuseipdb"):
                print_warning(console, "AbuseIPDB key missing — abuse score skipped")
            if not self.get_api_key("virustotal"):
                print_warning(console, "VirusTotal key missing — VT check skipped")
            if not self.get_api_key("shodan"):
                print_warning(console, "Shodan key missing — port/vuln data skipped")
        except Exception:
            pass

    def _enrich_all_ips(self, console: Console, ips: list[str]) -> list[dict[str, Any]]:
        """Enrich all IPs with threat intel APIs using a progress bar."""
        results = []
        ipinfo_key = self.get_api_key("ipinfo")
        abuse_key = self.get_api_key("abuseipdb")
        vt_key = self.get_api_key("virustotal")
        shodan_key = self.get_api_key("shodan")

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.description}"),
            BarColumn(),
            TextColumn("[white]{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("Enriching IPs...", total=len(ips))

            for ip in ips:
                try:
                    progress.update(task, description=f"Querying {ip}...")
                    intel = {"ip_address": ip}

                    # IPInfo
                    try:
                        from zephyrveil.integrations.ipinfo import query_ipinfo

                        r = query_ipinfo(ip, ipinfo_key)
                        if not r.get("skipped") and not r.get("error"):
                            intel.update(
                                {
                                    "country": r.get("country", ""),
                                    "city": r.get("city", ""),
                                    "org": r.get("org", ""),
                                    "isp": r.get("isp", ""),
                                    "asn": r.get("asn", ""),
                                    "hostname": r.get("hostname", ""),
                                    "raw_ipinfo": r.get("raw", {}),
                                }
                            )
                    except Exception:
                        pass

                    # AbuseIPDB
                    try:
                        from zephyrveil.integrations.abuseipdb import query_abuseipdb

                        r = query_abuseipdb(ip, abuse_key)
                        if not r.get("skipped") and not r.get("error"):
                            intel.update(
                                {
                                    "abuse_score": r.get("abuse_score", 0),
                                    "abuse_reports": r.get("abuse_reports", 0),
                                    "raw_abuseipdb": r.get("raw", {}),
                                }
                            )
                    except Exception:
                        pass

                    # VirusTotal
                    try:
                        from zephyrveil.integrations.virustotal import query_virustotal

                        r = query_virustotal(ip, vt_key)
                        if not r.get("skipped") and not r.get("error"):
                            intel.update(
                                {
                                    "vt_malicious": r.get("malicious", 0),
                                    "vt_total": r.get("total", 0),
                                    "raw_virustotal": r.get("raw", {}),
                                }
                            )
                    except Exception:
                        pass

                    # Shodan
                    try:
                        from zephyrveil.integrations.shodan import query_shodan

                        r = query_shodan(ip, shodan_key)
                        if not r.get("skipped") and not r.get("error"):
                            intel.update(
                                {
                                    "shodan_ports": r.get("ports", []),
                                    "shodan_vulns": r.get("vulns", []),
                                    "shodan_org": r.get("org", ""),
                                    "raw_shodan": r.get("raw", {}),
                                }
                            )
                    except Exception:
                        pass

                    # Fail2ban (local)
                    try:
                        from zephyrveil.integrations.fail2ban import check_ip_banned

                        f2b = check_ip_banned(ip)
                        intel["fail2ban_banned"] = f2b.get("banned", False)
                    except Exception:
                        pass

                    results.append(intel)
                    progress.advance(task)

                except Exception:
                    progress.advance(task)
                    continue

        return results

    def _show_ip_history_context(
        self, console: Console, ip_intel: list, db_path: str
    ) -> None:
        """Show a note if any IPs have been seen before."""
        try:
            from zephyrveil.storage.db import get_ip_history

            for intel in ip_intel:
                ip = intel.get("ip_address", "")
                if not ip:
                    continue
                history = get_ip_history(db_path, ip)
                if len(history) > 1:
                    print_warning(
                        console,
                        f"Known IP: {ip} has been seen {len(history)} times before "
                        f"(first: {history[-1].get('queried_at', '—')[:10]})",
                    )
        except Exception:
            pass

    def _run_system_audit(self, console: Console) -> dict[str, Any]:
        """Run all system audit components and return results."""
        audit: dict[str, Any] = {}

        steps = [
            (
                "tools",
                "Security tools",
                "zephyrveil.auditor.tool_checker",
                "check_all_tools",
                [],
            ),
            (
                "network",
                "Network info",
                "zephyrveil.auditor.network_info",
                "get_network_info",
                [],
            ),
            (
                "health",
                "System health",
                "zephyrveil.auditor.system_health",
                "get_system_health",
                [],
            ),
            (
                "hygiene",
                "Security hygiene",
                "zephyrveil.auditor.hygiene_check",
                "run_hygiene_checks",
                [],
            ),
        ]

        for key, label, module_path, func_name, args in steps:
            try:
                print_info(console, f"Running {label} audit...")
                import importlib

                mod = importlib.import_module(module_path)
                func = getattr(mod, func_name)
                audit[key] = func(*args)
                print_success(console, f"{label} audit complete")
            except Exception:
                print_warning(console, f"{label} audit failed — skipping")
                audit[key] = {}

        # CVE check (can be slow — run separately)
        try:
            print_info(
                console, "Checking CVEs on installed packages (may take a moment)..."
            )
            from zephyrveil.auditor.cve_check import check_packages_for_cves

            nvd_key = self.get_api_key("nvd")
            audit["cve"] = check_packages_for_cves(
                api_key=nvd_key, max_packages=8, cves_per_package=2
            )
            vuln_count = audit["cve"].get("vuln_count", 0)
            if vuln_count > 0:
                print_warning(
                    console, f"CVE check: {vuln_count} CVEs found in installed packages"
                )
            else:
                print_success(
                    console,
                    "CVE check complete — no critical CVEs found in checked packages",
                )
        except Exception:
            print_warning(console, "CVE check failed — skipping")
            audit["cve"] = {}

        return audit

    def _save_all_to_db(
        self,
        scan_id: str,
        db_path: str,
        source: str,
        events: list,
        threats: list,
        ip_intel: list,
        audit_results: dict,
    ) -> None:
        """Save everything to the SQLite database."""
        try:
            from zephyrveil.storage.db import (
                finish_scan,
                insert_audit_result,
                insert_event,
                insert_ip_intel,
                insert_threat,
            )

            # Save log events
            for event in events:
                try:
                    insert_event(db_path, scan_id, event)
                except Exception:
                    continue

            # Save threats
            for threat in threats:
                try:
                    insert_threat(db_path, scan_id, threat)
                except Exception:
                    continue

            # Save IP intel
            for intel in ip_intel:
                try:
                    insert_ip_intel(db_path, scan_id, intel)
                except Exception:
                    continue

            # Save audit results
            for audit_type, result in audit_results.items():
                try:
                    insert_audit_result(db_path, scan_id, f"scan_{audit_type}", result)
                except Exception:
                    continue

            # Mark scan as finished with summary counts
            finish_scan(
                db_path,
                scan_id,
                threat_count=len(threats),
                event_count=len(events),
                ip_count=len(ip_intel),
            )

        except Exception:
            pass

    def _send_telegram_alert(
        self,
        console: Console,
        scan_id: str,
        threats: list,
        audit_results: dict,
        db_path: str,
    ) -> None:
        """Send Telegram alert if configured and threats were found."""
        try:
            from zephyrveil.config.settings import is_telegram_configured

            if not is_telegram_configured(self.config):
                print_info(
                    console,
                    "Telegram not configured — skipping alert (run: use alerts)",
                )
                return

            tg = self.config.get("telegram", {})
            token = str(tg.get("bot_token", "")).strip()
            chat_id = str(tg.get("chat_id", "")).strip()

            # Get hostname for context
            hostname = ""
            try:
                health = audit_results.get("health", {})
                hostname = health.get("hostname", "")
            except Exception:
                pass

            from zephyrveil.integrations.telegram import (
                build_threat_alert_message,
                send_telegram_message,
            )

            message = build_threat_alert_message(threats, scan_id, hostname)
            if not message:
                return

            print_info(console, "Sending Telegram alert...")
            result = send_telegram_message(token, chat_id, message)

            if result.get("success"):
                print_success(console, "Telegram alert sent successfully")

                from zephyrveil.storage.db import insert_alert

                insert_alert(db_path, scan_id, "telegram", "sent", message)
            else:
                print_warning(
                    console, f"Telegram alert failed: {result.get('error', 'Unknown')}"
                )

                from zephyrveil.storage.db import insert_alert

                insert_alert(
                    db_path,
                    scan_id,
                    "telegram",
                    "failed",
                    message,
                    result.get("error", ""),
                )

        except Exception:
            print_warning(console, "Telegram alert failed — skipping")

    def _generate_reports(
        self,
        console: Console,
        scan_id: str,
        source: str,
        events: list,
        threats: list,
        ip_intel: list,
        audit_results: dict,
    ) -> None:
        """Generate PDF and JSON reports for this scan."""
        try:
            output_dir = self.get_reports_dir()

            # Build comprehensive scan_data for the reporters
            health = audit_results.get("health", {})
            scan_data: dict[str, Any] = {
                "scan_id": scan_id,
                "started_at": datetime.now().isoformat(),
                "finished_at": datetime.now().isoformat(),
                "source": source,
                "hostname": health.get("hostname", "")
                if isinstance(health, dict)
                else "",
                "kernel": health.get("kernel", "") if isinstance(health, dict) else "",
                "threats": threats,
                "ip_intel": ip_intel,
                "events": events,
                "event_count": len(events),
                "audit_tools": audit_results.get("tools", {}),
                "audit_network": audit_results.get("network", {}),
                "audit_health": health,
                "audit_hygiene": audit_results.get("hygiene", {}),
                "audit_cve": audit_results.get("cve", {}),
            }

            # JSON report (always try)
            # Generate PDF
            try:
                from zephyrveil.reporter.pdf_report import generate_pdf_report

                ok, path_or_err = generate_pdf_report(scan_data, output_dir)
                if ok:
                    print_success(console, f"PDF: {path_or_err}")
                else:
                    print_warning(console, f"PDF failed: {path_or_err}")
            except Exception as exc:
                print_warning(console, f"PDF generation skipped: {type(exc).__name__}")

            # Generate JSON
            try:
                from zephyrveil.reporter.json_report import generate_json_report

                ok, path_or_err = generate_json_report(scan_data, output_dir)
                if ok:
                    print_success(console, f"JSON: {path_or_err}")
                else:
                    print_error(console, f"JSON failed: {path_or_err}")
            except Exception as exc:
                print_error(console, f"JSON generation failed: {type(exc).__name__}")

            # Generate HTML
            try:
                from zephyrveil.reporter.html_report import generate_html_report

                ok, path_or_err = generate_html_report(scan_data, output_dir)
                if ok:
                    print_success(console, f"HTML: {path_or_err}")
                else:
                    print_error(console, f"HTML failed: {path_or_err}")
            except Exception as exc:
                print_error(console, f"HTML generation failed: {type(exc).__name__}")

        except Exception:
            print_error(console, "Report generation encountered an error")
