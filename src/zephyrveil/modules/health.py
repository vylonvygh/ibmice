"""
modules/health.py — Full system security audit module.

'use health' runs a comprehensive audit:
- Security tools check
- Network info (IPs, ports, connections)
- System health (RAM, disk, uptime, kernel)
- Security hygiene (SSH config, LUKS, firewall, sudo)
- CVE check on installed packages

Option FIX=true shows actionable fix commands for every issue.
"""

from datetime import datetime
from typing import Any
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from zephyrveil.modules.base import BaseModule
from zephyrveil.console.output import (
    print_section, print_subsection, print_success, print_warning,
    print_error, print_info, build_kv_panel,
)


class HealthModule(BaseModule):
    """Full system security audit module."""

    NAME        = "health"
    DESCRIPTION = "Full system security audit — tools, ports, SSH, LUKS, CVEs"

    DEFAULT_OPTIONS = {
        "FIX": ("false", "Show fix suggestions for every issue: true/false"),
    }

    def run(self, console: Console) -> None:
        """Execute all health checks and display results."""
        try:
            show_fix = self.options.get("FIX", "false").lower() == "true"

            print_section(console, "SYSTEM SECURITY AUDIT")

            audit_results: dict[str, Any] = {}

            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("Running security audit...", total=None)

                # ── Tool check ────────────────────────────────────────────
                progress.update(task, description="Checking security tools...")
                try:
                    from zephyrveil.auditor.tool_checker import check_all_tools
                    audit_results["tools"] = check_all_tools()
                except Exception:
                    audit_results["tools"] = {}

                # ── Network info ──────────────────────────────────────────
                progress.update(task, description="Gathering network info...")
                try:
                    from zephyrveil.auditor.network_info import get_network_info
                    audit_results["network"] = get_network_info()
                except Exception:
                    audit_results["network"] = {}

                # ── System health ─────────────────────────────────────────
                progress.update(task, description="Checking system health...")
                try:
                    from zephyrveil.auditor.system_health import get_system_health
                    audit_results["health"] = get_system_health()
                except Exception:
                    audit_results["health"] = {}

                # ── Security hygiene ──────────────────────────────────────
                progress.update(task, description="Checking security hygiene...")
                try:
                    from zephyrveil.auditor.hygiene_check import run_hygiene_checks
                    audit_results["hygiene"] = run_hygiene_checks()
                except Exception:
                    audit_results["hygiene"] = {}

                # ── CVE check ─────────────────────────────────────────────
                progress.update(task, description="Checking CVEs on installed packages...")
                try:
                    from zephyrveil.auditor.cve_check import check_packages_for_cves
                    nvd_key = self.get_api_key("nvd")
                    audit_results["cve"] = check_packages_for_cves(api_key=nvd_key, max_packages=10)
                except Exception:
                    audit_results["cve"] = {}

            # ── Display all results ───────────────────────────────────────
            self._show_tools(console, audit_results.get("tools", {}), show_fix)
            self._show_network(console, audit_results.get("network", {}))
            self._show_system_health(console, audit_results.get("health", {}))
            self._show_hygiene(console, audit_results.get("hygiene", {}), show_fix)
            self._show_cves(console, audit_results.get("cve", {}))

            # ── Save to DB ────────────────────────────────────────────────
            self._save_to_db(audit_results)
            print_success(console, "Audit results saved to database")

        except KeyboardInterrupt:
            print_warning(console, "Health audit interrupted")
        except Exception:
            print_error(console, "Health module encountered an error — try 'use doctor'")

    def _show_tools(self, console: Console, data: dict, show_fix: bool) -> None:
        """Display security tools check results."""
        try:
            print_section(console, "SECURITY TOOLS")
            from rich.table import Table
            from rich import box

            tools = data.get("tools", [])
            if not tools:
                print_warning(console, "Could not check security tools")
                return

            table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold cyan")
            table.add_column("Tool",        style="bold white", width=16)
            table.add_column("Status",      style="white",      width=24)
            table.add_column("Importance",  style="dim",        width=10)
            table.add_column("Description", style="dim white")

            for tool in tools:
                status = tool.get("status_label", "UNKNOWN")
                if "RUNNING" in status:
                    status_display = f"[bold green]● {status}[/bold green]"
                elif "INSTALLED" in status:
                    status_display = f"[bold yellow]● {status}[/bold yellow]"
                else:
                    status_display = f"[bold red]✗ {status}[/bold red]"

                imp = tool.get("importance", "")
                imp_display = (
                    f"[red]{imp}[/red]" if imp == "HIGH" else
                    f"[yellow]{imp}[/yellow]" if imp == "MEDIUM" else
                    f"[dim]{imp}[/dim]"
                )

                table.add_row(
                    tool.get("name", ""),
                    status_display,
                    imp_display,
                    tool.get("description", ""),
                )

            console.print(table)
            console.print(f"  [dim]{data.get('summary', '')}[/dim]")

            if show_fix:
                for tool in tools:
                    if not tool.get("installed"):
                        print_info(console, f"Fix [{tool['name']}]: {tool.get('install_cmd', '')}")

        except Exception:
            pass

    def _show_network(self, console: Console, data: dict) -> None:
        """Display network information."""
        try:
            print_section(console, "NETWORK INFO")
            from rich.table import Table
            from rich import box

            # Local IPs
            local_ips = data.get("local_ips", [])
            pub_ip    = data.get("public_ip", "Could not fetch")

            print_subsection(console, "IP Addresses")
            console.print(f"  [dim]Public IP:[/dim]  [bold white]{pub_ip}[/bold white]")
            for iface in local_ips:
                console.print(
                    f"  [dim]{iface.get('interface', '')}:[/dim]  "
                    f"[white]{iface.get('ip', '')}[/white]  "
                    f"[dim]({iface.get('cidr', '')})[/dim]"
                )
            console.print()

            # Open ports
            ports = data.get("open_ports", [])
            if ports:
                print_subsection(console, f"Open Listening Ports ({len(ports)} total)")
                port_table = Table(box=box.SIMPLE, header_style="bold cyan")
                port_table.add_column("Port",     style="bold white", width=8)
                port_table.add_column("Protocol", style="cyan",       width=10)
                port_table.add_column("Address",  style="dim",        width=20)
                port_table.add_column("Process",  style="white",      width=20)

                for p in ports[:20]:
                    port_table.add_row(
                        str(p.get("port", "")),
                        p.get("protocol", ""),
                        p.get("address", ""),
                        p.get("process", ""),
                    )

                console.print(port_table)

            # Active connections
            conns = data.get("connections", [])
            if conns:
                print_subsection(console, f"Active Connections ({len(conns)} established)")
                conn_table = Table(box=box.SIMPLE, header_style="bold cyan")
                conn_table.add_column("Local",   style="dim",   width=24)
                conn_table.add_column("Remote",  style="white", width=24)
                conn_table.add_column("Process", style="cyan",  width=20)

                for c in conns[:15]:
                    conn_table.add_row(
                        c.get("local_addr", ""),
                        c.get("remote_addr", ""),
                        c.get("process", ""),
                    )
                console.print(conn_table)

        except Exception:
            pass

    def _show_system_health(self, console: Console, data: dict) -> None:
        """Display system health metrics."""
        try:
            print_section(console, "SYSTEM HEALTH")

            ram    = data.get("ram", {})
            uptime = data.get("uptime", {})
            cpu    = data.get("cpu", {})
            disks  = data.get("disks", [])

            # RAM
            if ram:
                pct = ram.get("percent_used", 0)
                color = "red" if pct > 85 else ("yellow" if pct > 70 else "green")
                console.print(
                    f"  [dim]RAM:[/dim]    [{color}]{pct}%[/{color}] used  "
                    f"[dim]({ram.get('used_mb', 0)}MB / {ram.get('total_mb', 0)}MB)[/dim]"
                )

            # Uptime + Load
            if uptime:
                console.print(f"  [dim]Uptime:[/dim]  [white]{uptime.get('uptime_human', '—')}[/white]")
                console.print(
                    f"  [dim]Load:[/dim]   [white]{uptime.get('load_1m', 0)} "
                    f"/ {uptime.get('load_5m', 0)} / {uptime.get('load_15m', 0)}[/white]  "
                    f"[dim](1m / 5m / 15m)[/dim]"
                )

            # CPU
            if cpu:
                console.print(f"  [dim]CPU:[/dim]    [white]{cpu.get('model', '—')}[/white]")
                console.print(f"  [dim]Cores:[/dim]  [white]{cpu.get('cores', 0)} physical / {cpu.get('threads', 0)} threads[/white]")

            # Kernel
            console.print(f"  [dim]Kernel:[/dim] [white]{data.get('kernel', '—')}[/white]")
            console.print(f"  [dim]Host:[/dim]   [white]{data.get('hostname', '—')}[/white]")
            console.print(f"  [dim]Procs:[/dim]  [white]{data.get('process_count', 0)} running processes[/white]")
            console.print()

            # Disks
            if disks:
                print_subsection(console, "Disk Usage")
                from rich.table import Table
                from rich import box
                disk_table = Table(box=box.SIMPLE, header_style="bold cyan")
                disk_table.add_column("Mount",      style="white",     width=20)
                disk_table.add_column("Total",      style="dim white", width=10)
                disk_table.add_column("Used",       style="white",     width=10)
                disk_table.add_column("Free",       style="green",     width=10)
                disk_table.add_column("Used %",     style="bold white", width=10)

                for disk in disks:
                    pct  = disk.get("percent_used", 0)
                    color = "red" if pct > 90 else ("yellow" if pct > 75 else "white")
                    disk_table.add_row(
                        disk.get("mount_point", ""),
                        f"{disk.get('total_gb', 0)}GB",
                        f"{disk.get('used_gb', 0)}GB",
                        f"{disk.get('free_gb', 0)}GB",
                        f"[{color}]{pct}%[/{color}]",
                    )
                console.print(disk_table)

        except Exception:
            pass

    def _show_hygiene(self, console: Console, data: dict, show_fix: bool) -> None:
        """Display security hygiene check results."""
        try:
            print_section(console, "SECURITY HYGIENE")

            # SSH checks
            ssh_checks = data.get("ssh_checks", [])
            if ssh_checks:
                print_subsection(console, "SSH Configuration")
                for check in ssh_checks:
                    status = check.get("status", "")
                    setting = check.get("setting", "")
                    value   = check.get("current_value", "")
                    desc    = check.get("description", "")

                    if status == "PASS":
                        console.print(f"  [bold green]✓[/bold green] {setting}: {value}  [dim]{desc}[/dim]")
                    elif status == "FAIL":
                        console.print(f"  [bold red]✗[/bold red] {setting}: {value}  [dim]{desc}[/dim]")
                        if show_fix:
                            print_info(console, f"Fix: {check.get('fix', '')}")
                    else:
                        console.print(f"  [bold yellow]⚠[/bold yellow]  {setting}: {value}  [dim]{desc}[/dim]")
                        if show_fix:
                            print_info(console, f"Fix: {check.get('fix', '')}")
                console.print()

            # LUKS
            luks = data.get("luks", {})
            if luks:
                print_subsection(console, "Disk Encryption (LUKS)")
                if luks.get("luks_active"):
                    encrypted = luks.get("encrypted_devices", [])
                    console.print(f"  [bold green]✓[/bold green] LUKS active — encrypted: {', '.join(encrypted) or 'detected'}")
                else:
                    console.print("  [bold yellow]⚠[/bold yellow]  No LUKS encryption detected")
                    if show_fix:
                        print_info(console, "Fix: Enable full disk encryption — requires OS reinstall or cryptsetup on new partitions")
                console.print()

            # Firewall
            fw = data.get("firewall", {})
            if fw:
                print_subsection(console, "Firewall")
                if fw.get("active"):
                    console.print(f"  [bold green]✓[/bold green] Firewall active: {fw.get('type', '')}  zones: {', '.join(fw.get('active_zones', [])) or '—'}")
                else:
                    console.print("  [bold red]✗[/bold red] No active firewall detected")
                    if show_fix:
                        print_info(console, "Fix: Enable firewalld: systemctl enable --now firewalld")
                console.print()

            # Sudo
            sudo = data.get("sudo", {})
            if sudo:
                print_subsection(console, "Sudo Configuration")
                nopasswd = sudo.get("nopasswd_entries", [])
                if nopasswd:
                    console.print("  [bold yellow]⚠[/bold yellow]  NOPASSWD entries found in sudoers:")
                    for entry in nopasswd[:5]:
                        console.print(f"    [dim]{entry}[/dim]")
                    if show_fix:
                        print_info(console, "Fix: Remove NOPASSWD from /etc/sudoers unless strictly required")
                else:
                    console.print("  [bold green]✓[/bold green] sudo requires password — no NOPASSWD entries")
                if sudo.get("error"):
                    print_warning(console, f"Sudo check: {sudo['error']}")
                console.print()

        except Exception:
            pass

    def _show_cves(self, console: Console, data: dict) -> None:
        """Display CVE findings."""
        try:
            print_section(console, "CVE FINDINGS")

            if data.get("error"):
                print_warning(console, f"CVE check: {data['error']}")
                return

            results = data.get("results", [])
            checked = data.get("checked_count", 0)
            total   = data.get("vuln_count", 0)

            print_info(console, f"Checked {checked} packages — found {total} CVEs")
            console.print()

            if not results:
                print_success(console, "No CVEs found in checked packages")
                return

            for pkg_result in results:
                pkg_name = pkg_result.get("package", "")
                pkg_ver  = pkg_result.get("version", "")
                cves     = pkg_result.get("cves", [])

                console.print(f"  [bold yellow]⚠[/bold yellow]  [bold white]{pkg_name}[/bold white] [dim]({pkg_ver})[/dim]")

                for cve in cves:
                    score    = cve.get("score", 0)
                    severity = cve.get("severity", "")
                    cve_id   = cve.get("cve_id", "")
                    desc     = cve.get("description", "")[:120]
                    pub_date = cve.get("published", "")

                    score_color = "red" if score >= 7 else ("yellow" if score >= 4 else "white")
                    console.print(
                        f"    [bold {score_color}]{cve_id}[/bold {score_color}] "
                        f"Score: [{score_color}]{score}[/{score_color}] ({severity})  "
                        f"[dim]{pub_date}[/dim]"
                    )
                    console.print(f"    [dim]{desc}...[/dim]")
                    console.print()

        except Exception:
            pass

    def _save_to_db(self, audit_results: dict[str, Any]) -> None:
        """Save all audit results to database."""
        try:
            from zephyrveil.storage.db import insert_scan, insert_audit_result, finish_scan
            db_path = self.get_db_path()
            scan_id = f"health_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            insert_scan(db_path, scan_id, "health_audit")

            for audit_type, result in audit_results.items():
                try:
                    insert_audit_result(db_path, scan_id, f"health_{audit_type}", result)
                except Exception:
                    continue

            finish_scan(db_path, scan_id, 0, 0, 0)

        except Exception:
            pass
